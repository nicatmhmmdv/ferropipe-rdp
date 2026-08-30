//! The secured UDP multitransport tunnel — the completed UDP leg. It composes:
//!
//! 1. [`rdpeudp`] reliable transport (SYN carries the cookieHash binding)
//! 2. a reliable byte stream over it ([`rdpeudp::RdpUdpStream`])
//! 3. **TLS** over that stream (per [MS-RDPEMT], the reliable/UDPFECR tunnel is
//!    secured with TLS — DTLS is only for the lossy path)
//! 4. the [`crate::emt`] Tunnel Create handshake (full securityCookie)
//!
//! After [`UdpTunnel::establish`], `send_pdu`/`recv_pdu` carry ordinary RDP PDUs
//! (e.g. EGFX fast-path graphics) over UDP instead of the main TCP channel.

use crate::emt;
use crate::multitransport::{open_udp, InitiateRequest};
use crate::{Error, Result};
use rdpeudp::RdpUdpStream;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// A live, TLS-secured multitransport tunnel over RDP-UDP.
pub struct UdpTunnel {
    stream: rustls::StreamOwned<rustls::ClientConnection, RdpUdpStream>,
}

impl UdpTunnel {
    /// Dial the side-band UDP transport for `request`, secure it with TLS, and
    /// complete the Tunnel Create handshake. `isn` is the RDP-UDP initial sequence
    /// number (random in production).
    pub fn establish(request: &InitiateRequest, local: SocketAddr, peer: SocketAddr, isn: u32) -> Result<UdpTunnel> {
        // 1-2. Open the reliable RDP-UDP transport (cookieHash in the SYN) and wrap
        //      it as a byte stream.
        let mut transport = open_udp(request, local, peer, isn).map_err(Error::Io)?;
        transport
            .establish(Duration::from_secs(5))
            .map_err(Error::Io)?;
        let byte_stream = RdpUdpStream::new(transport);

        // 3. TLS over the reliable stream.
        let server_name = rustls::pki_types::ServerName::try_from("rdp".to_string())
            .map_err(|_| Error::Protocol("invalid TLS server name"))?;
        let conn = rustls::ClientConnection::new(Arc::new(crate::tls::client_config()), server_name)
            .map_err(|_| Error::Protocol("failed to create UDP-tunnel TLS client"))?;
        let mut stream = rustls::StreamOwned::new(conn, byte_stream);

        // 4. Tunnel Create Request (the first write drives the TLS handshake), then
        //    read and validate the Create Response.
        stream
            .write_all(&emt::create_request(request.request_id, &request.security_cookie))
            .map_err(Error::Io)?;
        stream.flush().map_err(Error::Io)?;

        let response = read_tunnel_pdu(&mut stream)?;
        match emt::parse(&response)? {
            emt::TunnelPdu::CreateResponse { hr_response: 0 } => {}
            emt::TunnelPdu::CreateResponse { .. } => {
                return Err(Error::NegotiationFailure("UDP tunnel create rejected"));
            }
            _ => return Err(Error::Protocol("unexpected UDP tunnel reply")),
        }
        Ok(UdpTunnel { stream })
    }

    /// Send a higher-layer RDP PDU through the tunnel.
    pub fn send_pdu(&mut self, rdp_pdu: &[u8]) -> Result<()> {
        self.stream.write_all(&emt::data(rdp_pdu)).map_err(Error::Io)?;
        self.stream.flush().map_err(Error::Io)?;
        Ok(())
    }

    /// Receive the next higher-layer RDP PDU from the tunnel.
    pub fn recv_pdu(&mut self) -> Result<Vec<u8>> {
        loop {
            let pdu = read_tunnel_pdu(&mut self.stream)?;
            match emt::parse(&pdu)? {
                emt::TunnelPdu::Data { higher_layer } => return Ok(higher_layer),
                _ => continue, // ignore non-data tunnel PDUs
            }
        }
    }
}

/// Read one RDP_TUNNEL_HEADER-framed PDU off a stream (header + subheaders + body).
fn read_tunnel_pdu<R: Read>(r: &mut R) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header).map_err(Error::Io)?;
    let payload_len = u16::from_le_bytes([header[1], header[2]]) as usize;
    let header_len = header[3] as usize;
    if header_len < 4 {
        return Err(Error::Protocol("bad tunnel HeaderLength"));
    }
    let mut rest = vec![0u8; (header_len - 4) + payload_len];
    r.read_exact(&mut rest).map_err(Error::Io)?;
    let mut whole = header.to_vec();
    whole.extend_from_slice(&rest);
    Ok(whole)
}
