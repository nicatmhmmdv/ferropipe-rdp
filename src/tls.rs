//! The live TCP + TLS transport that completes Phase 1 and implements
//! [`PduTransport`]: X.224 security negotiation, the TLS upgrade, capturing the
//! server certificate's `SubjectPublicKey` for NLA, and TPKT/X.224 framing.
//!
//! RDP servers present self-signed certificates and the real authentication
//! happens in NLA (CredSSP binds to this cert's public key), so the TLS layer
//! uses a permissive certificate verifier by design.

use crate::connection::PduTransport;
use crate::nego::{NegotiationRequest, NegotiationResponse, SecurityProtocol};
use crate::x224::{ConnectionConfirm, ConnectionRequest};
use crate::{tpkt, x224, Error, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

/// A TLS-wrapped RDP transport.
pub struct TlsTransport {
    stream: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    selected_protocol: u32,
    server_public_key: Vec<u8>,
}

impl TlsTransport {
    /// Connect to `addr`, negotiate a security protocol, upgrade to TLS, and
    /// capture the server's public key. `requested` is the OR of the protocols
    /// we offer (typically `SSL | HYBRID`).
    pub fn connect(addr: &str, requested: u32, cookie: Option<String>) -> Result<TlsTransport> {
        let mut tcp = TcpStream::connect(addr)?;
        tcp.set_nodelay(true).ok();

        // X.224 Connection Request with the RDP negotiation request.
        let cr = ConnectionRequest {
            cookie,
            nego: Some(NegotiationRequest { flags: 0, requested: SecurityProtocol(requested) }),
        };
        write_tpkt(&mut tcp, &cr.encode())?;

        // Connection Confirm → selected protocol.
        let cc_bytes = read_tpkt(&mut tcp)?;
        let cc = ConnectionConfirm::decode(&cc_bytes)?;
        let selected_protocol = match cc.nego {
            Some(NegotiationResponse::Selected { protocol, .. }) => protocol.0,
            Some(NegotiationResponse::Failure { code }) => {
                return Err(Error::NegotiationFailure(NegotiationResponse::failure_reason(code)));
            }
            None => SecurityProtocol::RDP, // server accepted plain RDP
        };

        // Upgrade to TLS over the same socket.
        let config = client_config();
        let server_name = rustls::pki_types::ServerName::try_from("rdp".to_string())
            .map_err(|_| Error::Protocol("invalid TLS server name"))?;
        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
            .map_err(|_| Error::Protocol("failed to create TLS client"))?;

        // Drive the handshake to completion on the blocking socket.
        while conn.is_handshaking() {
            let (_rd, _wr) = conn.complete_io(&mut tcp)?;
            if _rd == 0 && _wr == 0 {
                break;
            }
        }
        let stream = rustls::StreamOwned::new(conn, tcp);

        let server_public_key = stream
            .conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|cert| crate::cert::subject_public_key(cert.as_ref()))
            .transpose()?
            .ok_or(Error::Protocol("server presented no certificate"))?;

        Ok(TlsTransport { stream, selected_protocol, server_public_key })
    }

    pub fn selected_protocol(&self) -> u32 {
        self.selected_protocol
    }
    pub fn server_public_key(&self) -> &[u8] {
        &self.server_public_key
    }

    /// Read one CredSSP TSRequest (a DER SEQUENCE) off the TLS channel.
    pub fn read_credssp(&mut self) -> Result<Vec<u8>> {
        read_der_tlv(&mut self.stream)
    }

    /// Write a raw byte blob over the TLS channel (used by NLA).
    pub fn write_raw(&mut self, data: &[u8]) -> Result<()> {
        self.stream.write_all(data)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Read the next post-connection frame: a slow-path TPKT (returns its MCS
    /// payload) or a fast-path server update PDU.
    pub fn read_frame(&mut self) -> Result<Frame> {
        let mut first = [0u8; 1];
        self.stream.read_exact(&mut first)?;
        if first[0] == tpkt::TPKT_VERSION {
            // Slow-path: TPKT header is version, reserved, length(2 BE).
            let mut rest = [0u8; 3];
            self.stream.read_exact(&mut rest)?;
            let total = u16::from_be_bytes([rest[1], rest[2]]) as usize;
            let mut body = vec![0u8; total.saturating_sub(4)];
            self.stream.read_exact(&mut body)?;
            Ok(Frame::SlowPath(x224::unwrap_data(&body)?.to_vec()))
        } else {
            // Fast-path: header byte then the 1-or-2-byte fast-path length.
            let mut lb = [0u8; 1];
            self.stream.read_exact(&mut lb)?;
            let mut length_bytes = vec![lb[0]];
            let total = if lb[0] & 0x80 == 0 {
                lb[0] as usize
            } else {
                let mut lb2 = [0u8; 1];
                self.stream.read_exact(&mut lb2)?;
                length_bytes.push(lb2[0]);
                (((lb[0] & 0x7f) as usize) << 8) | lb2[0] as usize
            };
            let header_len = 1 + length_bytes.len();
            let mut body = vec![0u8; total.saturating_sub(header_len)];
            self.stream.read_exact(&mut body)?;
            let mut whole = vec![first[0]];
            whole.extend_from_slice(&length_bytes);
            whole.extend_from_slice(&body);
            Ok(Frame::FastPath(whole))
        }
    }
}

/// A post-connection frame from the server.
#[derive(Clone, Debug)]
pub enum Frame {
    /// Slow-path PDU: the MCS payload (X.224 already stripped).
    SlowPath(Vec<u8>),
    /// Fast-path output PDU (complete, including its header).
    FastPath(Vec<u8>),
}

/// Read one complete DER TLV (tag + definite length + content) from a stream.
fn read_der_tlv<R: Read>(r: &mut R) -> Result<Vec<u8>> {
    let mut tag = [0u8; 1];
    r.read_exact(&mut tag)?;
    let mut first = [0u8; 1];
    r.read_exact(&mut first)?;
    let mut out = vec![tag[0], first[0]];
    let content_len = if first[0] & 0x80 == 0 {
        first[0] as usize
    } else {
        let n = (first[0] & 0x7f) as usize;
        let mut len_bytes = vec![0u8; n];
        r.read_exact(&mut len_bytes)?;
        out.extend_from_slice(&len_bytes);
        len_bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize)
    };
    let mut content = vec![0u8; content_len];
    r.read_exact(&mut content)?;
    out.extend_from_slice(&content);
    Ok(out)
}

impl PduTransport for TlsTransport {
    fn send(&mut self, mcs_pdu: &[u8]) -> Result<()> {
        let framed = x224::wrap_data(mcs_pdu);
        write_tpkt(&mut self.stream, &framed)
    }
    fn recv(&mut self) -> Result<Vec<u8>> {
        let payload = read_tpkt(&mut self.stream)?;
        Ok(x224::unwrap_data(&payload)?.to_vec())
    }
}

/// Build a permissive rustls client config (RDP certs are self-signed; NLA does
/// the real authentication).
fn client_config() -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
        .with_no_client_auth()
}

/// Write `payload` framed in a TPKT header.
fn write_tpkt<W: Write>(w: &mut W, payload: &[u8]) -> Result<()> {
    let pkt = tpkt::encode(payload)?;
    w.write_all(&pkt)?;
    w.flush()?;
    Ok(())
}

/// Read one complete TPKT packet, returning its X.224 payload.
fn read_tpkt<R: Read>(r: &mut R) -> Result<Vec<u8>> {
    let mut header = [0u8; tpkt::TPKT_HEADER_LEN];
    r.read_exact(&mut header)?;
    let total = tpkt::peek_total_len(&header)?;
    let mut rest = vec![0u8; total - tpkt::TPKT_HEADER_LEN];
    r.read_exact(&mut rest)?;
    let mut whole = header.to_vec();
    whole.extend_from_slice(&rest);
    Ok(tpkt::decode(&whole)?.to_vec())
}

/// A certificate verifier that accepts any certificate. RDP relies on NLA, not
/// PKI, so this is intentional; do not reuse it for general TLS.
#[derive(Debug)]
struct AcceptAllVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}
