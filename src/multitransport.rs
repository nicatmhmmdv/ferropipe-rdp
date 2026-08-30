//! Multitransport bootstrap ([MS-RDPBCGR] 2.2.15): the mechanism that hands the
//! UDP transport its security cookie so an RDP session can migrate onto UDP
//! (carried by the sibling `rdpeudp` crate).
//!
//! Flow: the server sends a Server Initiate Multitransport Request with a 16-byte
//! `securityCookie`; the client opens an RDP-UDP connection whose SYN echoes
//! `SHA-256(securityCookie)` as the `cookieHash`, binding the UDP flow to this TCP
//! session; the full cookie is later re-sent in the (DTLS-protected) Tunnel Create
//! Request as the authoritative bind.

use crate::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};
use sha2::{Digest, Sha256};

/// requestedProtocol values ([MS-RDPBCGR] 2.2.15.1). Spec spelling "INITITATE".
pub const PROTOCOL_UDPFECR: u16 = 0x01; // reliable
pub const PROTOCOL_UDPFECL: u16 = 0x02; // lossy

/// TS_UD_CS_MULTITRANSPORTCHANNELDATA flags (GCC advertisement).
pub const TRANSPORTTYPE_UDPFECR: u32 = 0x01;
pub const TRANSPORTTYPE_UDPFECL: u32 = 0x04;
pub const TRANSPORTTYPE_UDP_PREFERRED: u32 = 0x100;
pub const TRANSPORTTYPE_SOFTSYNC: u32 = 0x200;

/// A parsed Server Initiate Multitransport Request ([MS-RDPBCGR] 2.2.15.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitiateRequest {
    pub request_id: u32,
    pub requested_protocol: u16,
    pub security_cookie: [u8; 16],
}

impl InitiateRequest {
    /// Parse the PDU body (requestId, requestedProtocol, reserved, securityCookie).
    pub fn parse(buf: &[u8]) -> Result<InitiateRequest> {
        if buf.len() < 24 {
            return Err(Error::Short { need: 24, have: buf.len() });
        }
        let mut b = buf;
        let request_id = b.get_u32_le();
        let requested_protocol = b.get_u16_le();
        let _reserved = b.get_u16_le();
        let mut security_cookie = [0u8; 16];
        security_cookie.copy_from_slice(&b[..16]);
        Ok(InitiateRequest { request_id, requested_protocol, security_cookie })
    }

    /// The `cookieHash` to echo in the RDP-UDP v3 SYN: SHA-256 of the raw 16-byte
    /// securityCookie (no salt/prefix), per [MS-RDPEUDP] §2.2.2.9.
    pub fn cookie_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.security_cookie);
        h.finalize().into()
    }
}

/// Build the Client Initiate Multitransport Response ([MS-RDPBCGR] 2.2.15.2):
/// requestId + hrResponse (0 = S_OK).
pub fn initiate_response(request_id: u32, hr_response: u32) -> Vec<u8> {
    let mut out = BytesMut::new();
    out.put_u32_le(request_id);
    out.put_u32_le(hr_response);
    out.to_vec()
}

/// Open the RDP-UDP sideband transport (via the `rdpeudp` crate) for a server
/// multitransport request, binding it to this TCP session by putting the
/// `cookieHash` in the SYN. `reliable` mode is chosen from the requested protocol.
///
/// This is the point where `ferropipe-rdp` composes with `rdpeudp`: the session's
/// graphics can then be carried over UDP instead of TCP.
pub fn open_udp(
    request: &InitiateRequest,
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
    isn: u32,
) -> std::io::Result<rdpeudp::UdpTransport> {
    let reliable = request.requested_protocol == PROTOCOL_UDPFECR;
    let config = rdpeudp::Config {
        reliable,
        cookie_hash: Some(request.cookie_hash()),
        ..Default::default()
    };
    rdpeudp::UdpTransport::connect(local, peer, config, isn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_initiate_request_and_hashes_cookie() {
        let mut body = BytesMut::new();
        body.put_u32_le(0xDEAD_BEEF); // requestId
        body.put_u16_le(PROTOCOL_UDPFECR);
        body.put_u16_le(0); // reserved
        let cookie = [0x11u8; 16];
        body.extend_from_slice(&cookie);

        let req = InitiateRequest::parse(&body).unwrap();
        assert_eq!(req.request_id, 0xDEAD_BEEF);
        assert_eq!(req.requested_protocol, PROTOCOL_UDPFECR);
        assert_eq!(req.security_cookie, cookie);

        // cookie_hash = SHA256(cookie); check it matches an independent SHA256.
        let mut h = Sha256::new();
        h.update(cookie);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(req.cookie_hash(), expected);
    }

    #[test]
    fn response_layout() {
        let r = initiate_response(0xDEAD_BEEF, 0);
        assert_eq!(u32::from_le_bytes([r[0], r[1], r[2], r[3]]), 0xDEAD_BEEF);
        assert_eq!(u32::from_le_bytes([r[4], r[5], r[6], r[7]]), 0);
    }
}
