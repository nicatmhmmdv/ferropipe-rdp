//! Multitransport tunnel PDUs ([MS-RDPEMT]). Once the side-band UDP connection is
//! secured (TLS over the reliable RDP-UDP transport), the client sends a Tunnel
//! Create Request carrying the full 16-byte `securityCookie` from the Initiate
//! Multitransport Request; the server matches it to the outstanding request and
//! replies. Thereafter RDP data is wrapped in Tunnel Data PDUs.
//!
//! Every PDU is prefixed by an RDP_TUNNEL_HEADER: `byte0 = (Flags<<4) | Action`,
//! a u16 PayloadLength (body bytes after the header), and a u8 HeaderLength
//! (≥ 4). Little-endian.

use crate::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};

pub const ACTION_CREATEREQUEST: u8 = 0x0;
pub const ACTION_CREATERESPONSE: u8 = 0x1;
pub const ACTION_DATA: u8 = 0x2;

const MIN_HEADER_LEN: usize = 4;

/// Write an RDP_TUNNEL_HEADER (bare, no subheaders) + body.
fn tunnel_pdu(action: u8, body: &[u8]) -> Vec<u8> {
    let mut out = BytesMut::with_capacity(MIN_HEADER_LEN + body.len());
    out.put_u8(action & 0x0f); // Flags 0 in the high nibble
    out.put_u16_le(body.len() as u16); // PayloadLength (body only)
    out.put_u8(MIN_HEADER_LEN as u8); // HeaderLength
    out.extend_from_slice(body);
    out.to_vec()
}

/// Build a Tunnel Create Request binding this UDP tunnel to the main session.
pub fn create_request(request_id: u32, security_cookie: &[u8; 16]) -> Vec<u8> {
    let mut body = BytesMut::new();
    body.put_u32_le(request_id);
    body.put_u32_le(0); // Reserved
    body.extend_from_slice(security_cookie);
    tunnel_pdu(ACTION_CREATEREQUEST, &body)
}

/// Build a Tunnel Data PDU wrapping a higher-layer RDP PDU.
pub fn data(higher_layer: &[u8]) -> Vec<u8> {
    tunnel_pdu(ACTION_DATA, higher_layer)
}

/// A parsed inbound tunnel PDU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelPdu {
    CreateResponse { hr_response: u32 },
    Data { higher_layer: Vec<u8> },
    Other { action: u8 },
}

/// Parse an RDP_TUNNEL_HEADER-prefixed PDU.
pub fn parse(pdu: &[u8]) -> Result<TunnelPdu> {
    if pdu.len() < MIN_HEADER_LEN {
        return Err(Error::Short { need: MIN_HEADER_LEN, have: pdu.len() });
    }
    let mut b = pdu;
    let action = b.get_u8() & 0x0f;
    let payload_len = b.get_u16_le() as usize;
    let header_len = b.get_u8() as usize;
    if header_len < MIN_HEADER_LEN || pdu.len() < header_len + payload_len {
        return Err(Error::Protocol("bad RDP_TUNNEL_HEADER length"));
    }
    let body = &pdu[header_len..header_len + payload_len];

    match action {
        ACTION_CREATERESPONSE => {
            if body.len() < 4 {
                return Err(Error::Short { need: 4, have: body.len() });
            }
            Ok(TunnelPdu::CreateResponse { hr_response: u32::from_le_bytes([body[0], body[1], body[2], body[3]]) })
        }
        ACTION_DATA => Ok(TunnelPdu::Data { higher_layer: body.to_vec() }),
        other => Ok(TunnelPdu::Other { action: other }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_request_matches_spec_example() {
        let cookie = [0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0];
        let pdu = create_request(1, &cookie);
        // header: action|flags=00, PayloadLength=0x0018, HeaderLength=04
        assert_eq!(&pdu[..4], &[0x00, 0x18, 0x00, 0x04]);
        assert_eq!(&pdu[4..8], &[0x01, 0x00, 0x00, 0x00]); // requestId
        assert_eq!(&pdu[8..12], &[0x00, 0x00, 0x00, 0x00]); // reserved
        assert_eq!(&pdu[12..28], &cookie);
        assert_eq!(pdu.len(), 28);
    }

    #[test]
    fn create_response_roundtrips() {
        let mut body = BytesMut::new();
        body.put_u32_le(0); // S_OK
        let pdu = tunnel_pdu(ACTION_CREATERESPONSE, &body);
        assert_eq!(parse(&pdu).unwrap(), TunnelPdu::CreateResponse { hr_response: 0 });
    }

    #[test]
    fn data_wraps_and_unwraps() {
        let inner = b"fast-path-update-bytes";
        let pdu = data(inner);
        assert_eq!(pdu[0], ACTION_DATA);
        match parse(&pdu).unwrap() {
            TunnelPdu::Data { higher_layer } => assert_eq!(higher_layer, inner),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn parse_skips_subheaders_via_header_length() {
        // A DATA PDU with a 6-byte header (2 bytes of subheader) then 3 body bytes.
        let mut pdu = vec![ACTION_DATA, 0x03, 0x00, 0x06, 0xAA, 0xBB]; // header incl. 2 subheader bytes
        pdu.extend_from_slice(&[1, 2, 3]);
        match parse(&pdu).unwrap() {
            TunnelPdu::Data { higher_layer } => assert_eq!(higher_layer, vec![1, 2, 3]),
            other => panic!("expected Data, got {other:?}"),
        }
    }
}
