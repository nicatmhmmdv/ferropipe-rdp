//! X.224 (ISO 8073) TPDUs as used by RDP ([MS-RDPBCGR] 2.2.1.1 / 2.2.1.2). These
//! are the bytes carried inside a TPKT payload.
//!
//! Three shapes matter to RDP:
//! - **Connection Request (CR, 0xE0)** — first client PDU, carries an optional
//!   routing cookie and the RDP_NEG_REQ.
//! - **Connection Confirm (CC, 0xD0)** — server reply, carries the RDP_NEG_RSP or
//!   RDP_NEG_FAILURE.
//! - **Data (DT, 0xF0)** — the 3-byte header prefixed to every slow-path PDU after
//!   the connection is up.
//!
//! The reference fields (DST-REF/SRC-REF) are big-endian per X.224; RDP always
//! sends them zero. The negotiation user data is little-endian (see [`crate::nego`]).

use crate::nego::{NegotiationRequest, NegotiationResponse};
use crate::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};

const TPDU_CR: u8 = 0xE0;
const TPDU_CC: u8 = 0xD0;
const TPDU_DT: u8 = 0xF0;
const EOT: u8 = 0x80;
/// Fixed octets after the length indicator in a CR/CC: code + DST + SRC + class.
const CR_CC_FIXED: usize = 6;

/// The X.224 Data TPDU header prefixed to every slow-path PDU: `LI=2, DT, EOT`.
pub const DATA_HEADER: [u8; 3] = [0x02, TPDU_DT, EOT];

/// Client X.224 Connection Request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectionRequest {
    /// Optional routing cookie identity (the `mstshash=<id>` value).
    pub cookie: Option<String>,
    pub nego: Option<NegotiationRequest>,
}

impl ConnectionRequest {
    /// Serialize to the X.224 TPDU bytes (wrap in TPKT to send).
    pub fn encode(&self) -> BytesMut {
        let cookie_bytes = self.cookie.as_deref().map(cookie_line).unwrap_or_default();
        let neg_len = if self.nego.is_some() { NegotiationRequest::SIZE } else { 0 };
        let li = CR_CC_FIXED + cookie_bytes.len() + neg_len;

        let mut out = BytesMut::with_capacity(li + 1);
        out.put_u8(li as u8);
        out.put_u8(TPDU_CR);
        out.put_u16(0); // DST-REF
        out.put_u16(0); // SRC-REF
        out.put_u8(0); // class option
        out.extend_from_slice(&cookie_bytes);
        if let Some(neg) = &self.nego {
            neg.write(&mut out);
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<ConnectionRequest> {
        let (mut body, code) = split_cr_cc(buf)?;
        if code != TPDU_CR {
            return Err(Error::Protocol("not an X.224 Connection Request"));
        }
        let (cookie, rest) = take_cookie(body);
        body = rest;
        let nego = if !body.is_empty() {
            Some(NegotiationRequest::read(&mut body)?)
        } else {
            None
        };
        Ok(ConnectionRequest { cookie, nego })
    }
}

/// Server X.224 Connection Confirm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionConfirm {
    pub nego: Option<NegotiationResponse>,
}

impl ConnectionConfirm {
    pub fn encode(&self) -> BytesMut {
        let neg_len = if self.nego.is_some() { NegotiationResponse::SIZE } else { 0 };
        let li = CR_CC_FIXED + neg_len;
        let mut out = BytesMut::with_capacity(li + 1);
        out.put_u8(li as u8);
        out.put_u8(TPDU_CC);
        out.put_u16(0);
        out.put_u16(0);
        out.put_u8(0);
        if let Some(neg) = &self.nego {
            neg.write(&mut out);
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<ConnectionConfirm> {
        let (mut body, code) = split_cr_cc(buf)?;
        if code != TPDU_CC {
            return Err(Error::Protocol("not an X.224 Connection Confirm"));
        }
        let nego = if !body.is_empty() {
            Some(NegotiationResponse::read(&mut body)?)
        } else {
            None
        };
        Ok(ConnectionConfirm { nego })
    }
}

/// Prefix `payload` with the X.224 Data TPDU header.
pub fn wrap_data(payload: &[u8]) -> BytesMut {
    let mut out = BytesMut::with_capacity(payload.len() + DATA_HEADER.len());
    out.extend_from_slice(&DATA_HEADER);
    out.extend_from_slice(payload);
    out
}

/// Strip the X.224 Data TPDU header, returning the inner PDU bytes.
pub fn unwrap_data(buf: &[u8]) -> Result<&[u8]> {
    if buf.len() < DATA_HEADER.len() {
        return Err(Error::Short { need: DATA_HEADER.len(), have: buf.len() });
    }
    if buf[1] != TPDU_DT {
        return Err(Error::Protocol("not an X.224 Data TPDU"));
    }
    // LI (buf[0]) counts the header octets after itself; for DT it is 2.
    Ok(&buf[(buf[0] as usize + 1)..])
}

/// Split a CR/CC TPDU into (body-after-fixed-header, code), validating the LI.
fn split_cr_cc(buf: &[u8]) -> Result<(&[u8], u8)> {
    if buf.len() < CR_CC_FIXED + 1 {
        return Err(Error::Short { need: CR_CC_FIXED + 1, have: buf.len() });
    }
    let li = buf[0] as usize;
    if buf.len() < li + 1 {
        return Err(Error::Short { need: li + 1, have: buf.len() });
    }
    let code = buf[1];
    let mut fixed = &buf[1..];
    fixed.advance(1); // code
    let _dst = fixed.get_u16();
    let _src = fixed.get_u16();
    let _class = fixed.get_u8();
    // Body = the variable part, bounded by LI.
    let body = &buf[1 + CR_CC_FIXED..1 + li];
    Ok((body, code))
}

/// Build the ANSI cookie line "Cookie: mstshash=<id>\r\n".
fn cookie_line(id: &str) -> Vec<u8> {
    format!("Cookie: mstshash={id}\r\n").into_bytes()
}

/// If `body` begins with a cookie line, parse the identity and return the rest.
fn take_cookie(body: &[u8]) -> (Option<String>, &[u8]) {
    const PREFIX: &[u8] = b"Cookie: mstshash=";
    if body.starts_with(PREFIX) {
        if let Some(end) = find_crlf(body) {
            let id = String::from_utf8_lossy(&body[PREFIX.len()..end]).into_owned();
            return (Some(id), &body[end + 2..]);
        }
    }
    (None, body)
}

fn find_crlf(b: &[u8]) -> Option<usize> {
    b.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nego::SecurityProtocol;

    fn sample_req() -> ConnectionRequest {
        ConnectionRequest {
            cookie: Some("nicat".to_string()),
            nego: Some(NegotiationRequest {
                flags: 0,
                requested: SecurityProtocol::default()
                    .with(SecurityProtocol::SSL)
                    .with(SecurityProtocol::HYBRID),
            }),
        }
    }

    #[test]
    fn connection_request_roundtrips_with_cookie_and_nego() {
        let req = sample_req();
        let bytes = req.encode();
        assert_eq!(bytes[1], TPDU_CR);
        assert_eq!(bytes[0] as usize + 1, bytes.len(), "LI covers the whole TPDU");
        assert_eq!(ConnectionRequest::decode(&bytes).unwrap(), req);
    }

    #[test]
    fn connection_request_without_cookie_roundtrips() {
        let req = ConnectionRequest {
            cookie: None,
            nego: Some(NegotiationRequest { flags: 0, requested: SecurityProtocol(SecurityProtocol::SSL) }),
        };
        let bytes = req.encode();
        assert_eq!(ConnectionRequest::decode(&bytes).unwrap(), req);
    }

    #[test]
    fn connection_confirm_roundtrips() {
        let cc = ConnectionConfirm {
            nego: Some(NegotiationResponse::Selected {
                flags: 0,
                protocol: SecurityProtocol(SecurityProtocol::HYBRID),
            }),
        };
        let bytes = cc.encode();
        assert_eq!(bytes[1], TPDU_CC);
        assert_eq!(ConnectionConfirm::decode(&bytes).unwrap(), cc);
    }

    #[test]
    fn data_tpdu_wraps_and_unwraps() {
        let payload = b"mcs-pdu-bytes-here";
        let wrapped = wrap_data(payload);
        assert_eq!(&wrapped[..3], &DATA_HEADER);
        assert_eq!(unwrap_data(&wrapped).unwrap(), payload);
    }
}
