//! RDP security-protocol negotiation ([MS-RDPBCGR] 2.2.1.1.1 / 2.2.1.2). These
//! structures are carried in the X.224 Connection Request/Confirm user data and
//! decide whether the connection upgrades to TLS, NLA (CredSSP), etc.
//!
//! Fields are **little-endian** (RDP convention), unlike the TPKT header.

use crate::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};

/// Requested/selected security protocols (a bitmask, [MS-RDPBCGR] 2.2.1.1.1).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct SecurityProtocol(pub u32);

impl SecurityProtocol {
    /// Standard RDP security (no external security protocol).
    pub const RDP: u32 = 0x0000_0000;
    /// TLS 1.x.
    pub const SSL: u32 = 0x0000_0001;
    /// CredSSP (Network Level Authentication).
    pub const HYBRID: u32 = 0x0000_0002;
    /// RDSTLS.
    pub const RDSTLS: u32 = 0x0000_0004;
    /// CredSSP with early user authorization.
    pub const HYBRID_EX: u32 = 0x0000_0008;

    pub fn has(self, bit: u32) -> bool {
        bit == 0 || self.0 & bit != 0
    }
    pub fn with(mut self, bit: u32) -> Self {
        self.0 |= bit;
        self
    }
}

impl std::fmt::Debug for SecurityProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        for (name, bit) in [("SSL", Self::SSL), ("HYBRID", Self::HYBRID), ("RDSTLS", Self::RDSTLS), ("HYBRID_EX", Self::HYBRID_EX)] {
            if self.0 & bit != 0 {
                parts.push(name);
            }
        }
        if parts.is_empty() {
            parts.push("RDP");
        }
        write!(f, "SecurityProtocol({:#010x} [{}])", self.0, parts.join("|"))
    }
}

const TYPE_RDP_NEG_REQ: u8 = 0x01;
const TYPE_RDP_NEG_RSP: u8 = 0x02;
const TYPE_RDP_NEG_FAILURE: u8 = 0x03;
/// Every negotiation structure is a fixed 8 bytes.
pub const NEG_LEN: u16 = 8;

/// RDP_NEG_REQ — the client's requested protocols ([MS-RDPBCGR] 2.2.1.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NegotiationRequest {
    pub flags: u8,
    pub requested: SecurityProtocol,
}

impl NegotiationRequest {
    pub const SIZE: usize = 8;

    pub fn write(&self, out: &mut BytesMut) {
        out.put_u8(TYPE_RDP_NEG_REQ);
        out.put_u8(self.flags);
        out.put_u16_le(NEG_LEN);
        out.put_u32_le(self.requested.0);
    }

    pub fn read(buf: &mut &[u8]) -> Result<NegotiationRequest> {
        if buf.len() < Self::SIZE {
            return Err(Error::Short { need: Self::SIZE, have: buf.len() });
        }
        let ty = buf.get_u8();
        if ty != TYPE_RDP_NEG_REQ {
            return Err(Error::Protocol("not an RDP_NEG_REQ"));
        }
        let flags = buf.get_u8();
        let _len = buf.get_u16_le();
        Ok(NegotiationRequest { flags, requested: SecurityProtocol(buf.get_u32_le()) })
    }
}

/// The server's answer to negotiation: either the selected protocol or a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NegotiationResponse {
    Selected { flags: u8, protocol: SecurityProtocol },
    Failure { code: u32 },
}

impl NegotiationResponse {
    pub const SIZE: usize = 8;

    pub fn write(&self, out: &mut BytesMut) {
        match self {
            NegotiationResponse::Selected { flags, protocol } => {
                out.put_u8(TYPE_RDP_NEG_RSP);
                out.put_u8(*flags);
                out.put_u16_le(NEG_LEN);
                out.put_u32_le(protocol.0);
            }
            NegotiationResponse::Failure { code } => {
                out.put_u8(TYPE_RDP_NEG_FAILURE);
                out.put_u8(0);
                out.put_u16_le(NEG_LEN);
                out.put_u32_le(*code);
            }
        }
    }

    pub fn read(buf: &mut &[u8]) -> Result<NegotiationResponse> {
        if buf.len() < Self::SIZE {
            return Err(Error::Short { need: Self::SIZE, have: buf.len() });
        }
        let ty = buf.get_u8();
        let flags = buf.get_u8();
        let _len = buf.get_u16_le();
        let value = buf.get_u32_le();
        match ty {
            TYPE_RDP_NEG_RSP => Ok(NegotiationResponse::Selected { flags, protocol: SecurityProtocol(value) }),
            TYPE_RDP_NEG_FAILURE => Ok(NegotiationResponse::Failure { code: value }),
            _ => Err(Error::Protocol("not an RDP_NEG_RSP/FAILURE")),
        }
    }

    /// Human-readable name for a RDP_NEG_FAILURE code ([MS-RDPBCGR] 2.2.1.2.2).
    pub fn failure_reason(code: u32) -> &'static str {
        match code {
            0x0001 => "SSL_REQUIRED_BY_SERVER",
            0x0002 => "SSL_NOT_ALLOWED_BY_SERVER",
            0x0003 => "SSL_CERT_NOT_ON_SERVER",
            0x0004 => "INCONSISTENT_FLAGS",
            0x0005 => "HYBRID_REQUIRED_BY_SERVER",
            0x0006 => "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
            _ => "unknown negotiation failure",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neg_request_roundtrips() {
        let req = NegotiationRequest {
            flags: 0,
            requested: SecurityProtocol::default().with(SecurityProtocol::SSL).with(SecurityProtocol::HYBRID),
        };
        let mut out = BytesMut::new();
        req.write(&mut out);
        assert_eq!(out.len(), NegotiationRequest::SIZE);
        assert_eq!(NegotiationRequest::read(&mut &out[..]).unwrap(), req);
    }

    #[test]
    fn neg_response_selected_roundtrips() {
        let rsp = NegotiationResponse::Selected { flags: 0x02, protocol: SecurityProtocol(SecurityProtocol::HYBRID) };
        let mut out = BytesMut::new();
        rsp.write(&mut out);
        assert_eq!(NegotiationResponse::read(&mut &out[..]).unwrap(), rsp);
    }

    #[test]
    fn neg_response_failure_roundtrips_with_reason() {
        let rsp = NegotiationResponse::Failure { code: 0x0005 };
        let mut out = BytesMut::new();
        rsp.write(&mut out);
        let back = NegotiationResponse::read(&mut &out[..]).unwrap();
        assert_eq!(back, rsp);
        if let NegotiationResponse::Failure { code } = back {
            assert_eq!(NegotiationResponse::failure_reason(code), "HYBRID_REQUIRED_BY_SERVER");
        }
    }
}
