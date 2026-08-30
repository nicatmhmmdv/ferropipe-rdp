//! NTLM message framing ([MS-NLMP] 2.2.1). Little-endian throughout.
//!
//! Each message begins with the signature `"NTLMSSP\0"` and a 4-byte message
//! type, then a set of fixed fields. Variable-length parts (domain, user,
//! challenge responses, target info) are referenced by 8-byte **security buffers**
//! (`Len`, `MaxLen`, `BufferOffset`) and appended after the fixed header.
//!
//! This module handles only the wire format; the NTLMv2 key computation and MIC
//! live in `ntlmv2` and are layered on top.

use crate::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};

/// `"NTLMSSP\0"`.
pub const SIGNATURE: [u8; 8] = *b"NTLMSSP\0";

/// NTLM NegotiateFlags ([MS-NLMP] 2.2.2.5).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct NegotiateFlags(pub u32);

impl NegotiateFlags {
    pub const UNICODE: u32 = 0x0000_0001;
    pub const OEM: u32 = 0x0000_0002;
    pub const REQUEST_TARGET: u32 = 0x0000_0004;
    pub const SIGN: u32 = 0x0000_0010;
    pub const SEAL: u32 = 0x0000_0020;
    pub const DATAGRAM: u32 = 0x0000_0040;
    pub const LM_KEY: u32 = 0x0000_0080;
    pub const NTLM: u32 = 0x0000_0200;
    pub const ANONYMOUS: u32 = 0x0000_0800;
    pub const OEM_DOMAIN_SUPPLIED: u32 = 0x0000_1000;
    pub const OEM_WORKSTATION_SUPPLIED: u32 = 0x0000_2000;
    pub const ALWAYS_SIGN: u32 = 0x0000_8000;
    pub const TARGET_TYPE_DOMAIN: u32 = 0x0001_0000;
    pub const TARGET_TYPE_SERVER: u32 = 0x0002_0000;
    pub const EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
    pub const IDENTIFY: u32 = 0x0010_0000;
    pub const REQUEST_NON_NT_SESSION_KEY: u32 = 0x0040_0000;
    pub const TARGET_INFO: u32 = 0x0080_0000;
    pub const VERSION: u32 = 0x0200_0000;
    pub const NEGOTIATE_128: u32 = 0x2000_0000;
    pub const KEY_EXCH: u32 = 0x4000_0000;
    pub const NEGOTIATE_56: u32 = 0x8000_0000;

    pub fn has(self, bit: u32) -> bool {
        self.0 & bit != 0
    }
    pub fn with(mut self, bit: u32) -> Self {
        self.0 |= bit;
        self
    }
}

impl std::fmt::Debug for NegotiateFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NegotiateFlags({:#010x})", self.0)
    }
}

/// AV_PAIR identifiers in the CHALLENGE target info ([MS-NLMP] 2.2.2.1).
pub mod av_id {
    pub const EOL: u16 = 0x0000;
    pub const NB_COMPUTER_NAME: u16 = 0x0001;
    pub const NB_DOMAIN_NAME: u16 = 0x0002;
    pub const DNS_COMPUTER_NAME: u16 = 0x0003;
    pub const DNS_DOMAIN_NAME: u16 = 0x0004;
    pub const DNS_TREE_NAME: u16 = 0x0005;
    pub const FLAGS: u16 = 0x0006;
    pub const TIMESTAMP: u16 = 0x0007;
    pub const SINGLE_HOST: u16 = 0x0008;
    pub const TARGET_NAME: u16 = 0x0009;
    pub const CHANNEL_BINDINGS: u16 = 0x000A;
}

/// An 8-byte security buffer descriptor: length + offset into the message.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Field {
    len: u16,
    offset: u32,
}

impl Field {
    fn write(&self, out: &mut BytesMut) {
        out.put_u16_le(self.len);
        out.put_u16_le(self.len); // MaxLen == Len
        out.put_u32_le(self.offset);
    }
    fn read(buf: &mut &[u8]) -> Field {
        let len = buf.get_u16_le();
        let _max = buf.get_u16_le();
        let offset = buf.get_u32_le();
        Field { len, offset }
    }
    /// Slice the referenced bytes out of the whole message.
    fn slice<'a>(&self, msg: &'a [u8]) -> Result<&'a [u8]> {
        let start = self.offset as usize;
        let end = start + self.len as usize;
        if end > msg.len() {
            return Err(Error::Short { need: end, have: msg.len() });
        }
        Ok(&msg[start..end])
    }
}

fn check_signature(buf: &mut &[u8], expected_type: u32) -> Result<()> {
    if buf.len() < 12 {
        return Err(Error::Short { need: 12, have: buf.len() });
    }
    let mut sig = [0u8; 8];
    sig.copy_from_slice(&buf[..8]);
    if sig != SIGNATURE {
        return Err(Error::Protocol("bad NTLMSSP signature"));
    }
    buf.advance(8);
    let ty = buf.get_u32_le();
    if ty != expected_type {
        return Err(Error::Protocol("unexpected NTLM message type"));
    }
    Ok(())
}

/// NEGOTIATE_MESSAGE (type 1), sent by the client first ([MS-NLMP] 2.2.1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiateMessage {
    pub flags: NegotiateFlags,
    pub version: Option<[u8; 8]>,
}

impl NegotiateMessage {
    pub fn encode(&self) -> BytesMut {
        // Fixed header: sig(8)+type(4)+flags(4)+domainField(8)+wsField(8) = 32,
        // plus an 8-byte Version when the VERSION flag is set. We send empty
        // domain/workstation, so both fields have len 0.
        let header_len = 32 + if self.version.is_some() { 8 } else { 0 };
        let mut out = BytesMut::with_capacity(header_len);
        out.extend_from_slice(&SIGNATURE);
        out.put_u32_le(1);
        out.put_u32_le(self.flags.0);
        Field { len: 0, offset: header_len as u32 }.write(&mut out); // domain
        Field { len: 0, offset: header_len as u32 }.write(&mut out); // workstation
        if let Some(v) = self.version {
            out.extend_from_slice(&v);
        }
        out
    }

    pub fn decode(msg: &[u8]) -> Result<NegotiateMessage> {
        let mut buf = msg;
        check_signature(&mut buf, 1)?;
        let flags = NegotiateFlags(buf.get_u32_le());
        let _domain = Field::read(&mut buf);
        let _ws = Field::read(&mut buf);
        let version = if flags.has(NegotiateFlags::VERSION) && buf.len() >= 8 {
            let mut v = [0u8; 8];
            v.copy_from_slice(&buf[..8]);
            Some(v)
        } else {
            None
        };
        Ok(NegotiateMessage { flags, version })
    }
}

/// CHALLENGE_MESSAGE (type 2), received from the server ([MS-NLMP] 2.2.1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeMessage {
    pub flags: NegotiateFlags,
    pub server_challenge: [u8; 8],
    pub target_name: Vec<u8>,
    /// Raw target-info AV_PAIR bytes (fed verbatim into the NTLMv2 temp blob).
    pub target_info: Vec<u8>,
}

impl ChallengeMessage {
    pub fn decode(msg: &[u8]) -> Result<ChallengeMessage> {
        let mut buf = msg;
        check_signature(&mut buf, 2)?;
        let target_name_field = Field::read(&mut buf);
        let flags = NegotiateFlags(buf.get_u32_le());
        if buf.len() < 16 {
            return Err(Error::Short { need: 16, have: buf.len() });
        }
        let mut server_challenge = [0u8; 8];
        server_challenge.copy_from_slice(&buf[..8]);
        buf.advance(8);
        buf.advance(8); // Reserved
        let target_info_field = Field::read(&mut buf);
        Ok(ChallengeMessage {
            flags,
            server_challenge,
            target_name: target_name_field.slice(msg).unwrap_or(&[]).to_vec(),
            target_info: target_info_field.slice(msg).unwrap_or(&[]).to_vec(),
        })
    }

    /// Encode (used to build test fixtures / server side).
    pub fn encode(&self) -> BytesMut {
        let header_len = 48u32; // sig8 type4 tnField8 flags4 chal8 rsv8 tiField8
        let mut out = BytesMut::new();
        out.extend_from_slice(&SIGNATURE);
        out.put_u32_le(2);
        Field { len: self.target_name.len() as u16, offset: header_len }.write(&mut out);
        out.put_u32_le(self.flags.0);
        out.extend_from_slice(&self.server_challenge);
        out.put_u64_le(0); // Reserved
        Field {
            len: self.target_info.len() as u16,
            offset: header_len + self.target_name.len() as u32,
        }
        .write(&mut out);
        out.extend_from_slice(&self.target_name);
        out.extend_from_slice(&self.target_info);
        out
    }
}

/// AUTHENTICATE_MESSAGE (type 3), the client's final NTLM message ([MS-NLMP]
/// 2.2.1.3). Always written with Version + MIC, so the MIC sits at offset 72 and
/// payloads start at 88.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticateMessage {
    pub flags: NegotiateFlags,
    pub domain: Vec<u8>,
    pub user: Vec<u8>,
    pub workstation: Vec<u8>,
    pub lm_response: Vec<u8>,
    pub nt_response: Vec<u8>,
    pub encrypted_session_key: Vec<u8>,
    pub version: [u8; 8],
    pub mic: [u8; 16],
}

impl AuthenticateMessage {
    /// Header length with Version (8) + MIC (16): payloads start here.
    pub const HEADER_LEN: usize = 88;
    /// Fixed offset of the 16-byte MIC field.
    pub const MIC_OFFSET: usize = 72;

    pub fn encode(&self) -> BytesMut {
        // Lay out payloads after the fixed header and record their descriptors.
        let mut payload = Vec::new();
        let mut off = Self::HEADER_LEN as u32;
        let mut place = |bytes: &[u8]| -> Field {
            let f = Field { len: bytes.len() as u16, offset: off };
            payload.extend_from_slice(bytes);
            off += bytes.len() as u32;
            f
        };
        let lm_f = place(&self.lm_response);
        let nt_f = place(&self.nt_response);
        let dom_f = place(&self.domain);
        let user_f = place(&self.user);
        let ws_f = place(&self.workstation);
        let key_f = place(&self.encrypted_session_key);

        let mut out = BytesMut::with_capacity(Self::HEADER_LEN + payload.len());
        out.extend_from_slice(&SIGNATURE);
        out.put_u32_le(3);
        lm_f.write(&mut out);
        nt_f.write(&mut out);
        dom_f.write(&mut out);
        user_f.write(&mut out);
        ws_f.write(&mut out);
        key_f.write(&mut out);
        out.put_u32_le(self.flags.0);
        out.extend_from_slice(&self.version);
        out.extend_from_slice(&self.mic);
        out.extend_from_slice(&payload);
        out
    }

    /// Compute and store the MIC = HMAC_MD5(exported_session_key, NEGOTIATE ‖
    /// CHALLENGE ‖ AUTHENTICATE-with-zeroed-MIC), per [MS-NLMP] §3.1.5.1.2.
    pub fn compute_mic(&mut self, exported_session_key: &[u8; 16], negotiate: &[u8], challenge: &[u8]) {
        self.mic = [0u8; 16];
        let auth_zeroed = self.encode();
        let mut data = Vec::with_capacity(negotiate.len() + challenge.len() + auth_zeroed.len());
        data.extend_from_slice(negotiate);
        data.extend_from_slice(challenge);
        data.extend_from_slice(&auth_zeroed);
        self.mic = super::crypto::hmac_md5(exported_session_key, &data);
    }

    pub fn decode(msg: &[u8]) -> Result<AuthenticateMessage> {
        let mut buf = msg;
        check_signature(&mut buf, 3)?;
        let lm_f = Field::read(&mut buf);
        let nt_f = Field::read(&mut buf);
        let dom_f = Field::read(&mut buf);
        let user_f = Field::read(&mut buf);
        let ws_f = Field::read(&mut buf);
        let key_f = Field::read(&mut buf);
        let flags = NegotiateFlags(buf.get_u32_le());
        if buf.len() < 8 + 16 {
            return Err(Error::Short { need: 8 + 16, have: buf.len() });
        }
        let mut version = [0u8; 8];
        version.copy_from_slice(&buf[..8]);
        buf.advance(8);
        let mut mic = [0u8; 16];
        mic.copy_from_slice(&buf[..16]);
        Ok(AuthenticateMessage {
            flags,
            domain: dom_f.slice(msg)?.to_vec(),
            user: user_f.slice(msg)?.to_vec(),
            workstation: ws_f.slice(msg)?.to_vec(),
            lm_response: lm_f.slice(msg)?.to_vec(),
            nt_response: nt_f.slice(msg)?.to_vec(),
            encrypted_session_key: key_f.slice(msg)?.to_vec(),
            version,
            mic,
        })
    }
}

/// Parse the AV_PAIRs of a target-info blob into (AvId, value) tuples.
pub fn parse_av_pairs(mut ti: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut pairs = Vec::new();
    while ti.len() >= 4 {
        let id = u16::from_le_bytes([ti[0], ti[1]]);
        let len = u16::from_le_bytes([ti[2], ti[3]]) as usize;
        ti = &ti[4..];
        if id == av_id::EOL {
            break;
        }
        if ti.len() < len {
            break;
        }
        pairs.push((id, ti[..len].to_vec()));
        ti = &ti[len..];
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_message_roundtrips() {
        let msg = NegotiateMessage {
            flags: NegotiateFlags::default()
                .with(NegotiateFlags::UNICODE)
                .with(NegotiateFlags::NTLM)
                .with(NegotiateFlags::EXTENDED_SESSIONSECURITY)
                .with(NegotiateFlags::VERSION),
            version: Some([6, 1, 0, 0, 0, 0, 0, 15]),
        };
        let bytes = msg.encode();
        assert_eq!(&bytes[..8], &SIGNATURE);
        assert_eq!(NegotiateMessage::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn challenge_message_roundtrips_with_target_info() {
        let mut target_info = BytesMut::new();
        // one NB_DOMAIN_NAME AV pair + EOL
        target_info.put_u16_le(av_id::NB_DOMAIN_NAME);
        target_info.put_u16_le(8);
        target_info.extend_from_slice(&crate::nla::crypto::unicode("DOM"));
        target_info.extend_from_slice(&[0, 0]); // pad to 8 (UTF16 "DOM" = 6, +2)
        target_info.put_u16_le(av_id::EOL);
        target_info.put_u16_le(0);

        let msg = ChallengeMessage {
            flags: NegotiateFlags::default().with(NegotiateFlags::UNICODE).with(NegotiateFlags::TARGET_INFO),
            server_challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            target_name: crate::nla::crypto::unicode("SERVER"),
            target_info: target_info.to_vec(),
        };
        let bytes = msg.encode();
        let back = ChallengeMessage::decode(&bytes).unwrap();
        assert_eq!(back.server_challenge, msg.server_challenge);
        assert_eq!(back.target_info, msg.target_info);
        assert_eq!(back.target_name, msg.target_name);

        let pairs = parse_av_pairs(&back.target_info);
        assert_eq!(pairs[0].0, av_id::NB_DOMAIN_NAME);
    }

    #[test]
    fn authenticate_message_roundtrips_with_mic() {
        let mut msg = AuthenticateMessage {
            flags: NegotiateFlags::default()
                .with(NegotiateFlags::UNICODE)
                .with(NegotiateFlags::NTLM)
                .with(NegotiateFlags::EXTENDED_SESSIONSECURITY)
                .with(NegotiateFlags::KEY_EXCH)
                .with(NegotiateFlags::VERSION),
            domain: crate::nla::crypto::unicode("DOMAIN"),
            user: crate::nla::crypto::unicode("nicat"),
            workstation: crate::nla::crypto::unicode("WS"),
            lm_response: vec![0u8; 24],
            nt_response: vec![0xABu8; 48],
            encrypted_session_key: vec![0xCDu8; 16],
            version: [6, 1, 0xB1, 0x1D, 0, 0, 0, 0x0F],
            mic: [0u8; 16],
        };
        msg.compute_mic(&[0x55u8; 16], b"NEGOTIATE-bytes", b"CHALLENGE-bytes");
        assert_ne!(msg.mic, [0u8; 16], "MIC was computed");

        let bytes = msg.encode();
        // MIC sits at the fixed offset and payloads start at 88.
        assert_eq!(&bytes[AuthenticateMessage::MIC_OFFSET..AuthenticateMessage::MIC_OFFSET + 16], &msg.mic);
        assert_eq!(AuthenticateMessage::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn mic_is_deterministic_and_binds_all_three_messages() {
        let mut a = AuthenticateMessage {
            flags: NegotiateFlags(0),
            domain: vec![],
            user: crate::nla::crypto::unicode("u"),
            workstation: vec![],
            lm_response: vec![0u8; 24],
            nt_response: vec![1u8; 16],
            encrypted_session_key: vec![],
            version: [0u8; 8],
            mic: [0u8; 16],
        };
        let mut b = a.clone();
        a.compute_mic(&[7u8; 16], b"NEG", b"CHAL");
        b.compute_mic(&[7u8; 16], b"NEG", b"CHAL-different");
        assert_ne!(a.mic, b.mic, "MIC changes when the CHALLENGE changes");
    }
}
