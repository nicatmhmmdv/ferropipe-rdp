//! RDP share PDU headers and the connection-finalization PDUs ([MS-RDPBCGR]
//! 2.2.8.1.1). Little-endian. These ride inside MCS Send Data, which rides inside
//! the X.224 Data TPDU and TPKT.

use crate::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};

/// TS_SHARECONTROLHEADER pduType values (low 4 bits; the high bits carry the
/// protocol version 0x1, so on the wire they appear as `type | 0x10`).
pub const PDUTYPE_DEMANDACTIVE: u16 = 0x1;
pub const PDUTYPE_CONFIRMACTIVE: u16 = 0x3;
pub const PDUTYPE_DEACTIVATEALL: u16 = 0x6;
pub const PDUTYPE_DATA: u16 = 0x7;
const PROTOCOL_VERSION: u16 = 0x10;

/// TS_SHAREDATAHEADER pduType2 values.
pub const PDUTYPE2_UPDATE: u8 = 2;
pub const PDUTYPE2_CONTROL: u8 = 20;
pub const PDUTYPE2_SYNCHRONIZE: u8 = 31;
pub const PDUTYPE2_FONTLIST: u8 = 39;
pub const PDUTYPE2_FONTMAP: u8 = 40;
pub const PDUTYPE2_SET_ERROR_INFO: u8 = 47;

const STREAM_LOW: u8 = 1;

/// A parsed TS_SHARECONTROLHEADER.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareControlHeader {
    pub pdu_type: u16,
    pub pdu_source: u16,
}

/// Wrap `body` in a TS_SHARECONTROLHEADER (totalLength is computed).
pub fn share_control(pdu_type: u16, pdu_source: u16, body: &[u8]) -> Vec<u8> {
    let total = body.len() + 6;
    let mut out = BytesMut::with_capacity(total);
    out.put_u16_le(total as u16);
    out.put_u16_le(pdu_type | PROTOCOL_VERSION);
    out.put_u16_le(pdu_source);
    out.extend_from_slice(body);
    out.to_vec()
}

/// Parse a TS_SHARECONTROLHEADER, returning (header, inner body).
pub fn parse_share_control(buf: &[u8]) -> Result<(ShareControlHeader, &[u8])> {
    if buf.len() < 6 {
        return Err(Error::Short { need: 6, have: buf.len() });
    }
    let mut b = buf;
    let total = b.get_u16_le() as usize;
    let type_field = b.get_u16_le();
    let pdu_source = b.get_u16_le();
    if total < 6 || buf.len() < total {
        return Err(Error::Protocol("bad share control totalLength"));
    }
    Ok((ShareControlHeader { pdu_type: type_field & 0x0f, pdu_source }, &buf[6..total]))
}

/// Wrap `body` in a full data PDU: TS_SHAREDATAHEADER inside a
/// TS_SHARECONTROLHEADER of type DATA.
pub fn share_data(pdu_source: u16, share_id: u32, pdu_type2: u8, body: &[u8]) -> Vec<u8> {
    let mut data = BytesMut::new();
    data.put_u32_le(share_id);
    data.put_u8(0); // pad1
    data.put_u8(STREAM_LOW); // streamId
    data.put_u16_le((body.len() + 4) as u16); // uncompressedLength (body + 4? spec: shareDataHeader length)
    data.put_u8(pdu_type2);
    data.put_u8(0); // compressedType (none)
    data.put_u16_le(0); // compressedLength
    data.extend_from_slice(body);
    share_control(PDUTYPE_DATA, pdu_source, &data)
}

/// Parse a data PDU's TS_SHAREDATAHEADER, returning (pduType2, inner body).
pub fn parse_share_data(share_control_body: &[u8]) -> Result<(u8, &[u8])> {
    if share_control_body.len() < 12 {
        return Err(Error::Short { need: 12, have: share_control_body.len() });
    }
    let pdu_type2 = share_control_body[8];
    Ok((pdu_type2, &share_control_body[12..]))
}

// --- Finalization PDU bodies (wrapped with `share_data`) ---

/// TS_SYNCHRONIZE_PDU (§2.2.1.14): messageType=1 (SYNC), targetUser.
pub fn synchronize(target_user: u16) -> Vec<u8> {
    let mut b = BytesMut::new();
    b.put_u16_le(1); // SYNCMSGTYPE_SYNC
    b.put_u16_le(target_user);
    b.to_vec()
}

/// TS_CONTROL_PDU control actions (§2.2.1.15).
pub const CTRLACTION_REQUEST_CONTROL: u16 = 0x0001;
pub const CTRLACTION_GRANTED_CONTROL: u16 = 0x0002;
pub const CTRLACTION_DETACH: u16 = 0x0003;
pub const CTRLACTION_COOPERATE: u16 = 0x0004;

/// TS_CONTROL_PDU (§2.2.1.15): action, grantId, controlId.
pub fn control(action: u16, grant_id: u16, control_id: u32) -> Vec<u8> {
    let mut b = BytesMut::new();
    b.put_u16_le(action);
    b.put_u16_le(grant_id);
    b.put_u32_le(control_id);
    b.to_vec()
}

/// TS_FONT_LIST_PDU (§2.2.1.18) — a client sends an empty font list.
pub fn font_list() -> Vec<u8> {
    let mut b = BytesMut::new();
    b.put_u16_le(0); // numberFonts
    b.put_u16_le(0); // totalNumFonts
    b.put_u16_le(0x0003); // listFlags: FONTLIST_FIRST | FONTLIST_LAST
    b.put_u16_le(0x0032); // entrySize
    b.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_control_roundtrips() {
        let body = b"share-control-body";
        let enc = share_control(PDUTYPE_CONFIRMACTIVE, 1002, body);
        let (hdr, inner) = parse_share_control(&enc).unwrap();
        assert_eq!(hdr.pdu_type, PDUTYPE_CONFIRMACTIVE);
        assert_eq!(hdr.pdu_source, 1002);
        assert_eq!(inner, body);
    }

    #[test]
    fn share_data_wraps_and_unwraps() {
        let inner = synchronize(1002);
        let enc = share_data(1007, 0x103EA, PDUTYPE2_SYNCHRONIZE, &inner);
        let (hdr, body) = parse_share_control(&enc).unwrap();
        assert_eq!(hdr.pdu_type, PDUTYPE_DATA);
        let (pdu_type2, data) = parse_share_data(body).unwrap();
        assert_eq!(pdu_type2, PDUTYPE2_SYNCHRONIZE);
        assert_eq!(data, &inner[..]);
    }

    #[test]
    fn control_cooperate_is_well_formed() {
        let c = control(CTRLACTION_COOPERATE, 0, 0);
        assert_eq!(u16::from_le_bytes([c[0], c[1]]), CTRLACTION_COOPERATE);
        assert_eq!(c.len(), 8);
    }

    #[test]
    fn synchronize_targets_user() {
        let s = synchronize(0x03EA);
        assert_eq!(u16::from_le_bytes([s[0], s[1]]), 1); // SYNCMSGTYPE_SYNC
        assert_eq!(u16::from_le_bytes([s[2], s[3]]), 0x03EA);
    }
}
