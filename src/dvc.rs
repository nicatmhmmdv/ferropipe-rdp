//! Dynamic Virtual Channel Extension ([MS-RDPEDYC], DRDYNVC). Rides over the
//! static "drdynvc" virtual channel and multiplexes named dynamic channels (e.g.
//! the EGFX graphics channel). Each DVC PDU starts with a header byte packing the
//! command (high nibble) and the channel-id width `cbChId` (low 2 bits).

use crate::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};

// DVC commands (header byte high nibble).
pub const CMD_CREATE: u8 = 0x01;
pub const CMD_DATA_FIRST: u8 = 0x02;
pub const CMD_DATA: u8 = 0x03;
pub const CMD_CLOSE: u8 = 0x04;
pub const CMD_CAPABILITY: u8 = 0x05;
pub const CMD_SOFT_SYNC_REQUEST: u8 = 0x08;

fn header_byte(cmd: u8, sp: u8, cb_chid: u8) -> u8 {
    (cmd << 4) | ((sp & 0x03) << 2) | (cb_chid & 0x03)
}

/// Encode a channel id at the width implied by `cb_chid` (0→1, 1→2, 2→4 bytes).
fn write_channel_id(out: &mut BytesMut, id: u32, cb_chid: u8) {
    match cb_chid {
        0 => out.put_u8(id as u8),
        1 => out.put_u16_le(id as u16),
        _ => out.put_u32_le(id),
    }
}

/// Smallest cbChId that can hold `id`.
fn cb_chid_for(id: u32) -> u8 {
    if id <= 0xFF {
        0
    } else if id <= 0xFFFF {
        1
    } else {
        2
    }
}

fn read_channel_id(buf: &mut &[u8], cb_chid: u8) -> Result<u32> {
    let need = match cb_chid {
        0 => 1,
        1 => 2,
        _ => 4,
    };
    if buf.len() < need {
        return Err(Error::Short { need, have: buf.len() });
    }
    Ok(match cb_chid {
        0 => buf.get_u8() as u32,
        1 => buf.get_u16_le() as u32,
        _ => buf.get_u32_le(),
    })
}

/// A parsed inbound DVC PDU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DvcPdu {
    Capabilities { version: u16 },
    Create { channel_id: u32, name: String },
    Data { channel_id: u32, data: Vec<u8> },
    DataFirst { channel_id: u32, total_length: u32, data: Vec<u8> },
    Close { channel_id: u32 },
    Other { cmd: u8 },
}

/// Parse an inbound DVC PDU (the payload of a "drdynvc" static-channel message).
pub fn parse(pdu: &[u8]) -> Result<DvcPdu> {
    if pdu.is_empty() {
        return Err(Error::Short { need: 1, have: 0 });
    }
    let mut buf = pdu;
    let header = buf.get_u8();
    let cmd = header >> 4;
    let sp = (header >> 2) & 0x03;
    let cb_chid = header & 0x03;

    match cmd {
        CMD_CAPABILITY => {
            if buf.len() < 3 {
                return Err(Error::Short { need: 3, have: buf.len() });
            }
            let _pad = buf.get_u8();
            Ok(DvcPdu::Capabilities { version: buf.get_u16_le() })
        }
        CMD_CREATE => {
            let channel_id = read_channel_id(&mut buf, cb_chid)?;
            // Channel name: null-terminated ASCII.
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            let name = String::from_utf8_lossy(&buf[..end]).into_owned();
            Ok(DvcPdu::Create { channel_id, name })
        }
        CMD_DATA => {
            let channel_id = read_channel_id(&mut buf, cb_chid)?;
            Ok(DvcPdu::Data { channel_id, data: buf.to_vec() })
        }
        CMD_DATA_FIRST => {
            let channel_id = read_channel_id(&mut buf, cb_chid)?;
            // Length field width is selected by `sp` (Len): 0→1, 1→2, 2→4 bytes.
            let total_length = read_channel_id(&mut buf, sp)?;
            Ok(DvcPdu::DataFirst { channel_id, total_length, data: buf.to_vec() })
        }
        CMD_CLOSE => {
            let channel_id = read_channel_id(&mut buf, cb_chid)?;
            Ok(DvcPdu::Close { channel_id })
        }
        _ => Ok(DvcPdu::Other { cmd }),
    }
}

/// Build a Capabilities Response selecting `version`.
pub fn capabilities_response(version: u16) -> Vec<u8> {
    let mut out = BytesMut::new();
    out.put_u8(header_byte(CMD_CAPABILITY, 0, 0));
    out.put_u8(0); // Pad
    out.put_u16_le(version);
    out.to_vec()
}

/// Build a Create Response for `channel_id` with the given status (0 = success).
pub fn create_response(channel_id: u32, status: i32) -> Vec<u8> {
    let cb = cb_chid_for(channel_id);
    let mut out = BytesMut::new();
    out.put_u8(header_byte(CMD_CREATE, 0, cb));
    write_channel_id(&mut out, channel_id, cb);
    out.put_i32_le(status);
    out.to_vec()
}

/// Build a Data PDU carrying `data` on `channel_id`.
pub fn data(channel_id: u32, payload: &[u8]) -> Vec<u8> {
    let cb = cb_chid_for(channel_id);
    let mut out = BytesMut::new();
    out.put_u8(header_byte(CMD_DATA, 0, cb));
    write_channel_id(&mut out, channel_id, cb);
    out.extend_from_slice(payload);
    out.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_capabilities_request() {
        // Version 3 caps request: 50 00 03 00 + priority charges
        let pdu = [0x50, 0x00, 0x03, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse(&pdu).unwrap(), DvcPdu::Capabilities { version: 3 });
    }

    #[test]
    fn capabilities_response_roundtrips() {
        let resp = capabilities_response(2);
        assert_eq!(resp, vec![0x50, 0x00, 0x02, 0x00]);
        assert_eq!(parse(&resp).unwrap(), DvcPdu::Capabilities { version: 2 });
    }

    #[test]
    fn parses_create_request() {
        // 0x10 (CREATE, cbChId 0), id 3, "ECHO\0"
        let pdu = [0x10, 0x03, b'E', b'C', b'H', b'O', 0x00];
        assert_eq!(parse(&pdu).unwrap(), DvcPdu::Create { channel_id: 3, name: "ECHO".into() });
    }

    #[test]
    fn create_response_success() {
        let resp = create_response(3, 0);
        assert_eq!(resp, vec![0x10, 0x03, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn data_pdu_roundtrips() {
        let pdu = data(5, b"graphics-bytes");
        match parse(&pdu).unwrap() {
            DvcPdu::Data { channel_id, data } => {
                assert_eq!(channel_id, 5);
                assert_eq!(data, b"graphics-bytes");
            }
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn two_byte_channel_id() {
        let pdu = data(0x0102, b"x");
        // header 0x31 = CMD_DATA(3)<<4 | cbChId 1
        assert_eq!(pdu[0], 0x31);
        assert_eq!(u16::from_le_bytes([pdu[1], pdu[2]]), 0x0102);
    }
}
