//! Fast-path server output PDU parsing ([MS-RDPBCGR] 2.2.9.1.2). Fast-path is
//! the compact framing the server uses for graphics/pointer updates after the
//! connection is active — a 1-byte header, a 1-or-2-byte length, then a sequence
//! of updates. Under TLS there is no per-PDU signature.

use crate::{Error, Result};

/// Fast-path update codes ([MS-RDPBCGR] 2.2.9.1.2.1.1).
pub const UPDATETYPE_ORDERS: u8 = 0x0;
pub const UPDATETYPE_BITMAP: u8 = 0x1;
pub const UPDATETYPE_PALETTE: u8 = 0x2;
pub const UPDATETYPE_SYNCHRONIZE: u8 = 0x3;
pub const UPDATETYPE_SURFCMDS: u8 = 0x4;
pub const UPDATETYPE_PTR_NULL: u8 = 0x5;
pub const UPDATETYPE_PTR_DEFAULT: u8 = 0x6;
pub const UPDATETYPE_PTR_POSITION: u8 = 0x8;
pub const UPDATETYPE_COLOR: u8 = 0x9;
pub const UPDATETYPE_CACHED: u8 = 0xA;
pub const UPDATETYPE_POINTER: u8 = 0xB;

/// Fragmentation states (updateHeader bits 4-5).
pub const FRAGMENT_SINGLE: u8 = 0x0;
pub const FRAGMENT_LAST: u8 = 0x1;
pub const FRAGMENT_FIRST: u8 = 0x2;
pub const FRAGMENT_NEXT: u8 = 0x3;

const FASTPATH_OUTPUT_COMPRESSION_USED: u8 = 0x2;

/// One parsed fast-path update: its code plus the raw update data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathUpdate {
    pub update_code: u8,
    pub fragmentation: u8,
    pub data: Vec<u8>,
}

/// Read a fast-path length field: 1 byte if the high bit is clear, else 2 bytes
/// big-endian with the top bit of the first byte masked off.
fn read_fp_length(buf: &mut &[u8]) -> Result<usize> {
    if buf.is_empty() {
        return Err(Error::Short { need: 1, have: 0 });
    }
    let b0 = buf[0];
    if b0 & 0x80 == 0 {
        *buf = &buf[1..];
        Ok(b0 as usize)
    } else {
        if buf.len() < 2 {
            return Err(Error::Short { need: 2, have: buf.len() });
        }
        let len = (((b0 & 0x7f) as usize) << 8) | buf[1] as usize;
        *buf = &buf[2..];
        Ok(len)
    }
}

/// Parse a complete fast-path output PDU, returning all its updates.
///
/// The `fpOutputHeader` low 2 bits must be 0 (FASTPATH_OUTPUT_ACTION_FASTPATH).
/// Encryption/signature flags are rejected — under TLS the server sets none.
pub fn parse_output_pdu(pdu: &[u8]) -> Result<Vec<FastPathUpdate>> {
    let mut buf = pdu;
    if buf.is_empty() {
        return Err(Error::Short { need: 1, have: 0 });
    }
    let header = buf[0];
    buf = &buf[1..];
    if header & 0x03 != 0 {
        return Err(Error::Protocol("not a fast-path output PDU"));
    }
    // Flags in bits 6-7: any encryption/checksum flag means a signature we don't
    // expect under TLS.
    if header & 0xC0 != 0 {
        return Err(Error::Protocol("unexpected fast-path security flags under TLS"));
    }

    let total_len = read_fp_length(&mut buf)?;
    // total_len counts from the fpOutputHeader; subtract what we've consumed.
    let consumed = pdu.len() - buf.len();
    let body_len = total_len.checked_sub(consumed).unwrap_or(buf.len());
    if buf.len() < body_len {
        return Err(Error::Short { need: body_len, have: buf.len() });
    }
    let mut body = &buf[..body_len];

    let mut updates = Vec::new();
    while !body.is_empty() {
        let update_header = body[0];
        body = &body[1..];
        let update_code = update_header & 0x0f;
        let fragmentation = (update_header >> 4) & 0x03;
        let compression = (update_header >> 6) & 0x03;

        if compression & FASTPATH_OUTPUT_COMPRESSION_USED != 0 {
            if body.is_empty() {
                return Err(Error::Short { need: 1, have: 0 });
            }
            body = &body[1..]; // compressionFlags (decompression not yet supported)
        }
        if body.len() < 2 {
            return Err(Error::Short { need: 2, have: body.len() });
        }
        let size = u16::from_le_bytes([body[0], body[1]]) as usize;
        body = &body[2..];
        if body.len() < size {
            return Err(Error::Short { need: size, have: body.len() });
        }
        updates.push(FastPathUpdate { update_code, fragmentation, data: body[..size].to_vec() });
        body = &body[size..];
    }
    Ok(updates)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fast-path PDU wrapping a single update.
    fn wrap(update_code: u8, data: &[u8]) -> Vec<u8> {
        let mut update = Vec::new();
        update.push(update_code); // fragmentation SINGLE, no compression
        update.extend_from_slice(&(data.len() as u16).to_le_bytes());
        update.extend_from_slice(data);

        let mut pdu = vec![0u8]; // fpOutputHeader: action fastpath, no flags
        let total = 2 + update.len(); // header(1) + length(1) + update
        pdu.push(total as u8);
        pdu.extend_from_slice(&update);
        pdu
    }

    #[test]
    fn parses_a_single_bitmap_update() {
        let pdu = wrap(UPDATETYPE_BITMAP, b"bitmap-update-bytes");
        let updates = parse_output_pdu(&pdu).unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].update_code, UPDATETYPE_BITMAP);
        assert_eq!(updates[0].data, b"bitmap-update-bytes");
    }

    #[test]
    fn parses_multiple_updates() {
        let mut update = Vec::new();
        for (code, data) in [(UPDATETYPE_SYNCHRONIZE, &b"\x00\x00"[..]), (UPDATETYPE_POINTER, &b"cursor"[..])] {
            update.push(code);
            update.extend_from_slice(&(data.len() as u16).to_le_bytes());
            update.extend_from_slice(data);
        }
        let mut pdu = vec![0u8];
        pdu.push((2 + update.len()) as u8);
        pdu.extend_from_slice(&update);

        let updates = parse_output_pdu(&pdu).unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].update_code, UPDATETYPE_SYNCHRONIZE);
        assert_eq!(updates[1].update_code, UPDATETYPE_POINTER);
    }

    #[test]
    fn two_byte_length_form() {
        let big = vec![0xABu8; 300];
        let pdu = wrap(UPDATETYPE_BITMAP, &big);
        // The wrap() helper used a 1-byte length; rebuild with the 2-byte form.
        let mut update = vec![UPDATETYPE_BITMAP];
        update.extend_from_slice(&(big.len() as u16).to_le_bytes());
        update.extend_from_slice(&big);
        let total = 1 + 2 + update.len();
        let mut pdu2 = vec![0u8];
        pdu2.push(0x80 | (total >> 8) as u8);
        pdu2.push((total & 0xff) as u8);
        pdu2.extend_from_slice(&update);
        let _ = pdu;

        let updates = parse_output_pdu(&pdu2).unwrap();
        assert_eq!(updates[0].data.len(), 300);
    }

    #[test]
    fn rejects_non_fastpath_action() {
        assert!(matches!(parse_output_pdu(&[0x03, 0x02]), Err(Error::Protocol(_))));
    }
}
