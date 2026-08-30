//! ASN.1 PER (ALIGNED) primitives for the MCS domain PDUs and GCC
//! ConferenceCreate (ITU-T X.691 as used by T.124/T.125). Only the subset RDP
//! needs. PER integers are big-endian.

use crate::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};

/// Write a PER length determinant (ALIGNED). Values up to 0x3FFF use the 1- or
/// 2-byte forms RDP relies on; larger (fragmented) lengths are not emitted here.
pub fn write_length(out: &mut BytesMut, n: usize) {
    if n < 0x80 {
        out.put_u8(n as u8);
    } else if n < 0x4000 {
        out.put_u16((n as u16) | 0x8000);
    } else {
        // Fragmented form: single-fragment with the 0xC0 count marker.
        out.put_u8(0xC1);
        out.put_u16(n as u16);
    }
}

/// Read a PER length determinant.
pub fn read_length(buf: &mut &[u8]) -> Result<usize> {
    if buf.is_empty() {
        return Err(Error::Short { need: 1, have: 0 });
    }
    let first = buf.get_u8();
    if first & 0x80 == 0 {
        Ok(first as usize)
    } else if first & 0xC0 == 0x80 {
        if buf.is_empty() {
            return Err(Error::Short { need: 1, have: 0 });
        }
        let lo = buf.get_u8();
        Ok((((first & 0x3f) as usize) << 8) | lo as usize)
    } else {
        Err(Error::Protocol("unsupported PER fragmented length"))
    }
}

/// Write a constrained INTEGER in the 16-bit range as a big-endian u16.
pub fn write_u16(out: &mut BytesMut, v: u16) {
    out.put_u16(v);
}

/// Write a CHOICE index / small enumerated value as one byte.
pub fn write_u8(out: &mut BytesMut, v: u8) {
    out.put_u8(v);
}

/// Encode an OBJECT IDENTIFIER as a PER octet string (length determinant + bytes).
pub fn write_object_identifier(out: &mut BytesMut, oid_encoded: &[u8]) {
    write_length(out, oid_encoded.len());
    out.extend_from_slice(oid_encoded);
}

/// Encode an OCTET STRING with a PER length determinant.
pub fn write_octet_string(out: &mut BytesMut, bytes: &[u8]) {
    write_length(out, bytes.len());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_short_form() {
        let mut out = BytesMut::new();
        write_length(&mut out, 0x1f);
        assert_eq!(&out[..], &[0x1f]);
        let mut slice = &out[..];
        assert_eq!(read_length(&mut slice).unwrap(), 0x1f);
    }

    #[test]
    fn length_two_byte_form() {
        let mut out = BytesMut::new();
        write_length(&mut out, 0x200);
        assert_eq!(&out[..], &[0x82, 0x00]); // 0x0200 | 0x8000 = 0x8200
        let mut slice = &out[..];
        assert_eq!(read_length(&mut slice).unwrap(), 0x200);
    }

    #[test]
    fn length_boundary_127_and_128() {
        for n in [0usize, 1, 127, 128, 255, 1000, 0x3fff] {
            let mut out = BytesMut::new();
            write_length(&mut out, n);
            let mut slice = &out[..];
            assert_eq!(read_length(&mut slice).unwrap(), n, "n={n}");
        }
    }
}
