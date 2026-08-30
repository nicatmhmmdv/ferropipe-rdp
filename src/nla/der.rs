//! Minimal ASN.1 DER encoder/decoder — just what CredSSP's TSRequest and
//! TSCredentials need ([MS-CSSP] 2.2.1). Definite-length only.
//!
//! CredSSP uses EXPLICIT context tagging: `[n]` is a constructed context tag
//! `0xA0 + n` wrapping the inner universal type.

use crate::{Error, Result};

pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_SEQUENCE: u8 = 0x30;

/// Constructed context-specific tag byte for `[n]`.
pub fn context_tag(n: u8) -> u8 {
    0xA0 + n
}

/// Encode a DER definite length.
pub fn encode_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut bytes = Vec::new();
        let mut v = len;
        while v > 0 {
            bytes.insert(0, (v & 0xff) as u8);
            v >>= 8;
        }
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend_from_slice(&bytes);
        out
    }
}

/// Encode a tag-length-value triple.
pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 4);
    out.push(tag);
    out.extend_from_slice(&encode_len(value.len()));
    out.extend_from_slice(value);
    out
}

/// Encode an unsigned INTEGER (minimal, with a leading 0x00 if the high bit is set).
pub fn integer(v: u64) -> Vec<u8> {
    if v == 0 {
        return tlv(TAG_INTEGER, &[0]);
    }
    let mut bytes = Vec::new();
    let mut n = v;
    while n > 0 {
        bytes.insert(0, (n & 0xff) as u8);
        n >>= 8;
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }
    tlv(TAG_INTEGER, &bytes)
}

pub fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(TAG_OCTET_STRING, bytes)
}

pub fn sequence(contents: &[u8]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, contents)
}

/// Wrap `contents` in an explicit context tag `[n]`.
pub fn context(n: u8, contents: &[u8]) -> Vec<u8> {
    tlv(context_tag(n), contents)
}

/// A cursor over DER bytes for decoding.
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Read one TLV, returning (tag, value). Advances past it.
    pub fn read_tlv(&mut self) -> Result<(u8, &'a [u8])> {
        if self.buf.len() < 2 {
            return Err(Error::Short { need: 2, have: self.buf.len() });
        }
        let tag = self.buf[0];
        let (len, header) = decode_len(&self.buf[1..])?;
        let start = 1 + header;
        let end = start + len;
        if self.buf.len() < end {
            return Err(Error::Short { need: end, have: self.buf.len() });
        }
        let value = &self.buf[start..end];
        self.buf = &self.buf[end..];
        Ok((tag, value))
    }

    /// Read a TLV and assert its tag.
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8]> {
        let (t, v) = self.read_tlv()?;
        if t != tag {
            return Err(Error::Protocol("unexpected DER tag"));
        }
        Ok(v)
    }

    /// Read an INTEGER as a u64 (big-endian, unsigned).
    pub fn read_integer(&mut self) -> Result<u64> {
        let v = self.expect(TAG_INTEGER)?;
        let mut n: u64 = 0;
        for &b in v {
            n = (n << 8) | b as u64;
        }
        Ok(n)
    }
}

/// Decode a DER length, returning (length, header_bytes_consumed).
pub fn decode_len(buf: &[u8]) -> Result<(usize, usize)> {
    if buf.is_empty() {
        return Err(Error::Short { need: 1, have: 0 });
    }
    let first = buf[0];
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || buf.len() < 1 + n {
        return Err(Error::Protocol("bad DER length"));
    }
    let mut len = 0usize;
    for &b in &buf[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Ok((len, 1 + n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_encodings() {
        assert_eq!(integer(6), vec![0x02, 0x01, 0x06]);
        assert_eq!(integer(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(integer(128), vec![0x02, 0x02, 0x00, 0x80]); // high bit → leading 0
        assert_eq!(integer(0x1234), vec![0x02, 0x02, 0x12, 0x34]);
    }

    #[test]
    fn length_encodings() {
        assert_eq!(encode_len(10), vec![10]);
        assert_eq!(encode_len(127), vec![127]);
        assert_eq!(encode_len(128), vec![0x81, 128]);
        assert_eq!(encode_len(300), vec![0x82, 0x01, 0x2c]);
    }

    #[test]
    fn octet_string_and_context_wrap() {
        assert_eq!(octet_string(&[1, 2, 3]), vec![0x04, 0x03, 1, 2, 3]);
        // [0] wrapping INTEGER 2 → A0 03 02 01 02
        assert_eq!(context(0, &integer(2)), vec![0xA0, 0x03, 0x02, 0x01, 0x02]);
    }

    #[test]
    fn nested_sequence_roundtrips() {
        // SEQUENCE { [0] INTEGER 5, [1] OCTET STRING "hi" }
        let body = [context(0, &integer(5)), context(1, &octet_string(b"hi"))].concat();
        let seq = sequence(&body);

        let mut r = Reader::new(&seq);
        let inner = r.expect(TAG_SEQUENCE).unwrap();
        let mut ri = Reader::new(inner);
        let v0 = ri.expect(context_tag(0)).unwrap();
        assert_eq!(Reader::new(v0).read_integer().unwrap(), 5);
        let v1 = ri.expect(context_tag(1)).unwrap();
        assert_eq!(Reader::new(v1).expect(TAG_OCTET_STRING).unwrap(), b"hi");
    }

    #[test]
    fn long_form_length_roundtrips() {
        let big = vec![0xABu8; 500];
        let enc = octet_string(&big);
        let mut r = Reader::new(&enc);
        assert_eq!(r.expect(TAG_OCTET_STRING).unwrap(), &big[..]);
    }
}
