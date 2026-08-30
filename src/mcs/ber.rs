//! Minimal ASN.1 BER encoding for the MCS Connect Initial/Response PDUs
//! (ITU-T T.125 / [MS-RDPBCGR] 2.2.1.3-2.2.1.4). Definite-length only.

use crate::{Error, Result};

/// Encode a definite BER length.
pub fn length(len: usize) -> Vec<u8> {
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

fn tlv(tag: &[u8], contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + 4 + contents.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(&length(contents.len()));
    out.extend_from_slice(contents);
    out
}

/// INTEGER (universal tag 2), minimal unsigned encoding.
pub fn integer(v: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut n = v;
    if n == 0 {
        bytes.push(0);
    }
    while n > 0 {
        bytes.insert(0, (n & 0xff) as u8);
        n >>= 8;
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00); // keep it positive
    }
    tlv(&[0x02], &bytes)
}

/// BOOLEAN (universal tag 1); TRUE is 0xFF.
pub fn boolean(b: bool) -> Vec<u8> {
    tlv(&[0x01], &[if b { 0xff } else { 0x00 }])
}

/// OCTET STRING (universal tag 4).
pub fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(&[0x04], bytes)
}

/// ENUMERATED (universal tag 10).
pub fn enumerated(v: u8) -> Vec<u8> {
    tlv(&[0x0a], &[v])
}

/// SEQUENCE (universal tag 0x30, constructed).
pub fn sequence(contents: &[u8]) -> Vec<u8> {
    tlv(&[0x30], contents)
}

/// Application-class constructed tag (e.g. 101 for Connect-Initial).
pub fn application_tag_bytes(tag_number: u32) -> Vec<u8> {
    if tag_number < 31 {
        vec![0x40 | 0x20 | tag_number as u8]
    } else {
        // Long form: 0x7F then base-128 of the tag number, high bit set on all but last.
        let mut digits = Vec::new();
        let mut n = tag_number;
        digits.push((n & 0x7f) as u8);
        n >>= 7;
        while n > 0 {
            digits.push((n & 0x7f) as u8 | 0x80);
            n >>= 7;
        }
        digits.reverse();
        let mut out = vec![0x7f];
        out.extend_from_slice(&digits);
        out
    }
}

/// Wrap `contents` in an application-class constructed tag.
pub fn application(tag_number: u32, contents: &[u8]) -> Vec<u8> {
    tlv(&application_tag_bytes(tag_number), contents)
}

/// A BER reader over a byte slice.
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

    /// Read the length field at the cursor.
    pub fn read_length(&mut self) -> Result<usize> {
        if self.buf.is_empty() {
            return Err(Error::Short { need: 1, have: 0 });
        }
        let first = self.buf[0];
        self.buf = &self.buf[1..];
        if first < 0x80 {
            return Ok(first as usize);
        }
        let n = (first & 0x7f) as usize;
        if self.buf.len() < n {
            return Err(Error::Short { need: n, have: self.buf.len() });
        }
        let mut len = 0usize;
        for &b in &self.buf[..n] {
            len = (len << 8) | b as usize;
        }
        self.buf = &self.buf[n..];
        Ok(len)
    }

    /// Expect a specific (possibly multi-byte) tag, returning its contents.
    pub fn expect(&mut self, tag: &[u8]) -> Result<&'a [u8]> {
        if self.buf.len() < tag.len() {
            return Err(Error::Short { need: tag.len(), have: self.buf.len() });
        }
        if &self.buf[..tag.len()] != tag {
            return Err(Error::Protocol("unexpected BER tag"));
        }
        self.buf = &self.buf[tag.len()..];
        let len = self.read_length()?;
        if self.buf.len() < len {
            return Err(Error::Short { need: len, have: self.buf.len() });
        }
        let v = &self.buf[..len];
        self.buf = &self.buf[len..];
        Ok(v)
    }

    /// Read an INTEGER's value as u32.
    pub fn read_integer(&mut self) -> Result<u32> {
        let v = self.expect(&[0x02])?;
        let mut n = 0u32;
        for &b in v {
            n = (n << 8) | b as u32;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_and_length() {
        assert_eq!(integer(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(integer(2), vec![0x02, 0x01, 0x02]);
        assert_eq!(integer(65535), vec![0x02, 0x03, 0x00, 0xff, 0xff]);
        assert_eq!(length(200), vec![0x81, 0xc8]);
    }

    #[test]
    fn application_tag_short_and_long() {
        // Connect-Initial = application 101 → 0x7f 0x65
        assert_eq!(application_tag_bytes(101), vec![0x7f, 0x65]);
        assert_eq!(application_tag_bytes(102), vec![0x7f, 0x66]);
        assert_eq!(application_tag_bytes(30), vec![0x40 | 0x20 | 30]);
    }

    #[test]
    fn reader_roundtrips_integer_and_octet_string() {
        let enc = [integer(65535), octet_string(b"hello")].concat();
        let mut r = Reader::new(&enc);
        assert_eq!(r.read_integer().unwrap(), 65535);
        assert_eq!(r.expect(&[0x04]).unwrap(), b"hello");
    }

    #[test]
    fn application_wrap_roundtrips() {
        let inner = integer(7);
        let app = application(101, &inner);
        assert_eq!(&app[..2], &[0x7f, 0x65]);
        let mut r = Reader::new(&app);
        let contents = r.expect(&[0x7f, 0x65]).unwrap();
        assert_eq!(Reader::new(contents).read_integer().unwrap(), 7);
    }
}
