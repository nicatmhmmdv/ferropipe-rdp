//! TPKT framing (RFC 1006 / [MS-RDPBCGR] 2.2.1). Big-endian.
//!
//! A TPKT packet is a 4-byte header — version `3`, one reserved byte, and a
//! 16-bit total length (header included) — followed by the X.224 payload. RDP
//! uses TPKT for all "slow-path" PDUs; fast-path updates use a different, smaller
//! header (added in a later phase).

use crate::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};

/// TPKT version byte — always 3.
pub const TPKT_VERSION: u8 = 3;
/// Size of the TPKT header in bytes.
pub const TPKT_HEADER_LEN: usize = 4;
/// Largest payload a single TPKT can carry (u16 length minus the header).
pub const MAX_TPKT_PAYLOAD: usize = u16::MAX as usize - TPKT_HEADER_LEN;

/// Wrap `payload` in a TPKT header, returning the full packet.
pub fn encode(payload: &[u8]) -> Result<BytesMut> {
    if payload.len() > MAX_TPKT_PAYLOAD {
        return Err(Error::Protocol("TPKT payload exceeds u16 length"));
    }
    let total = (payload.len() + TPKT_HEADER_LEN) as u16;
    let mut out = BytesMut::with_capacity(total as usize);
    out.put_u8(TPKT_VERSION);
    out.put_u8(0); // reserved
    out.put_u16(total); // big-endian total length
    out.extend_from_slice(payload);
    Ok(out)
}

/// Parse a TPKT header off the front of `buf` and return the declared **total**
/// packet length (header + payload). Does not consume; the caller decides whether
/// the whole packet is present before slicing.
pub fn peek_total_len(buf: &[u8]) -> Result<usize> {
    if buf.len() < TPKT_HEADER_LEN {
        return Err(Error::Short { need: TPKT_HEADER_LEN, have: buf.len() });
    }
    if buf[0] != TPKT_VERSION {
        return Err(Error::Protocol("bad TPKT version"));
    }
    let total = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if total < TPKT_HEADER_LEN {
        return Err(Error::Protocol("TPKT length shorter than header"));
    }
    Ok(total)
}

/// Strip the TPKT header from a complete packet, returning the X.224 payload.
pub fn decode(buf: &[u8]) -> Result<&[u8]> {
    let total = peek_total_len(buf)?;
    if buf.len() < total {
        return Err(Error::Short { need: total, have: buf.len() });
    }
    let mut header = &buf[..TPKT_HEADER_LEN];
    header.advance(2); // version + reserved
    let _ = header.get_u16();
    Ok(&buf[TPKT_HEADER_LEN..total])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_then_decode_roundtrips() {
        let payload = b"\xe0\x00\x00\x00\x00\x00"; // a small X.224-ish blob
        let pkt = encode(payload).unwrap();
        assert_eq!(pkt[0], 3);
        assert_eq!(pkt[1], 0);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]) as usize, payload.len() + 4);
        assert_eq!(decode(&pkt).unwrap(), payload);
    }

    #[test]
    fn peek_reports_total_length() {
        let pkt = encode(&[0u8; 10]).unwrap();
        assert_eq!(peek_total_len(&pkt).unwrap(), 14);
    }

    #[test]
    fn decode_needs_the_whole_packet() {
        let pkt = encode(&[0u8; 20]).unwrap();
        // Truncate to just under the declared length.
        assert!(matches!(decode(&pkt[..10]), Err(Error::Short { .. })));
    }

    #[test]
    fn rejects_bad_version() {
        let mut pkt = encode(&[0u8; 4]).unwrap();
        pkt[0] = 4;
        assert!(matches!(peek_total_len(&pkt), Err(Error::Protocol(_))));
    }
}
