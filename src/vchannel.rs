//! Static virtual channel framing ([MS-RDPBCGR] 2.2.6.1): the CHANNEL_PDU_HEADER
//! that prefixes data on a joined virtual channel, plus chunk reassembly. Large
//! messages are split into ≤ `CHANNEL_CHUNK_LENGTH` chunks flagged FIRST/LAST.

use crate::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};

/// Maximum bytes of channel data per chunk.
pub const CHANNEL_CHUNK_LENGTH: usize = 1600;

pub const CHANNEL_FLAG_FIRST: u32 = 0x0000_0001;
pub const CHANNEL_FLAG_LAST: u32 = 0x0000_0002;
pub const CHANNEL_FLAG_SHOW_PROTOCOL: u32 = 0x0000_0010;

/// Wrap `data` as a single-chunk virtual channel PDU (FIRST | LAST). Suitable for
/// messages up to `CHANNEL_CHUNK_LENGTH`.
pub fn wrap(data: &[u8]) -> Vec<u8> {
    let mut out = BytesMut::with_capacity(data.len() + 8);
    out.put_u32_le(data.len() as u32); // total length
    out.put_u32_le(CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST);
    out.extend_from_slice(data);
    out.to_vec()
}

/// Split `data` into virtual channel chunks (each with its own header).
pub fn chunk(data: &[u8]) -> Vec<Vec<u8>> {
    if data.len() <= CHANNEL_CHUNK_LENGTH {
        return vec![wrap(data)];
    }
    let total = data.len() as u32;
    let mut chunks = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + CHANNEL_CHUNK_LENGTH).min(data.len());
        let mut flags = 0u32;
        if offset == 0 {
            flags |= CHANNEL_FLAG_FIRST;
        }
        if end == data.len() {
            flags |= CHANNEL_FLAG_LAST;
        }
        let mut out = BytesMut::new();
        out.put_u32_le(total);
        out.put_u32_le(flags);
        out.extend_from_slice(&data[offset..end]);
        chunks.push(out.to_vec());
        offset = end;
    }
    chunks
}

/// Reassembles chunked virtual channel PDUs into complete messages.
#[derive(Default)]
pub struct Reassembler {
    buffer: Vec<u8>,
    expected: usize,
    in_progress: bool,
}

impl Reassembler {
    pub fn new() -> Reassembler {
        Reassembler::default()
    }

    /// Feed one virtual channel PDU. Returns the complete message when the LAST
    /// chunk arrives, else `None`.
    pub fn push(&mut self, pdu: &[u8]) -> Result<Option<Vec<u8>>> {
        if pdu.len() < 8 {
            return Err(Error::Short { need: 8, have: pdu.len() });
        }
        let mut b = pdu;
        let total = b.get_u32_le() as usize;
        let flags = b.get_u32_le();
        let data = b;

        if flags & CHANNEL_FLAG_FIRST != 0 {
            self.buffer.clear();
            self.expected = total;
            self.in_progress = true;
        }
        if !self.in_progress {
            return Err(Error::Protocol("virtual channel chunk without FIRST"));
        }
        self.buffer.extend_from_slice(data);

        if flags & CHANNEL_FLAG_LAST != 0 {
            self.in_progress = false;
            let msg = std::mem::take(&mut self.buffer);
            return Ok(Some(msg));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_chunk_wraps_and_reassembles() {
        let data = b"hello dynamic channel";
        let pdu = wrap(data);
        let mut r = Reassembler::new();
        assert_eq!(r.push(&pdu).unwrap(), Some(data.to_vec()));
    }

    #[test]
    fn large_message_chunks_and_reassembles() {
        let data: Vec<u8> = (0..4000u32).map(|i| i as u8).collect();
        let chunks = chunk(&data);
        assert!(chunks.len() >= 3);
        let mut r = Reassembler::new();
        let mut result = None;
        for c in &chunks {
            if let Some(msg) = r.push(c).unwrap() {
                result = Some(msg);
            }
        }
        assert_eq!(result, Some(data));
    }

    #[test]
    fn first_chunk_flags_are_set() {
        let chunks = chunk(&vec![0u8; 3500]);
        let first_flags = u32::from_le_bytes([chunks[0][4], chunks[0][5], chunks[0][6], chunks[0][7]]);
        assert!(first_flags & CHANNEL_FLAG_FIRST != 0);
        assert!(first_flags & CHANNEL_FLAG_LAST == 0);
        let last = chunks.last().unwrap();
        let last_flags = u32::from_le_bytes([last[4], last[5], last[6], last[7]]);
        assert!(last_flags & CHANNEL_FLAG_LAST != 0);
    }
}
