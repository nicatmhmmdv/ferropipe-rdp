//! MCS domain PDUs ([MS-RDPBCGR] 2.2.1.5-2.2.1.13, ITU-T T.125). PER-encoded.
//! The DomainMCSPDU CHOICE index sits in the top 6 bits of the first byte
//! (`index << 2`); the low bit 0x02 marks an optional field present. Send Data
//! Request/Indication wrap every RDP PDU once the channels are joined.
//!
//! UserIds and the initiator field are encoded as PER INTEGER(16) offset from
//! `MCS_BASE = 1001`; channel IDs are offset from 0 (i.e. sent directly).

use super::per;
use crate::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};

/// Base value for MCS user/channel INTEGER(16) fields.
const MCS_BASE: u16 = 1001;
/// The well-known RDP I/O channel.
pub const IO_CHANNEL: u16 = 1003;

// DomainMCSPDU CHOICE indices.
const ERECT_DOMAIN_REQUEST: u8 = 1;
const ATTACH_USER_REQUEST: u8 = 10;
const ATTACH_USER_CONFIRM: u8 = 11;
const CHANNEL_JOIN_REQUEST: u8 = 14;
const CHANNEL_JOIN_CONFIRM: u8 = 15;
const SEND_DATA_REQUEST: u8 = 25;
const SEND_DATA_INDICATION: u8 = 26;

fn choice(index: u8) -> u8 {
    index << 2
}

/// MCS Erect Domain Request (subHeight=0, subInterval=0).
pub fn erect_domain_request() -> Vec<u8> {
    vec![choice(ERECT_DOMAIN_REQUEST), 0x01, 0x00, 0x01, 0x00]
}

/// MCS Attach User Request (a single choice byte).
pub fn attach_user_request() -> Vec<u8> {
    vec![choice(ATTACH_USER_REQUEST)]
}

/// Parse an MCS Attach User Confirm, returning the assigned user channel ID.
pub fn parse_attach_user_confirm(buf: &[u8]) -> Result<u16> {
    if buf.len() < 2 {
        return Err(Error::Short { need: 2, have: buf.len() });
    }
    let mut b = buf;
    let tag = b.get_u8();
    if tag >> 2 != ATTACH_USER_CONFIRM {
        return Err(Error::Protocol("not an Attach User Confirm"));
    }
    let result = b.get_u8(); // ENUMERATED result
    if result != 0 {
        return Err(Error::NegotiationFailure("Attach User Confirm result not successful"));
    }
    // initiator present iff low bit 0x02 was set on the tag.
    if tag & 0x02 == 0 || b.len() < 2 {
        return Err(Error::Protocol("Attach User Confirm missing initiator"));
    }
    Ok(b.get_u16() + MCS_BASE)
}

/// MCS Channel Join Request for `channel_id` from `user_id`.
pub fn channel_join_request(user_id: u16, channel_id: u16) -> Vec<u8> {
    let mut out = BytesMut::new();
    out.put_u8(choice(CHANNEL_JOIN_REQUEST));
    out.put_u16(user_id - MCS_BASE); // initiator (base 1001)
    out.put_u16(channel_id); // channelId (base 0)
    out.to_vec()
}

/// Parse an MCS Channel Join Confirm, returning the joined channel ID.
pub fn parse_channel_join_confirm(buf: &[u8]) -> Result<u16> {
    if buf.len() < 2 {
        return Err(Error::Short { need: 2, have: buf.len() });
    }
    let mut b = buf;
    let tag = b.get_u8();
    if tag >> 2 != CHANNEL_JOIN_CONFIRM {
        return Err(Error::Protocol("not a Channel Join Confirm"));
    }
    let result = b.get_u8();
    if result != 0 {
        return Err(Error::NegotiationFailure("Channel Join Confirm result not successful"));
    }
    if b.len() < 4 {
        return Err(Error::Short { need: 4, have: b.len() });
    }
    let _initiator = b.get_u16();
    let _requested = b.get_u16();
    // The confirmed channelId follows when present (low bit set).
    if tag & 0x02 != 0 {
        if b.len() < 2 {
            return Err(Error::Short { need: 2, have: b.len() });
        }
        Ok(b.get_u16())
    } else {
        Ok(_requested)
    }
}

/// Wrap `data` in an MCS Send Data Request on `channel_id` from `user_id`.
pub fn send_data_request(user_id: u16, channel_id: u16, data: &[u8]) -> Vec<u8> {
    let mut out = BytesMut::new();
    out.put_u8(choice(SEND_DATA_REQUEST));
    out.put_u16(user_id - MCS_BASE); // initiator
    out.put_u16(channel_id); // channelId
    out.put_u8(0x70); // dataPriority (high) + segmentation (begin|end)
    per::write_length(&mut out, data.len());
    out.extend_from_slice(data);
    out.to_vec()
}

/// Parse an MCS Send Data Indication, returning (channel_id, payload).
pub fn parse_send_data_indication(buf: &[u8]) -> Result<(u16, &[u8])> {
    if buf.is_empty() {
        return Err(Error::Short { need: 1, have: 0 });
    }
    let mut b = buf;
    let tag = b.get_u8();
    if tag >> 2 != SEND_DATA_INDICATION {
        return Err(Error::Protocol("not a Send Data Indication"));
    }
    if b.len() < 5 {
        return Err(Error::Short { need: 5, have: b.len() });
    }
    let _initiator = b.get_u16();
    let channel_id = b.get_u16();
    let _priority = b.get_u8();
    let len = per::read_length(&mut b)?;
    if b.len() < len {
        return Err(Error::Short { need: len, have: b.len() });
    }
    // Compute the payload offset back into the original buffer.
    let consumed = buf.len() - b.len();
    Ok((channel_id, &buf[consumed..consumed + len]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erect_and_attach_have_expected_choice_bytes() {
        assert_eq!(erect_domain_request()[0], 0x04);
        assert_eq!(attach_user_request(), vec![0x28]);
    }

    #[test]
    fn attach_user_confirm_extracts_channel() {
        // tag = (11<<2)|2 = 0x2E, result 0, initiator 6 → user channel 1007.
        let buf = [0x2E, 0x00, 0x00, 0x06];
        assert_eq!(parse_attach_user_confirm(&buf).unwrap(), 1007);
    }

    #[test]
    fn channel_join_request_encoding() {
        let req = channel_join_request(1007, IO_CHANNEL);
        assert_eq!(req[0], 0x38); // 14 << 2
        assert_eq!(u16::from_be_bytes([req[1], req[2]]), 1007 - MCS_BASE);
        assert_eq!(u16::from_be_bytes([req[3], req[4]]), IO_CHANNEL);
    }

    #[test]
    fn channel_join_confirm_extracts_channel() {
        // tag=(15<<2)|2=0x3E, result 0, initiator 6, requested 1003, channelId 1003.
        let mut buf = BytesMut::new();
        buf.put_u8(0x3E);
        buf.put_u8(0x00);
        buf.put_u16(6);
        buf.put_u16(1003);
        buf.put_u16(1003);
        assert_eq!(parse_channel_join_confirm(&buf).unwrap(), 1003);
    }

    #[test]
    fn send_data_request_roundtrips_via_indication_parser() {
        let payload = b"an-rdp-pdu-payload";
        let req = send_data_request(1007, IO_CHANNEL, payload);
        assert_eq!(req[0], 0x64); // 25 << 2
        // Re-tag as an indication (26<<2 = 0x68) to exercise the parser.
        let mut ind = req.clone();
        ind[0] = 0x68;
        let (chan, data) = parse_send_data_indication(&ind).unwrap();
        assert_eq!(chan, IO_CHANNEL);
        assert_eq!(data, payload);
    }
}
