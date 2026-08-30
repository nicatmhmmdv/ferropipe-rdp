//! Capability sets and the Confirm Active PDU ([MS-RDPBCGR] 2.2.1.13 / 2.2.7).
//! The server sends a Demand Active PDU advertising its capabilities; the client
//! replies with a Confirm Active PDU carrying its own. Little-endian.

use crate::pdu::{share_control, PDUTYPE_CONFIRMACTIVE};
use crate::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};

/// capabilitySetType values ([MS-RDPBCGR] 2.2.7).
pub const CAPSTYPE_GENERAL: u16 = 1;
pub const CAPSTYPE_BITMAP: u16 = 2;
pub const CAPSTYPE_ORDER: u16 = 3;
pub const CAPSTYPE_POINTER: u16 = 8;
pub const CAPSTYPE_SHARE: u16 = 9;
pub const CAPSTYPE_INPUT: u16 = 13;
pub const CAPSTYPE_VIRTUALCHANNEL: u16 = 20;

/// Frame one capability set: type, total length (incl. 4-byte header), data.
pub fn capability_set(cap_type: u16, data: &[u8]) -> Vec<u8> {
    let mut out = BytesMut::with_capacity(data.len() + 4);
    out.put_u16_le(cap_type);
    out.put_u16_le((data.len() + 4) as u16);
    out.extend_from_slice(data);
    out.to_vec()
}

/// TS_GENERAL_CAPABILITYSET (2.2.7.1.1).
pub fn general_caps() -> Vec<u8> {
    let mut d = BytesMut::new();
    d.put_u16_le(1); // osMajorType = WINDOWS
    d.put_u16_le(3); // osMinorType = WINDOWS NT
    d.put_u16_le(0x0200); // protocolVersion
    d.put_u16_le(0); // pad2octetsA
    d.put_u16_le(0); // generalCompressionTypes
    d.put_u16_le(0); // extraFlags (FASTPATH_OUTPUT etc. set later)
    d.put_u16_le(0); // updateCapabilityFlag
    d.put_u16_le(0); // remoteUnshareFlag
    d.put_u16_le(0); // generalCompressionLevel
    d.put_u8(0); // refreshRectSupport
    d.put_u8(0); // suppressOutputSupport
    capability_set(CAPSTYPE_GENERAL, &d)
}

/// TS_BITMAP_CAPABILITYSET (2.2.7.1.2).
pub fn bitmap_caps(width: u16, height: u16) -> Vec<u8> {
    let mut d = BytesMut::new();
    d.put_u16_le(0x0018); // preferredBitsPerPixel = 24
    d.put_u16_le(1); // receive1BitPerPixel
    d.put_u16_le(1); // receive4BitsPerPixel
    d.put_u16_le(1); // receive8BitsPerPixel
    d.put_u16_le(width);
    d.put_u16_le(height);
    d.put_u16_le(0); // pad2octets
    d.put_u16_le(1); // desktopResizeFlag
    d.put_u16_le(1); // bitmapCompressionFlag
    d.put_u8(0); // highColorFlags
    d.put_u8(0); // drawingFlags
    d.put_u16_le(1); // multipleRectangleSupport
    d.put_u16_le(0); // pad2octetsB
    capability_set(CAPSTYPE_BITMAP, &d)
}

/// TS_POINTER_CAPABILITYSET (2.2.7.1.5).
pub fn pointer_caps() -> Vec<u8> {
    let mut d = BytesMut::new();
    d.put_u16_le(1); // colorPointerFlag
    d.put_u16_le(20); // colorPointerCacheSize
    d.put_u16_le(21); // pointerCacheSize
    capability_set(CAPSTYPE_POINTER, &d)
}

/// TS_INPUT_CAPABILITYSET (2.2.7.1.6).
pub fn input_caps(keyboard_layout: u32) -> Vec<u8> {
    let mut d = BytesMut::new();
    // INPUT_FLAG_SCANCODES | INPUT_FLAG_MOUSEX | INPUT_FLAG_UNICODE | INPUT_FLAG_FASTPATH_INPUT2
    d.put_u16_le(0x0001 | 0x0100 | 0x0004 | 0x0020);
    d.put_u16_le(0); // pad2octetsA
    d.put_u32_le(keyboard_layout);
    d.put_u32_le(4); // keyboardType
    d.put_u32_le(0); // keyboardSubType
    d.put_u32_le(12); // keyboardFunctionKey
    d.extend_from_slice(&[0u8; 64]); // imeFileName
    capability_set(CAPSTYPE_INPUT, &d)
}

/// TS_ORDER_CAPABILITYSET (2.2.7.1.3) with no drawing orders enabled — the server
/// then falls back to bitmap updates, which a bitmap-only client can render.
pub fn order_caps() -> Vec<u8> {
    let mut d = BytesMut::new();
    d.extend_from_slice(&[0u8; 16]); // terminalDescriptor
    d.put_u32_le(0); // pad4octetsA
    d.put_u16_le(1); // desktopSaveXGranularity
    d.put_u16_le(20); // desktopSaveYGranularity
    d.put_u16_le(0); // pad2octetsA
    d.put_u16_le(1); // maximumOrderLevel
    d.put_u16_le(0); // numberFonts
    d.put_u16_le(0x0022); // orderFlags: NEGOTIATEORDERSUPPORT | ZEROBOUNDSDELTASSUPPORT
    d.extend_from_slice(&[0u8; 32]); // orderSupport (none)
    d.put_u16_le(0); // textFlags
    d.put_u16_le(0); // orderSupportExFlags
    d.put_u32_le(0); // pad4octetsB
    d.put_u32_le(230400); // desktopSaveSize
    d.put_u16_le(0); // pad2octetsC
    d.put_u16_le(0); // pad2octetsD
    d.put_u16_le(0); // textANSICodePage
    d.put_u16_le(0); // pad2octetsE
    capability_set(CAPSTYPE_ORDER, &d)
}

/// TS_VIRTUALCHANNEL_CAPABILITYSET (2.2.7.1.10).
pub fn virtual_channel_caps() -> Vec<u8> {
    let mut d = BytesMut::new();
    d.put_u32_le(0); // flags: VCCAPS_NO_COMPR
    d.put_u32_le(0); // VCChunkSize
    capability_set(CAPSTYPE_VIRTUALCHANNEL, &d)
}

/// TS_SHARE_CAPABILITYSET (2.2.7.2.4).
pub fn share_caps() -> Vec<u8> {
    let mut d = BytesMut::new();
    d.put_u16_le(0); // nodeId (filled by server; 0 from client)
    d.put_u16_le(0); // pad2octets
    capability_set(CAPSTYPE_SHARE, &d)
}

/// Build a Confirm Active PDU ([MS-RDPBCGR] 2.2.1.13.2) advertising `capabilities`.
pub fn confirm_active(pdu_source: u16, share_id: u32, capability_sets: &[Vec<u8>]) -> Vec<u8> {
    let source_descriptor = b"MSTSC\0";
    let combined_caps: Vec<u8> = capability_sets.concat();

    let mut body = BytesMut::new();
    body.put_u32_le(share_id);
    body.put_u16_le(0x03EA); // originatorId (server channel)
    body.put_u16_le(source_descriptor.len() as u16); // lengthSourceDescriptor
    // lengthCombinedCapabilities = numberCapabilities(2) + pad(2) + caps.
    body.put_u16_le((combined_caps.len() + 4) as u16);
    body.extend_from_slice(source_descriptor);
    body.put_u16_le(capability_sets.len() as u16); // numberCapabilities
    body.put_u16_le(0); // pad2octets
    body.extend_from_slice(&combined_caps);

    share_control(PDUTYPE_CONFIRMACTIVE, pdu_source, &body)
}

/// Parsed Demand Active header info the client needs to reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DemandActive {
    pub share_id: u32,
    pub capability_sets: Vec<(u16, Vec<u8>)>,
}

/// Parse a Demand Active PDU body (after the share control header).
pub fn parse_demand_active(body: &[u8]) -> Result<DemandActive> {
    let mut b = body;
    if b.len() < 8 {
        return Err(Error::Short { need: 8, have: b.len() });
    }
    let share_id = b.get_u32_le();
    let len_source = b.get_u16_le() as usize;
    let _len_combined = b.get_u16_le() as usize;
    if b.len() < len_source + 4 {
        return Err(Error::Short { need: len_source + 4, have: b.len() });
    }
    b.advance(len_source); // sourceDescriptor
    let number_caps = b.get_u16_le() as usize;
    b.advance(2); // pad2octets
    let mut capability_sets = Vec::with_capacity(number_caps);
    for _ in 0..number_caps {
        if b.len() < 4 {
            return Err(Error::Short { need: 4, have: b.len() });
        }
        let cap_type = b.get_u16_le();
        let cap_len = b.get_u16_le() as usize;
        if cap_len < 4 || b.len() < cap_len - 4 {
            return Err(Error::Protocol("bad capability set length"));
        }
        let data = b[..cap_len - 4].to_vec();
        b.advance(cap_len - 4);
        capability_sets.push((cap_type, data));
    }
    Ok(DemandActive { share_id, capability_sets })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::parse_share_control;

    #[test]
    fn capability_set_framing() {
        let cs = capability_set(CAPSTYPE_GENERAL, &[1, 2, 3, 4]);
        assert_eq!(u16::from_le_bytes([cs[0], cs[1]]), CAPSTYPE_GENERAL);
        assert_eq!(u16::from_le_bytes([cs[2], cs[3]]) as usize, cs.len());
    }

    #[test]
    fn confirm_active_is_valid_share_control() {
        let caps = [general_caps(), bitmap_caps(1024, 768), pointer_caps(), input_caps(0x409), share_caps()];
        let pdu = confirm_active(1007, 0x0001_03EA, &caps);
        let (hdr, _body) = parse_share_control(&pdu).unwrap();
        assert_eq!(hdr.pdu_type, PDUTYPE_CONFIRMACTIVE);
        assert_eq!(hdr.pdu_source, 1007);
    }

    #[test]
    fn demand_active_roundtrips_through_parse() {
        // Build a Demand-Active-shaped body and parse it back.
        let caps = [general_caps(), bitmap_caps(800, 600)];
        let combined: Vec<u8> = caps.concat();
        let mut body = BytesMut::new();
        body.put_u32_le(0x0001_03EA); // shareId
        body.put_u16_le(6); // lengthSourceDescriptor
        body.put_u16_le((combined.len() + 4) as u16);
        body.extend_from_slice(b"RDP\0\0\0");
        body.put_u16_le(2); // numberCapabilities
        body.put_u16_le(0);
        body.extend_from_slice(&combined);

        let da = parse_demand_active(&body).unwrap();
        assert_eq!(da.share_id, 0x0001_03EA);
        assert_eq!(da.capability_sets.len(), 2);
        assert_eq!(da.capability_sets[0].0, CAPSTYPE_GENERAL);
        assert_eq!(da.capability_sets[1].0, CAPSTYPE_BITMAP);
    }
}
