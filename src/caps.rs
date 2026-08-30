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
pub const CAPSTYPE_BITMAPCACHE: u16 = 4;
pub const CAPSTYPE_CONTROL: u16 = 5;
pub const CAPSTYPE_ACTIVATION: u16 = 7;
pub const CAPSTYPE_COLORCACHE: u16 = 10;
pub const CAPSTYPE_SOUND: u16 = 12;
pub const CAPSTYPE_FONT: u16 = 14;
pub const CAPSTYPE_BRUSH: u16 = 15;
pub const CAPSTYPE_GLYPHCACHE: u16 = 16;
pub const CAPSTYPE_OFFSCREENCACHE: u16 = 17;

/// TS_CONTROL_CAPABILITYSET (2.2.7.2.2).
pub fn control_caps() -> Vec<u8> {
    let mut d = BytesMut::new();
    d.put_u16_le(0); // controlFlags
    d.put_u16_le(0); // remoteDetachFlag
    d.put_u16_le(2); // controlInterest = CONTROLPRIORITY_NEVER
    d.put_u16_le(2); // detachInterest = CONTROLPRIORITY_NEVER
    capability_set(CAPSTYPE_CONTROL, &d)
}

/// TS_WINDOWACTIVATION_CAPABILITYSET (2.2.7.2.3) — all flags off.
pub fn activation_caps() -> Vec<u8> {
    capability_set(CAPSTYPE_ACTIVATION, &[0u8; 8])
}

/// TS_COLORTABLE_CACHE_CAPABILITYSET (2.2.7.1.4).
pub fn color_cache_caps() -> Vec<u8> {
    let mut d = BytesMut::new();
    d.put_u16_le(6); // colorTableCacheSize
    d.put_u16_le(0); // pad2octets
    capability_set(CAPSTYPE_COLORCACHE, &d)
}

/// TS_SOUND_CAPABILITYSET (2.2.7.1.11).
pub fn sound_caps() -> Vec<u8> {
    capability_set(CAPSTYPE_SOUND, &[0x01, 0x00, 0x00, 0x00]) // SOUND_BEEPS_FLAG
}

/// TS_FONT_CAPABILITYSET (2.2.7.2.5).
pub fn font_caps() -> Vec<u8> {
    let mut d = BytesMut::new();
    d.put_u16_le(0x0001); // FONTSUPPORT_FONTLIST
    d.put_u16_le(0); // pad2octets
    capability_set(CAPSTYPE_FONT, &d)
}

/// TS_BRUSH_CAPABILITYSET (2.2.7.1.7) — BRUSH_DEFAULT.
pub fn brush_caps() -> Vec<u8> {
    let mut d = BytesMut::new();
    d.put_u32_le(2); // brushSupportLevel = BRUSH_COLOR_FULL
    capability_set(CAPSTYPE_BRUSH, &d)
}

/// TS_GLYPHCACHE_CAPABILITYSET (2.2.7.1.8) — support level NONE (server uses bitmaps).
pub fn glyph_cache_caps() -> Vec<u8> {
    let mut d = BytesMut::new();
    // 10 cache definitions (cacheEntries, cacheMaximumCellSize).
    for &(entries, cell) in &[
        (254u16, 4u16), (254, 4), (254, 8), (254, 8), (254, 16), (254, 32), (254, 64), (254, 128), (254, 256), (254, 256),
    ] {
        d.put_u16_le(entries);
        d.put_u16_le(cell);
    }
    d.put_u32_le(0x0100_0100); // FragCache
    d.put_u16_le(0); // GlyphSupportLevel = GLYPH_SUPPORT_NONE
    d.put_u16_le(0); // pad2octets
    capability_set(CAPSTYPE_GLYPHCACHE, &d)
}

/// TS_OFFSCREEN_CAPABILITYSET (2.2.7.1.9) — offscreen caching disabled.
pub fn offscreen_caps() -> Vec<u8> {
    let mut d = BytesMut::new();
    d.put_u32_le(0); // offscreenSupportLevel = FALSE
    d.put_u16_le(0); // offscreenCacheSize
    d.put_u16_le(0); // offscreenCacheEntries
    capability_set(CAPSTYPE_OFFSCREENCACHE, &d)
}

pub const CAPSTYPE_BITMAPCACHE_REV2: u16 = 19;
pub const CAPSETTYPE_BITMAP_CODECS: u16 = 29;

/// TS_BITMAPCACHE_CAPABILITYSET_REV2 (2.2.7.1.4.2) — matches what a modern client
/// sends (the server rejects the legacy rev1 cache cap on RDP 8+ sessions).
pub fn bitmap_cache_rev2_caps() -> Vec<u8> {
    // CacheFlags, pad, NumCellCaches=5, 5×CellInfo, 12 bytes pad3 (mstsc/FreeRDP values).
    let body: [u8; 36] = [
        0x02, 0x00, 0x00, 0x05, 0x58, 0x02, 0x00, 0x00, 0x58, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    capability_set(CAPSTYPE_BITMAPCACHE_REV2, &body)
}

/// TS_BITMAPCODECS_CAPABILITYSET (2.2.7.2.10) — advertise codec support with an
/// empty codec list (bitmapCodecCount = 0), which modern servers expect present.
pub fn bitmap_codecs_caps() -> Vec<u8> {
    capability_set(CAPSETTYPE_BITMAP_CODECS, &[0x00])
}

pub const CAPSETTYPE_MULTIFRAGMENTUPDATE: u16 = 26;
pub const CAPSETTYPE_LARGE_POINTER: u16 = 27;
pub const CAPSETTYPE_SURFACE_COMMANDS: u16 = 28;
pub const CAPSETTYPE_FRAME_ACKNOWLEDGE: u16 = 30;

/// TS_MULTIFRAGMENTUPDATE_CAPABILITYSET (2.2.7.2.6).
pub fn multifragment_caps() -> Vec<u8> {
    let mut d = BytesMut::new();
    d.put_u32_le(0x0009_482b); // MaxRequestSize
    capability_set(CAPSETTYPE_MULTIFRAGMENTUPDATE, &d)
}

/// TS_LARGE_POINTER_CAPABILITYSET (2.2.7.2.7).
pub fn large_pointer_caps() -> Vec<u8> {
    let mut d = BytesMut::new();
    d.put_u16_le(0x0003); // LARGE_POINTER_FLAG_96x96 | LARGE_POINTER_FLAG_384x384
    capability_set(CAPSETTYPE_LARGE_POINTER, &d)
}

/// TS_SURFCMDS_CAPABILITYSET (2.2.9.2.1).
pub fn surface_commands_caps() -> Vec<u8> {
    let mut d = BytesMut::new();
    // SURFCMDS_SETSURFACEBITS | SURFCMDS_FRAMEMARKER | SURFCMDS_STREAMSURFACEBITS
    d.put_u32_le(0x02 | 0x10 | 0x40);
    d.put_u32_le(0); // reserved
    capability_set(CAPSETTYPE_SURFACE_COMMANDS, &d)
}

/// TS_FRAME_ACKNOWLEDGE_CAPABILITYSET ([MS-RDPRFX] 2.2.1.3) — max unacked frames.
pub fn frame_acknowledge_caps() -> Vec<u8> {
    let mut d = BytesMut::new();
    d.put_u32_le(2); // maxUnacknowledgedFrameCount
    capability_set(CAPSETTYPE_FRAME_ACKNOWLEDGE, &d)
}

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
    d.put_u16_le(4); // osMajorType = UNIX
    d.put_u16_le(7); // osMinorType
    d.put_u16_le(0x0200); // protocolVersion
    d.put_u16_le(0); // pad2octetsA
    d.put_u16_le(0); // generalCompressionTypes
    // FASTPATH_OUTPUT | NO_BITMAP_COMPRESSION_HDR | LONG_CREDENTIALS | ENC_SALTED_CHECKSUM | AUTORECONNECT
    d.put_u16_le(0x0001 | 0x0400 | 0x0004 | 0x0008 | 0x0010);
    d.put_u16_le(0); // updateCapabilityFlag
    d.put_u16_le(0); // remoteUnshareFlag
    d.put_u16_le(0); // generalCompressionLevel
    d.put_u8(1); // refreshRectSupport
    d.put_u8(1); // suppressOutputSupport
    capability_set(CAPSTYPE_GENERAL, &d)
}

/// TS_BITMAP_CAPABILITYSET (2.2.7.1.2).
pub fn bitmap_caps(width: u16, height: u16) -> Vec<u8> {
    let mut d = BytesMut::new();
    d.put_u16_le(32); // preferredBitsPerPixel = 32 (matches the 32bpp session from WANT_32BPP)
    d.put_u16_le(1); // receive1BitPerPixel
    d.put_u16_le(1); // receive4BitsPerPixel
    d.put_u16_le(1); // receive8BitsPerPixel
    d.put_u16_le(width);
    d.put_u16_le(height);
    d.put_u16_le(0); // pad2octets
    d.put_u16_le(1); // desktopResizeFlag
    d.put_u16_le(1); // bitmapCompressionFlag
    d.put_u8(0); // highColorFlags
    d.put_u8(0x0a); // drawingFlags = DRAW_ALLOW_DYNAMIC_COLOR_FIDELITY | DRAW_ALLOW_SKIP_ALPHA
    d.put_u16_le(1); // multipleRectangleSupport
    d.put_u16_le(0); // pad2octetsB
    capability_set(CAPSTYPE_BITMAP, &d)
}

/// TS_POINTER_CAPABILITYSET (2.2.7.1.5).
pub fn pointer_caps() -> Vec<u8> {
    let mut d = BytesMut::new();
    d.put_u16_le(1); // colorPointerFlag
    d.put_u16_le(25); // colorPointerCacheSize
    d.put_u16_le(25); // pointerCacheSize
    capability_set(CAPSTYPE_POINTER, &d)
}

/// TS_INPUT_CAPABILITYSET (2.2.7.1.6).
pub fn input_caps(keyboard_layout: u32) -> Vec<u8> {
    let mut d = BytesMut::new();
    // SCANCODES | MOUSEX | FASTPATH_INPUT | FASTPATH_INPUT2 | MOUSE_HWHEEL | QOE_TIMESTAMPS (0x032d, matches mstsc/FreeRDP)
    d.put_u16_le(0x032d);
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
    // Exact body a normal client (FreeRDP/mstsc) sends: orderFlags 0x00AA, the
    // standard primary-order support array (DSTBLT/PATBLT/SCRBLT/MEMBLT/… enabled),
    // textFlags, desktopSaveSize, and textANSICodePage.
    let body: [u8; 84] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // terminalDescriptor
        0, 0, 0, 0, // pad4octetsA
        0x01, 0x00, // desktopSaveXGranularity
        0x14, 0x00, // desktopSaveYGranularity
        0x00, 0x00, // pad2octetsA
        0x01, 0x00, // maximumOrderLevel
        0x00, 0x00, // numberFonts
        0xaa, 0x00, // orderFlags
        // orderSupport (32): indexes 0,1,2,7,16,20 enabled
        0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, // textFlags
        0x00, 0x00, // orderSupportExFlags
        0x00, 0x00, 0x00, 0x00, // pad4octetsB
        0x00, 0x84, 0x03, 0x00, // desktopSaveSize = 0x00038400 = 230400
        0x00, 0x00, // pad2octetsC
        0x00, 0x00, // pad2octetsD
        0xe9, 0xfd, // textANSICodePage
        0x00, 0x00, // pad2octetsE
    ];
    capability_set(CAPSTYPE_ORDER, &body)
}

/// TS_VIRTUALCHANNEL_CAPABILITYSET (2.2.7.1.10).
pub fn virtual_channel_caps() -> Vec<u8> {
    let mut d = BytesMut::new();
    d.put_u32_le(0); // flags: VCCAPS_NO_COMPR
    d.put_u32_le(1600); // VCChunkSize (CHANNEL_CHUNK_LENGTH)
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
