//! Graphics Pipeline Extension ([MS-RDPEGFX]): the RDPGFX_HEADER + command PDUs
//! that ride the "Microsoft::Windows::RDS::Graphics" dynamic virtual channel and
//! paint onto server-side *surfaces* which are then mapped to the output.
//!
//! This module implements the protocol framing, the client-side CAPSADVERTISE /
//! FRAMEACKNOWLEDGE, a surface store, and UNCOMPRESSED wire-to-surface decode.
//! The PLANAR codec and the H.264 (AVC420/AVC444) codecs are separate decoders
//! layered on top; codecs this module can't decode are surfaced as a clear error.

use crate::graphics::Framebuffer;
use crate::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};
use std::collections::HashMap;

// RDPGFX_CMDID_* ([MS-RDPEGFX] 2.2.1.5).
pub const CMDID_WIRETOSURFACE_1: u16 = 0x0001;
pub const CMDID_WIRETOSURFACE_2: u16 = 0x0002;
pub const CMDID_SOLIDFILL: u16 = 0x0004;
pub const CMDID_CREATESURFACE: u16 = 0x0009;
pub const CMDID_DELETESURFACE: u16 = 0x000A;
pub const CMDID_STARTFRAME: u16 = 0x000B;
pub const CMDID_ENDFRAME: u16 = 0x000C;
pub const CMDID_FRAMEACKNOWLEDGE: u16 = 0x000D;
pub const CMDID_RESETGRAPHICS: u16 = 0x000E;
pub const CMDID_MAPSURFACETOOUTPUT: u16 = 0x000F;
pub const CMDID_CAPSADVERTISE: u16 = 0x0012;
pub const CMDID_CAPSCONFIRM: u16 = 0x0013;

// RDPGFX_CODECID_* ([MS-RDPEGFX] 2.2.2.1).
pub const CODECID_UNCOMPRESSED: u16 = 0x0000;
pub const CODECID_CAVIDEO_RFX: u16 = 0x0003;
pub const CODECID_PLANAR: u16 = 0x000A;
pub const CODECID_AVC420: u16 = 0x000B;
pub const CODECID_ALPHA: u16 = 0x000C;
pub const CODECID_AVC444: u16 = 0x000E;

const HEADER_LEN: usize = 8;

/// RDPGFX_HEADER: cmdId, flags(=0), pduLength (includes the 8-byte header).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GfxHeader {
    pub cmd_id: u16,
    pub pdu_length: u32,
}

/// A 16-bit rectangle (right/bottom exclusive).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect16 {
    pub left: u16,
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
}

impl Rect16 {
    pub fn width(&self) -> u16 {
        self.right.saturating_sub(self.left)
    }
    pub fn height(&self) -> u16 {
        self.bottom.saturating_sub(self.top)
    }
}

/// A parsed server→client EGFX command (the ones the client acts on).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GfxCommand {
    CreateSurface { surface_id: u16, width: u16, height: u16, pixel_format: u8 },
    DeleteSurface { surface_id: u16 },
    MapSurfaceToOutput { surface_id: u16, x: u32, y: u32 },
    StartFrame { frame_id: u32 },
    EndFrame { frame_id: u32 },
    ResetGraphics { width: u32, height: u32 },
    WireToSurface1 { surface_id: u16, codec_id: u16, pixel_format: u8, dest: Rect16, data: Vec<u8> },
    CapsConfirm { version: u32 },
    Other { cmd_id: u16 },
}

/// Parse one RDPGFX PDU (after ZGFX decompression), returning (command, bytes consumed).
pub fn parse_command(buf: &[u8]) -> Result<(GfxCommand, usize)> {
    if buf.len() < HEADER_LEN {
        return Err(Error::Short { need: HEADER_LEN, have: buf.len() });
    }
    let mut h = buf;
    let cmd_id = h.get_u16_le();
    let _flags = h.get_u16_le();
    let pdu_length = h.get_u32_le() as usize;
    if pdu_length < HEADER_LEN || buf.len() < pdu_length {
        return Err(Error::Protocol("bad RDPGFX pduLength"));
    }
    let mut body = &buf[HEADER_LEN..pdu_length];

    let cmd = match cmd_id {
        CMDID_CREATESURFACE => {
            need(body, 7)?;
            let surface_id = body.get_u16_le();
            let width = body.get_u16_le();
            let height = body.get_u16_le();
            let pixel_format = body.get_u8();
            GfxCommand::CreateSurface { surface_id, width, height, pixel_format }
        }
        CMDID_DELETESURFACE => {
            need(body, 2)?;
            GfxCommand::DeleteSurface { surface_id: body.get_u16_le() }
        }
        CMDID_MAPSURFACETOOUTPUT => {
            need(body, 12)?;
            let surface_id = body.get_u16_le();
            let _reserved = body.get_u16_le();
            let x = body.get_u32_le();
            let y = body.get_u32_le();
            GfxCommand::MapSurfaceToOutput { surface_id, x, y }
        }
        CMDID_STARTFRAME => {
            need(body, 8)?;
            let _timestamp = body.get_u32_le();
            GfxCommand::StartFrame { frame_id: body.get_u32_le() }
        }
        CMDID_ENDFRAME => {
            need(body, 4)?;
            GfxCommand::EndFrame { frame_id: body.get_u32_le() }
        }
        CMDID_RESETGRAPHICS => {
            need(body, 8)?;
            let width = body.get_u32_le();
            let height = body.get_u32_le();
            GfxCommand::ResetGraphics { width, height }
        }
        CMDID_WIRETOSURFACE_1 => {
            need(body, 17)?;
            let surface_id = body.get_u16_le();
            let codec_id = body.get_u16_le();
            let pixel_format = body.get_u8();
            let dest = Rect16 {
                left: body.get_u16_le(),
                top: body.get_u16_le(),
                right: body.get_u16_le(),
                bottom: body.get_u16_le(),
            };
            let data_len = body.get_u32_le() as usize;
            need(body, data_len)?;
            GfxCommand::WireToSurface1 { surface_id, codec_id, pixel_format, dest, data: body[..data_len].to_vec() }
        }
        CMDID_CAPSCONFIRM => {
            need(body, 4)?;
            GfxCommand::CapsConfirm { version: body.get_u32_le() }
        }
        other => GfxCommand::Other { cmd_id: other },
    };
    Ok((cmd, pdu_length))
}

/// Parse all commands in a decompressed EGFX message stream.
pub fn parse_all(mut buf: &[u8]) -> Result<Vec<GfxCommand>> {
    let mut cmds = Vec::new();
    while !buf.is_empty() {
        let (cmd, consumed) = parse_command(buf)?;
        cmds.push(cmd);
        buf = &buf[consumed..];
    }
    Ok(cmds)
}

fn need(buf: &[u8], n: usize) -> Result<()> {
    if buf.len() < n {
        Err(Error::Short { need: n, have: buf.len() })
    } else {
        Ok(())
    }
}

fn frame_header(cmd_id: u16, body: &[u8]) -> Vec<u8> {
    let mut out = BytesMut::with_capacity(HEADER_LEN + body.len());
    out.put_u16_le(cmd_id);
    out.put_u16_le(0); // flags
    out.put_u32_le((HEADER_LEN + body.len()) as u32);
    out.extend_from_slice(body);
    out.to_vec()
}

/// Build a CAPSADVERTISE advertising the given capability-set versions (no data).
pub fn caps_advertise(versions: &[u32]) -> Vec<u8> {
    let mut body = BytesMut::new();
    body.put_u16_le(versions.len() as u16); // capsSetCount
    for &v in versions {
        body.put_u32_le(v); // version
        body.put_u32_le(0); // capsDataLength
    }
    frame_header(CMDID_CAPSADVERTISE, &body)
}

/// Build a FRAMEACKNOWLEDGE for `frame_id`.
pub fn frame_acknowledge(frame_id: u32, total_frames_decoded: u32) -> Vec<u8> {
    let mut body = BytesMut::new();
    body.put_u32_le(0); // queueDepth (SUSPEND_FRAME_ACKNOWLEDGE = 0xFFFFFFFF; 0 = normal)
    body.put_u32_le(frame_id);
    body.put_u32_le(total_frames_decoded);
    frame_header(CMDID_FRAMEACKNOWLEDGE, &body)
}

/// The client-side surface store: server surfaces plus their mapping to output.
#[derive(Default)]
pub struct SurfaceStore {
    surfaces: HashMap<u16, Framebuffer>,
    /// surface_id → (output x, output y)
    mapped: HashMap<u16, (u32, u32)>,
}

impl SurfaceStore {
    pub fn new() -> SurfaceStore {
        SurfaceStore::default()
    }

    /// Apply a parsed command, compositing pixels into surfaces. Returns the
    /// surface id that changed, if the caller should re-present.
    pub fn apply(&mut self, cmd: &GfxCommand) -> Result<Option<u16>> {
        match cmd {
            GfxCommand::CreateSurface { surface_id, width, height, .. } => {
                self.surfaces.insert(*surface_id, Framebuffer::new(*width as usize, *height as usize));
                Ok(None)
            }
            GfxCommand::DeleteSurface { surface_id } => {
                self.surfaces.remove(surface_id);
                self.mapped.remove(surface_id);
                Ok(None)
            }
            GfxCommand::MapSurfaceToOutput { surface_id, x, y } => {
                self.mapped.insert(*surface_id, (*x, *y));
                Ok(None)
            }
            GfxCommand::WireToSurface1 { surface_id, codec_id, dest, data, .. } => {
                let fb = self.surfaces.get_mut(surface_id).ok_or(Error::Protocol("unknown surface"))?;
                let rgba = decode_surface_bits(*codec_id, dest, data)?;
                fb.blit_rgba(dest.left as usize, dest.top as usize, dest.width() as usize, dest.height() as usize, &rgba);
                Ok(Some(*surface_id))
            }
            _ => Ok(None),
        }
    }

    pub fn surface(&self, id: u16) -> Option<&Framebuffer> {
        self.surfaces.get(&id)
    }
    pub fn mapping(&self, id: u16) -> Option<(u32, u32)> {
        self.mapped.get(&id).copied()
    }
}

/// Decode a wire-to-surface bitmap into RGBA. Only UNCOMPRESSED is handled here;
/// PLANAR and the H.264 codecs plug in as separate decoders.
fn decode_surface_bits(codec_id: u16, dest: &Rect16, data: &[u8]) -> Result<Vec<u8>> {
    let w = dest.width() as usize;
    let h = dest.height() as usize;
    match codec_id {
        CODECID_UNCOMPRESSED => {
            // 32bpp XRGB/ARGB, top-down, left→right.
            if data.len() < w * h * 4 {
                return Err(Error::Short { need: w * h * 4, have: data.len() });
            }
            let mut rgba = vec![0u8; w * h * 4];
            for i in 0..w * h {
                // stored little-endian BGRA/BGRX
                rgba[i * 4] = data[i * 4 + 2];
                rgba[i * 4 + 1] = data[i * 4 + 1];
                rgba[i * 4 + 2] = data[i * 4];
                rgba[i * 4 + 3] = 255;
            }
            Ok(rgba)
        }
        CODECID_PLANAR => Err(Error::Protocol("EGFX PLANAR codec decoder not yet wired")),
        CODECID_AVC420 | CODECID_AVC444 => Err(Error::Protocol("EGFX H.264 codec requires an external decoder")),
        _ => Err(Error::Protocol("unsupported EGFX codec")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pdu(cmd_id: u16, body: &[u8]) -> Vec<u8> {
        frame_header(cmd_id, body)
    }

    #[test]
    fn parse_create_and_map_surface() {
        let mut body = BytesMut::new();
        body.put_u16_le(7); // surfaceId
        body.put_u16_le(640);
        body.put_u16_le(480);
        body.put_u8(0x20);
        let p = pdu(CMDID_CREATESURFACE, &body);
        let (cmd, n) = parse_command(&p).unwrap();
        assert_eq!(n, p.len());
        assert_eq!(cmd, GfxCommand::CreateSurface { surface_id: 7, width: 640, height: 480, pixel_format: 0x20 });
    }

    #[test]
    fn caps_advertise_and_frame_ack_are_well_formed() {
        let ca = caps_advertise(&[0x0008_0004]);
        let (cmd, _) = parse_command(&ca).unwrap();
        assert!(matches!(cmd, GfxCommand::Other { cmd_id } if cmd_id == CMDID_CAPSADVERTISE));

        let fa = frame_acknowledge(42, 42);
        assert_eq!(u16::from_le_bytes([fa[0], fa[1]]), CMDID_FRAMEACKNOWLEDGE);
        assert_eq!(u32::from_le_bytes([fa[12], fa[13], fa[14], fa[15]]), 42); // frameId
    }

    #[test]
    fn uncompressed_wire_to_surface_paints() {
        let mut store = SurfaceStore::new();
        // create a 2x1 surface
        let mut cb = BytesMut::new();
        cb.put_u16_le(1);
        cb.put_u16_le(2);
        cb.put_u16_le(1);
        cb.put_u8(0x20);
        store.apply(&parse_command(&pdu(CMDID_CREATESURFACE, &cb)).unwrap().0).unwrap();

        // wire-to-surface: 2 pixels, red then green (BGRA)
        let mut wb = BytesMut::new();
        wb.put_u16_le(1); // surfaceId
        wb.put_u16_le(CODECID_UNCOMPRESSED);
        wb.put_u8(0x20); // pixelFormat
        wb.put_u16_le(0); // left
        wb.put_u16_le(0); // top
        wb.put_u16_le(2); // right
        wb.put_u16_le(1); // bottom
        let pixels = [0x00, 0x00, 0xFF, 0xFF, /* red */ 0x00, 0xFF, 0x00, 0xFF /* green */];
        wb.put_u32_le(pixels.len() as u32);
        wb.extend_from_slice(&pixels);
        let (cmd, _) = parse_command(&pdu(CMDID_WIRETOSURFACE_1, &wb)).unwrap();
        let changed = store.apply(&cmd).unwrap();
        assert_eq!(changed, Some(1));
        assert_eq!(store.surface(1).unwrap().pixel(0, 0), (255, 0, 0, 255));
        assert_eq!(store.surface(1).unwrap().pixel(1, 0), (0, 255, 0, 255));
    }

    #[test]
    fn h264_codec_reports_boundary() {
        let dest = Rect16 { left: 0, top: 0, right: 4, bottom: 4 };
        assert!(matches!(decode_surface_bits(CODECID_AVC444, &dest, &[0u8; 64]), Err(Error::Protocol(_))));
    }
}
