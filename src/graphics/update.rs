//! The display state: applies decoded fast-path updates to a framebuffer and
//! tracks the cursor. This is the top of the Phase-4 graphics stack — a
//! connection feeds it fast-path update PDUs and reads back the framebuffer to
//! present.

use super::bitmap::{apply as apply_bitmap, parse_bitmap_update};
use super::fastpath::{
    FastPathUpdate, UPDATETYPE_BITMAP, UPDATETYPE_COLOR, UPDATETYPE_POINTER, UPDATETYPE_PTR_NULL,
    UPDATETYPE_PTR_POSITION,
};
use super::pointer::{decode_color_pointer, decode_new_pointer, Cursor};
use super::Framebuffer;
use crate::Result;

/// Everything needed to present the remote desktop: the pixel buffer and cursor.
pub struct Display {
    pub framebuffer: Framebuffer,
    pub cursor: Option<Cursor>,
    pub cursor_pos: (u16, u16),
    /// Rectangles touched since the last present (for partial-redraw callers).
    pub dirty: bool,
}

impl Display {
    pub fn new(width: usize, height: usize) -> Display {
        Display { framebuffer: Framebuffer::new(width, height), cursor: None, cursor_pos: (0, 0), dirty: false }
    }

    /// Apply one fast-path update. Unknown/soft update types are ignored; a bitmap
    /// rectangle that fails to decode (e.g. an unsupported codec) is skipped so a
    /// single bad rect doesn't blank the session.
    pub fn apply(&mut self, update: &FastPathUpdate) -> Result<()> {
        match update.update_code {
            UPDATETYPE_BITMAP => {
                for rect in parse_bitmap_update(&update.data)? {
                    if apply_bitmap(&mut self.framebuffer, &rect).is_ok() {
                        self.dirty = true;
                    }
                }
            }
            UPDATETYPE_COLOR => {
                self.cursor = Some(decode_color_pointer(&update.data)?);
                self.dirty = true;
            }
            UPDATETYPE_POINTER => {
                self.cursor = Some(decode_new_pointer(&update.data)?);
                self.dirty = true;
            }
            UPDATETYPE_PTR_POSITION => {
                if update.data.len() >= 4 {
                    self.cursor_pos =
                        (u16::from_le_bytes([update.data[0], update.data[1]]), u16::from_le_bytes([update.data[2], update.data[3]]));
                    self.dirty = true;
                }
            }
            UPDATETYPE_PTR_NULL => {
                self.cursor = None;
                self.dirty = true;
            }
            _ => {} // orders / palette / synchronize / surfcmds: handled in later phases
        }
        Ok(())
    }

    /// Apply every update in a parsed fast-path output PDU.
    pub fn apply_all(&mut self, updates: &[FastPathUpdate]) -> Result<()> {
        for u in updates {
            self.apply(u)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    fn bitmap_update_bytes() -> Vec<u8> {
        // one 1x1 red 16bpp rect at (2,2)
        let mut b = BytesMut::new();
        b.put_u16_le(1); // numberRectangles
        b.put_u16_le(2); // destLeft
        b.put_u16_le(2); // destTop
        b.put_u16_le(2); // destRight
        b.put_u16_le(2); // destBottom
        b.put_u16_le(1); // width
        b.put_u16_le(1); // height
        b.put_u16_le(16); // bpp
        b.put_u16_le(0); // flags
        b.put_u16_le(2); // bitmapLength
        b.put_u16_le(0xF800); // red pixel
        b.to_vec()
    }

    #[test]
    fn bitmap_update_paints_framebuffer() {
        let mut d = Display::new(8, 8);
        let update = FastPathUpdate { update_code: UPDATETYPE_BITMAP, fragmentation: 0, data: bitmap_update_bytes() };
        d.apply(&update).unwrap();
        assert!(d.dirty);
        assert_eq!(d.framebuffer.pixel(2, 2), (255, 0, 0, 255));
    }

    #[test]
    fn ptr_position_updates_cursor_pos() {
        let mut d = Display::new(8, 8);
        let mut data = Vec::new();
        data.extend_from_slice(&10u16.to_le_bytes());
        data.extend_from_slice(&20u16.to_le_bytes());
        let update = FastPathUpdate { update_code: UPDATETYPE_PTR_POSITION, fragmentation: 0, data };
        d.apply(&update).unwrap();
        assert_eq!(d.cursor_pos, (10, 20));
    }

    #[test]
    fn ptr_null_clears_cursor() {
        let mut d = Display::new(8, 8);
        d.cursor = Some(Cursor { width: 1, height: 1, hotspot_x: 0, hotspot_y: 0, rgba: vec![0; 4] });
        let update = FastPathUpdate { update_code: UPDATETYPE_PTR_NULL, fragmentation: 0, data: vec![] };
        d.apply(&update).unwrap();
        assert!(d.cursor.is_none());
    }
}
