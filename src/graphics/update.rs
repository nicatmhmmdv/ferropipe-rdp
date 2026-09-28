//! The display state: applies decoded fast-path updates to a framebuffer and
//! tracks the cursor. This is the top of the Phase-4 graphics stack — a
//! connection feeds it fast-path update PDUs and reads back the framebuffer to
//! present.

use super::bitmap::{apply as apply_bitmap, parse_bitmap_update};
use super::fastpath::{
    FastPathUpdate, UPDATETYPE_BITMAP, UPDATETYPE_CACHED, UPDATETYPE_COLOR, UPDATETYPE_POINTER,
    UPDATETYPE_PTR_DEFAULT, UPDATETYPE_PTR_NULL, UPDATETYPE_PTR_POSITION,
};
use super::pointer::{decode_color_pointer, decode_new_pointer, Cursor};
use super::Framebuffer;
use crate::Result;

/// Pointer cache slots the client advertises (`caps::pointer_caps`:
/// colorPointerCacheSize = pointerCacheSize = 25); a cached-pointer update
/// recalls a shape by slot.
pub const POINTER_CACHE_SIZE: usize = 25;

/// Everything needed to present the remote desktop: the pixel buffer and cursor.
pub struct Display {
    pub framebuffer: Framebuffer,
    /// The current pointer shape; `None` when the pointer is hidden or the server
    /// asked for the system default arrow (the client's own cursor is right).
    pub cursor: Option<Cursor>,
    pub cursor_pos: (u16, u16),
    /// Rectangles touched since the last present (for partial-redraw callers).
    pub dirty: bool,
    /// Bumped on every change to `cursor` so a presenter can re-upload lazily.
    cursor_generation: u64,
    /// Shapes the server stored by cache index (TS_COLORPOINTERATTRIBUTE /
    /// TS_POINTERATTRIBUTE), recalled by TS_CACHEDPOINTERATTRIBUTE.
    pointer_cache: Vec<Option<Cursor>>,
    /// Reassembly buffer for fragmented updates (FIRST/NEXT/LAST) + its code.
    frag: Vec<u8>,
    frag_code: u8,
}

impl Display {
    pub fn new(width: usize, height: usize) -> Display {
        Display {
            framebuffer: Framebuffer::new(width, height),
            cursor: None,
            cursor_pos: (0, 0),
            dirty: false,
            cursor_generation: 0,
            pointer_cache: vec![None; POINTER_CACHE_SIZE],
            frag: Vec::new(),
            frag_code: 0,
        }
    }

    /// Monotonic count of pointer-shape changes (new/cached/hidden/default), so
    /// a presenter can tell when `cursor` needs re-uploading.
    pub fn cursor_generation(&self) -> u64 {
        self.cursor_generation
    }

    /// Make `cursor` the current shape and mark the display changed.
    fn set_cursor(&mut self, cursor: Option<Cursor>) {
        self.cursor = cursor;
        self.cursor_generation += 1;
        self.dirty = true;
    }

    /// Store a decoded shape in its cache slot (out-of-range slots are ignored)
    /// and make it current.
    fn store_pointer(&mut self, slot: Option<usize>, cursor: Cursor) {
        if let Some(entry) = slot.and_then(|i| self.pointer_cache.get_mut(i)) {
            *entry = Some(cursor.clone());
        }
        self.set_cursor(Some(cursor));
    }

    /// Recall a cached shape; an unfilled slot leaves the cursor as it is.
    fn recall_pointer(&mut self, data: &[u8]) {
        let Some(cursor) =
            cache_index(data, 0).and_then(|i| self.pointer_cache.get(i).cloned().flatten())
        else {
            return;
        };
        self.set_cursor(Some(cursor));
    }

    /// Apply one fast-path update, reassembling fragmented ones (a large bitmap
    /// update spans FIRST/NEXT/LAST fragments) before decoding.
    pub fn apply(&mut self, update: &FastPathUpdate) -> Result<()> {
        use crate::graphics::fastpath::{
            FRAGMENT_FIRST, FRAGMENT_LAST, FRAGMENT_NEXT, FRAGMENT_SINGLE,
        };
        match update.fragmentation {
            FRAGMENT_SINGLE => self.process(update.update_code, &update.data.clone()),
            FRAGMENT_FIRST => {
                self.frag.clear();
                self.frag_code = update.update_code;
                self.frag.extend_from_slice(&update.data);
                Ok(())
            }
            FRAGMENT_NEXT => {
                self.frag.extend_from_slice(&update.data);
                Ok(())
            }
            FRAGMENT_LAST => {
                self.frag.extend_from_slice(&update.data);
                let (code, data) = (self.frag_code, std::mem::take(&mut self.frag));
                self.process(code, &data)
            }
            _ => Ok(()),
        }
    }

    /// Decode + apply a complete (reassembled) update payload.
    fn process(&mut self, update_code: u8, data: &[u8]) -> Result<()> {
        match update_code {
            UPDATETYPE_BITMAP => {
                // A single bad/unsupported rect is skipped so it can't blank the session.
                for rect in parse_bitmap_update(data)? {
                    if apply_bitmap(&mut self.framebuffer, &rect).is_ok() {
                        self.dirty = true;
                    }
                }
            }
            // TS_COLORPOINTERATTRIBUTE starts with cacheIndex; TS_POINTERATTRIBUTE
            // prefixes it with xorBpp.
            UPDATETYPE_COLOR => {
                self.store_pointer(cache_index(data, 0), decode_color_pointer(data)?)
            }
            UPDATETYPE_POINTER => {
                self.store_pointer(cache_index(data, 2), decode_new_pointer(data)?)
            }
            UPDATETYPE_CACHED => self.recall_pointer(data),
            UPDATETYPE_PTR_POSITION => {
                if data.len() >= 4 {
                    self.cursor_pos = (
                        u16::from_le_bytes([data[0], data[1]]),
                        u16::from_le_bytes([data[2], data[3]]),
                    );
                    self.dirty = true;
                }
            }
            UPDATETYPE_PTR_NULL | UPDATETYPE_PTR_DEFAULT => self.set_cursor(None),
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

/// The little-endian u16 cache index at `offset` in a pointer update payload.
fn cache_index(data: &[u8], offset: usize) -> Option<usize> {
    let bytes = data.get(offset..offset + 2)?;
    Some(usize::from(u16::from_le_bytes([bytes[0], bytes[1]])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    fn bitmap_update_bytes() -> Vec<u8> {
        // one 1x1 red 16bpp rect at (2,2)
        let mut b = BytesMut::new();
        b.put_u16_le(1); // updateType = BITMAP
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
        let update = FastPathUpdate {
            update_code: UPDATETYPE_BITMAP,
            fragmentation: 0,
            data: bitmap_update_bytes(),
        };
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
        let update = FastPathUpdate {
            update_code: UPDATETYPE_PTR_POSITION,
            fragmentation: 0,
            data,
        };
        d.apply(&update).unwrap();
        assert_eq!(d.cursor_pos, (10, 20));
    }

    /// A TS_COLORPOINTERATTRIBUTE for a 1x1 opaque cursor stored at `cache_index`.
    fn color_pointer_bytes(cache_index: u16) -> Vec<u8> {
        let mut b = BytesMut::new();
        b.put_u16_le(cache_index);
        b.put_u16_le(0); // hotspot x
        b.put_u16_le(0); // hotspot y
        b.put_u16_le(1); // width
        b.put_u16_le(1); // height
        b.put_u16_le(2); // lengthAndMask: 1 bit padded to a 2-byte stride
        b.put_u16_le(4); // lengthXorMask: 3 bytes padded to 4
        b.extend_from_slice(&[0x00, 0x00, 0xFF, 0x00]); // XOR: one red pixel (BGR)
        b.extend_from_slice(&[0x00, 0x00]); // AND: opaque
        b.to_vec()
    }

    fn update(update_code: u8, data: Vec<u8>) -> FastPathUpdate {
        FastPathUpdate {
            update_code,
            fragmentation: 0,
            data,
        }
    }

    #[test]
    fn pointer_shape_updates_bump_the_cursor_generation() {
        // Arrange
        let mut d = Display::new(8, 8);
        assert_eq!(d.cursor_generation(), 0);
        // Act: a new shape, then the hidden pointer.
        d.apply(&update(UPDATETYPE_COLOR, color_pointer_bytes(0)))
            .unwrap();
        let after_shape = d.cursor_generation();
        d.apply(&update(UPDATETYPE_PTR_NULL, vec![])).unwrap();
        let after_null = d.cursor_generation();
        // Assert: each bumps once; the hidden pointer reads as no cursor.
        assert_eq!(after_shape, 1);
        assert_eq!(after_null, 2);
        assert!(d.cursor.is_none());
    }

    #[test]
    fn pointer_position_does_not_bump_the_cursor_generation() {
        // Arrange
        let mut d = Display::new(8, 8);
        d.apply(&update(UPDATETYPE_COLOR, color_pointer_bytes(0)))
            .unwrap();
        // Act: a server-side pointer move changes no shape.
        d.apply(&update(UPDATETYPE_PTR_POSITION, vec![1, 0, 2, 0]))
            .unwrap();
        // Assert
        assert_eq!(d.cursor_generation(), 1);
    }

    #[test]
    fn default_pointer_shows_no_custom_cursor() {
        // Arrange
        let mut d = Display::new(8, 8);
        d.apply(&update(UPDATETYPE_COLOR, color_pointer_bytes(0)))
            .unwrap();
        // Act: the server switches to the system default arrow.
        d.apply(&update(UPDATETYPE_PTR_DEFAULT, vec![])).unwrap();
        // Assert: the client's own arrow is the right thing to show.
        assert!(d.cursor.is_none());
        assert_eq!(d.cursor_generation(), 2);
    }

    #[test]
    fn cached_pointer_recalls_a_stored_shape() {
        // Arrange: shape stored at cache slot 3, then hidden.
        let mut d = Display::new(8, 8);
        d.apply(&update(UPDATETYPE_COLOR, color_pointer_bytes(3)))
            .unwrap();
        let stored = d.cursor.clone().unwrap();
        d.apply(&update(UPDATETYPE_PTR_NULL, vec![])).unwrap();
        // Act: TS_CACHEDPOINTERATTRIBUTE { cacheIndex = 3 }
        d.apply(&update(UPDATETYPE_CACHED, vec![3, 0])).unwrap();
        // Assert
        assert_eq!(d.cursor.as_ref(), Some(&stored));
        assert_eq!(d.cursor_generation(), 3);
    }

    #[test]
    fn cached_pointer_with_unknown_slot_changes_nothing() {
        // Arrange
        let mut d = Display::new(8, 8);
        d.apply(&update(UPDATETYPE_COLOR, color_pointer_bytes(0)))
            .unwrap();
        // Act: a slot the server never filled.
        d.apply(&update(UPDATETYPE_CACHED, vec![7, 0])).unwrap();
        // Assert: keep the current shape rather than blanking the cursor.
        assert!(d.cursor.is_some());
        assert_eq!(d.cursor_generation(), 1);
    }

    #[test]
    fn ptr_null_clears_cursor() {
        let mut d = Display::new(8, 8);
        d.cursor = Some(Cursor {
            width: 1,
            height: 1,
            hotspot_x: 0,
            hotspot_y: 0,
            rgba: vec![0; 4],
        });
        let update = FastPathUpdate {
            update_code: UPDATETYPE_PTR_NULL,
            fragmentation: 0,
            data: vec![],
        };
        d.apply(&update).unwrap();
        assert!(d.cursor.is_none());
    }
}
