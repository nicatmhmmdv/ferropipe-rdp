//! Bitmap updates ([MS-RDPBCGR] 2.2.9.1.1.3.1.2 / fast-path variant): a set of
//! rectangles the server sends to repaint parts of the desktop. Each rectangle
//! carries raw or interleaved-RLE-compressed pixel data in 15/16/24/32 bpp.
//!
//! RDP bitmap scanlines are stored **bottom-up** (the first row in the stream is
//! the bottom of the image); [`to_rgba`] flips them to the top-down RGBA the
//! framebuffer expects.

use super::framebuffer::Framebuffer;
use crate::{Error, Result};
use bytes::Buf;

const BITMAP_COMPRESSION: u16 = 0x0001;
const NO_BITMAP_COMPRESSION_HDR: u16 = 0x0400;

/// One bitmap rectangle to repaint.
#[derive(Clone, Debug)]
pub struct BitmapRect {
    pub dest_left: u16,
    pub dest_top: u16,
    pub width: u16,
    pub height: u16,
    pub bits_per_pixel: u16,
    pub compressed: bool,
    pub data: Vec<u8>,
}

/// Parse a (fast-path) bitmap update body: numberRectangles + TS_BITMAP_DATA[].
pub fn parse_bitmap_update(mut buf: &[u8]) -> Result<Vec<BitmapRect>> {
    if buf.len() < 2 {
        return Err(Error::Short { need: 2, have: buf.len() });
    }
    let count = buf.get_u16_le() as usize;
    let mut rects = Vec::with_capacity(count);
    for _ in 0..count {
        if buf.len() < 18 {
            return Err(Error::Short { need: 18, have: buf.len() });
        }
        let dest_left = buf.get_u16_le();
        let dest_top = buf.get_u16_le();
        let _dest_right = buf.get_u16_le();
        let _dest_bottom = buf.get_u16_le();
        let width = buf.get_u16_le();
        let height = buf.get_u16_le();
        let bits_per_pixel = buf.get_u16_le();
        let flags = buf.get_u16_le();
        let bitmap_length = buf.get_u16_le() as usize;

        let compressed = flags & BITMAP_COMPRESSION != 0;
        let mut data_len = bitmap_length;
        if compressed && flags & NO_BITMAP_COMPRESSION_HDR == 0 {
            // TS_CD_HEADER (8 bytes): skip cbCompFirstRowSize + take cbCompMainBodySize.
            if buf.len() < 8 {
                return Err(Error::Short { need: 8, have: buf.len() });
            }
            let _first_row = buf.get_u16_le();
            let main_body = buf.get_u16_le() as usize;
            let _scan_width = buf.get_u16_le();
            let _uncompressed = buf.get_u16_le();
            data_len = main_body;
        }
        if buf.len() < data_len {
            return Err(Error::Short { need: data_len, have: buf.len() });
        }
        let data = buf[..data_len].to_vec();
        buf.advance(data_len);
        rects.push(BitmapRect { dest_left, dest_top, width, height, bits_per_pixel, compressed, data });
    }
    Ok(rects)
}

/// Convert bottom-up pixel bytes of the given bpp into top-down RGBA.
pub fn to_rgba(pixels: &[u8], width: usize, height: usize, bpp: u16) -> Result<Vec<u8>> {
    let bytes_per_pixel = match bpp {
        15 | 16 => 2,
        24 => 3,
        32 => 4,
        _ => return Err(Error::Protocol("unsupported bitmap bpp")),
    };
    let stride = width * bytes_per_pixel;
    if pixels.len() < stride * height {
        return Err(Error::Short { need: stride * height, have: pixels.len() });
    }
    let mut out = vec![0u8; width * height * 4];
    for row in 0..height {
        let src_row = height - 1 - row; // flip: source is bottom-up
        let src = &pixels[src_row * stride..src_row * stride + stride];
        for col in 0..width {
            // scale an n-bit channel value to 8 bits (arithmetic in u16 to avoid overflow)
            let scale = |v: u16, max: u16| ((v * 255 + max / 2) / max) as u8;
            let (r, g, b) = match bpp {
                16 => {
                    let p = u16::from_le_bytes([src[col * 2], src[col * 2 + 1]]);
                    (scale((p >> 11) & 0x1f, 31), scale((p >> 5) & 0x3f, 63), scale(p & 0x1f, 31))
                }
                15 => {
                    let p = u16::from_le_bytes([src[col * 2], src[col * 2 + 1]]);
                    (scale((p >> 10) & 0x1f, 31), scale((p >> 5) & 0x1f, 31), scale(p & 0x1f, 31))
                }
                24 => (src[col * 3 + 2], src[col * 3 + 1], src[col * 3]), // stored BGR
                32 => (src[col * 4 + 2], src[col * 4 + 1], src[col * 4]), // BGRX
                _ => unreachable!(),
            };
            let o = (row * width + col) * 4;
            out[o] = r;
            out[o + 1] = g;
            out[o + 2] = b;
            out[o + 3] = 255;
        }
    }
    Ok(out)
}

/// Decode one bitmap rectangle and blit it into the framebuffer.
pub fn apply(fb: &mut Framebuffer, rect: &BitmapRect) -> Result<()> {
    let pixels = if rect.compressed {
        super::rle::decompress(&rect.data, rect.width as usize, rect.height as usize, rect.bits_per_pixel)?
    } else {
        rect.data.clone()
    };
    let rgba = to_rgba(&pixels, rect.width as usize, rect.height as usize, rect.bits_per_pixel)?;
    fb.blit_rgba(rect.dest_left as usize, rect.dest_top as usize, rect.width as usize, rect.height as usize, &rgba);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    fn make_rect_bytes(w: u16, h: u16, bpp: u16, pixels: &[u8]) -> Vec<u8> {
        let mut b = BytesMut::new();
        b.put_u16_le(1); // numberRectangles
        b.put_u16_le(0); // destLeft
        b.put_u16_le(0); // destTop
        b.put_u16_le(w - 1); // destRight
        b.put_u16_le(h - 1); // destBottom
        b.put_u16_le(w);
        b.put_u16_le(h);
        b.put_u16_le(bpp);
        b.put_u16_le(0); // flags (uncompressed)
        b.put_u16_le(pixels.len() as u16);
        b.extend_from_slice(pixels);
        b.to_vec()
    }

    #[test]
    fn parses_uncompressed_rect() {
        // 2x1 16bpp: two pixels
        let pixels = [0x00, 0xF8, 0x1F, 0x00]; // red (RGB565 0xF800), blue (0x001F)
        let bytes = make_rect_bytes(2, 1, 16, &pixels);
        let rects = parse_bitmap_update(&bytes).unwrap();
        assert_eq!(rects.len(), 1);
        assert_eq!(rects[0].width, 2);
        assert!(!rects[0].compressed);
    }

    #[test]
    fn rgb565_converts_to_rgba() {
        // one red pixel (0xF800) as a 1x1 image
        let pixels = [0x00, 0xF8];
        let rgba = to_rgba(&pixels, 1, 1, 16).unwrap();
        assert_eq!(&rgba[..4], &[255, 0, 0, 255]);
    }

    #[test]
    fn bgr24_converts_and_flips_rows() {
        // 1x2 image, bottom-up: row0(bottom)=green, row1(top)=red. Stored BGR.
        let pixels = [0x00, 0xFF, 0x00, /* green */ 0x00, 0x00, 0xFF /* red */];
        let rgba = to_rgba(&pixels, 1, 2, 24).unwrap();
        // top-down output: first row should be red (the top), second green.
        assert_eq!(&rgba[..4], &[255, 0, 0, 255]);
        assert_eq!(&rgba[4..8], &[0, 255, 0, 255]);
    }

    #[test]
    fn apply_compressed_rle_rect() {
        // 4x1 16bpp rect, RLE COLOR_RUN of red (0xF800). flags = BITMAP_COMPRESSION
        // | NO_BITMAP_COMPRESSION_HDR so there's no TS_CD_HEADER to skip.
        let rle = [0x64u8, 0x00, 0xF8]; // COLOR_RUN len 4, red
        let mut b = BytesMut::new();
        b.put_u16_le(1); // numberRectangles
        b.put_u16_le(0);
        b.put_u16_le(0);
        b.put_u16_le(3);
        b.put_u16_le(0);
        b.put_u16_le(4); // width
        b.put_u16_le(1); // height
        b.put_u16_le(16);
        b.put_u16_le(0x0001 | 0x0400); // BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR
        b.put_u16_le(rle.len() as u16);
        b.extend_from_slice(&rle);

        let rects = parse_bitmap_update(&b).unwrap();
        assert!(rects[0].compressed);
        let mut fb = Framebuffer::new(4, 1);
        apply(&mut fb, &rects[0]).unwrap();
        for x in 0..4 {
            assert_eq!(fb.pixel(x, 0), (255, 0, 0, 255));
        }
    }

    #[test]
    fn apply_uncompressed_paints_framebuffer() {
        let mut fb = Framebuffer::new(4, 4);
        let pixels = [0x00, 0xF8]; // red 16bpp
        let bytes = make_rect_bytes(1, 1, 16, &pixels);
        let rect = &parse_bitmap_update(&bytes).unwrap()[0];
        apply(&mut fb, rect).unwrap();
        assert_eq!(fb.pixel(0, 0), (255, 0, 0, 255));
    }
}
