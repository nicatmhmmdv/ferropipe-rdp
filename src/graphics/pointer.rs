//! Pointer (cursor) updates ([MS-RDPBCGR] 2.2.9.1.1.4). The server sends the
//! mouse cursor shape as a color (XOR) bitmap plus a 1-bpp AND transparency mask;
//! this decodes it into a top-down RGBA image the UI can draw.

use crate::{Error, Result};
use bytes::Buf;

/// A decoded cursor: RGBA image plus the hot-spot (click point).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub width: usize,
    pub height: usize,
    pub hotspot_x: u16,
    pub hotspot_y: u16,
    pub rgba: Vec<u8>,
}

/// Round `n` up to a multiple of `align`.
fn pad(n: usize, align: usize) -> usize {
    n.div_ceil(align) * align
}

/// Decode a TS_COLORPOINTERATTRIBUTE (24-bpp XOR mask + 1-bpp AND mask).
pub fn decode_color_pointer(mut buf: &[u8]) -> Result<Cursor> {
    if buf.len() < 14 {
        return Err(Error::Short { need: 14, have: buf.len() });
    }
    let _cache_index = buf.get_u16_le();
    let hotspot_x = buf.get_u16_le();
    let hotspot_y = buf.get_u16_le();
    let width = buf.get_u16_le() as usize;
    let height = buf.get_u16_le() as usize;
    let len_and = buf.get_u16_le() as usize;
    let len_xor = buf.get_u16_le() as usize;
    if buf.len() < len_xor + len_and {
        return Err(Error::Short { need: len_xor + len_and, have: buf.len() });
    }
    let xor_mask = &buf[..len_xor];
    let and_mask = &buf[len_xor..len_xor + len_and];

    decode_masks(width, height, hotspot_x, hotspot_y, xor_mask, and_mask, 24)
}

/// Decode a TS_POINTERATTRIBUTE ("New Pointer") — an xorBpp prefix + color pointer.
pub fn decode_new_pointer(mut buf: &[u8]) -> Result<Cursor> {
    if buf.len() < 2 {
        return Err(Error::Short { need: 2, have: buf.len() });
    }
    let xor_bpp = buf.get_u16_le();
    let mut c = decode_color_pointer(buf)?;
    // For 24bpp the color pointer path already produced correct RGBA; other bpps
    // reuse the same mask geometry with a different pixel stride.
    if xor_bpp != 24 {
        // Re-decode with the actual bpp.
        let mut b2 = buf;
        let _cache = b2.get_u16_le();
        let hotspot_x = b2.get_u16_le();
        let hotspot_y = b2.get_u16_le();
        let width = b2.get_u16_le() as usize;
        let height = b2.get_u16_le() as usize;
        let len_and = b2.get_u16_le() as usize;
        let len_xor = b2.get_u16_le() as usize;
        if b2.len() < len_xor + len_and {
            return Err(Error::Short { need: len_xor + len_and, have: b2.len() });
        }
        c = decode_masks(width, height, hotspot_x, hotspot_y, &b2[..len_xor], &b2[len_xor..len_xor + len_and], xor_bpp)?;
    }
    Ok(c)
}

fn decode_masks(
    width: usize,
    height: usize,
    hotspot_x: u16,
    hotspot_y: u16,
    xor_mask: &[u8],
    and_mask: &[u8],
    xor_bpp: u16,
) -> Result<Cursor> {
    let bytes_pp = match xor_bpp {
        24 => 3,
        32 => 4,
        16 | 15 => 2,
        _ => return Err(Error::Protocol("unsupported cursor bpp")),
    };
    let xor_stride = pad(width * bytes_pp, 2);
    let and_stride = pad(width.div_ceil(8), 2);
    let mut rgba = vec![0u8; width * height * 4];

    for y in 0..height {
        let src_row = height - 1 - y; // masks are bottom-up
        for x in 0..width {
            let xo = src_row * xor_stride + x * bytes_pp;
            let (r, g, b) = match xor_bpp {
                24 | 32 => (
                    *xor_mask.get(xo + 2).unwrap_or(&0),
                    *xor_mask.get(xo + 1).unwrap_or(&0),
                    *xor_mask.get(xo).unwrap_or(&0),
                ),
                _ => {
                    let p = u16::from_le_bytes([*xor_mask.get(xo).unwrap_or(&0), *xor_mask.get(xo + 1).unwrap_or(&0)]);
                    ((((p >> 11) & 0x1f) * 255 / 31) as u8, (((p >> 5) & 0x3f) * 255 / 63) as u8, ((p & 0x1f) * 255 / 31) as u8)
                }
            };
            let and_byte = *and_mask.get(src_row * and_stride + x / 8).unwrap_or(&0xff);
            let and_bit = (and_byte >> (7 - (x % 8))) & 1;
            let alpha = if and_bit == 1 { 0 } else { 255 };
            let o = (y * width + x) * 4;
            rgba[o] = r;
            rgba[o + 1] = g;
            rgba[o + 2] = b;
            rgba[o + 3] = alpha;
        }
    }
    Ok(Cursor { width, height, hotspot_x, hotspot_y, rgba })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn decodes_a_2x2_color_pointer() {
        // 2x2 cursor. XOR 24bpp bottom-up: bottom row two red, top row two green.
        // Row stride = pad(2*3, 2) = 6 bytes.
        let mut xor = Vec::new();
        xor.extend_from_slice(&[0x00, 0x00, 0xFF, 0x00, 0x00, 0xFF]); // bottom row (red, BGR)
        xor.extend_from_slice(&[0x00, 0xFF, 0x00, 0x00, 0xFF, 0x00]); // top row (green)
        // AND mask 1bpp: 2 bits/row, stride pad((2+7)/8=1, 2) = 2. All opaque (0).
        let and = vec![0x00, 0x00, 0x00, 0x00];

        let mut b = BytesMut::new();
        b.put_u16_le(0); // cacheIndex
        b.put_u16_le(1); // hotspot x
        b.put_u16_le(1); // hotspot y
        b.put_u16_le(2); // width
        b.put_u16_le(2); // height
        b.put_u16_le(and.len() as u16);
        b.put_u16_le(xor.len() as u16);
        b.extend_from_slice(&xor);
        b.extend_from_slice(&and);

        let cur = decode_color_pointer(&b).unwrap();
        assert_eq!((cur.width, cur.height), (2, 2));
        assert_eq!(cur.hotspot_x, 1);
        // top-left pixel (top row) = green, opaque
        assert_eq!(&cur.rgba[..4], &[0, 255, 0, 255]);
        // bottom-left pixel = red (row 1, col 0)
        let bl = 2 * 4;
        assert_eq!(&cur.rgba[bl..bl + 4], &[255, 0, 0, 255]);
    }

    #[test]
    fn and_mask_makes_pixels_transparent() {
        // 8x1 cursor, all AND bits set → fully transparent.
        let xor = vec![0u8; pad(8 * 3, 2)];
        let and = vec![0xFF, 0x00]; // 8 bits set, stride 2
        let mut b = BytesMut::new();
        b.put_u16_le(0);
        b.put_u16_le(0);
        b.put_u16_le(0);
        b.put_u16_le(8);
        b.put_u16_le(1);
        b.put_u16_le(and.len() as u16);
        b.put_u16_le(xor.len() as u16);
        b.extend_from_slice(&xor);
        b.extend_from_slice(&and);
        let cur = decode_color_pointer(&b).unwrap();
        assert!(cur.rgba.chunks(4).all(|p| p[3] == 0), "all pixels transparent");
    }
}
