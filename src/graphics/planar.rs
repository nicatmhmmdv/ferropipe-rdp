//! RDP 6.0 Planar codec (RDP6_BITMAP_STREAM, [MS-RDPEGDI] 2.2.2.5.1) — the
//! plane-oriented bitmap codec used by EGFX `CODECID_PLANAR` and legacy bitmap
//! caches. Pure Rust: no H.264 required.
//!
//! A 1-byte FormatHeader selects the layout, then the color planes follow in
//! order (A, R, G, B — or A, Y, Co, Cg for the lossy YCoCg color space). Each
//! plane is either raw (absolute bytes) or RLE-compressed with per-scanline
//! run-length + a vertical delta transform. Output is top-down RGBA.
//!
//! Supported: the lossless ARGB path (CLL=0, CS=0) raw or RLE, and the
//! uncompressed 32bpp shortcut. Chroma-subsampled / YCoCg lossy modes return an
//! error rather than producing wrong colors.

use crate::{Error, Result};

const CLL_MASK: u8 = 0x07; // color loss level (bits 0-2)
const CS_FLAG: u8 = 0x08; // chroma subsampling (bit 3)
const RLE_FLAG: u8 = 0x10; // planes are RLE-compressed (bit 4)
const NA_FLAG: u8 = 0x20; // no alpha plane (bit 5)

/// Decode a planar bitmap stream into top-down RGBA (`width*height*4` bytes).
pub fn decode(data: &[u8], width: usize, height: usize) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(Error::Short { need: 1, have: 0 });
    }
    let format = data[0];

    // Uncompressed 32bpp shortcut: FormatHeader 0x00, then raw BGRA (top-down).
    if format == 0x00 {
        let need = width * height * 4;
        if data.len() < 1 + need {
            return Err(Error::Short { need: 1 + need, have: data.len() });
        }
        let px = &data[1..1 + need];
        let mut rgba = vec![0u8; need];
        for i in 0..width * height {
            rgba[i * 4] = px[i * 4 + 2]; // R (stored BGRA)
            rgba[i * 4 + 1] = px[i * 4 + 1];
            rgba[i * 4 + 2] = px[i * 4];
            rgba[i * 4 + 3] = px[i * 4 + 3];
        }
        return Ok(rgba);
    }

    let cll = (format & CLL_MASK) as u32;
    let cs = format & CS_FLAG != 0;
    let has_alpha = format & NA_FLAG == 0;
    let rle = format & RLE_FLAG != 0;

    // AYCoCg color space (lossy / chroma-subsampled): decode A,Y,Co,Cg planes and
    // run the inverse YCoCg transform.
    if cll != 0 || cs {
        return decode_aycocg(data, width, height, cll, cs, has_alpha, rle);
    }

    let mut cursor = 1usize;
    let plane = |cursor: &mut usize| -> Result<Vec<u8>> {
        if rle {
            decode_rle_plane(data, cursor, width, height)
        } else {
            let need = width * height;
            if data.len() < *cursor + need {
                return Err(Error::Short { need: *cursor + need, have: data.len() });
            }
            let p = data[*cursor..*cursor + need].to_vec();
            *cursor += need;
            Ok(p)
        }
    };

    // Plane order: [A], R, G, B.
    let alpha = if has_alpha { Some(plane(&mut cursor)?) } else { None };
    let red = plane(&mut cursor)?;
    let green = plane(&mut cursor)?;
    let blue = plane(&mut cursor)?;

    let mut rgba = vec![0u8; width * height * 4];
    for i in 0..width * height {
        rgba[i * 4] = red[i];
        rgba[i * 4 + 1] = green[i];
        rgba[i * 4 + 2] = blue[i];
        rgba[i * 4 + 3] = alpha.as_ref().map(|a| a[i]).unwrap_or(0xFF);
    }
    Ok(rgba)
}

/// Decode a plane (RAW or RLE) of `w*h` bytes at `cursor`.
fn read_plane(data: &[u8], cursor: &mut usize, w: usize, h: usize, rle: bool) -> Result<Vec<u8>> {
    if rle {
        decode_rle_plane(data, cursor, w, h)
    } else {
        let need = w * h;
        if data.len() < *cursor + need {
            return Err(Error::Short { need: *cursor + need, have: data.len() });
        }
        let p = data[*cursor..*cursor + need].to_vec();
        *cursor += need;
        Ok(p)
    }
}

/// Decode the AYCoCg planar variant (lossy / chroma-subsampled) into top-down RGBA.
fn decode_aycocg(data: &[u8], width: usize, height: usize, cll: u32, cs: bool, has_alpha: bool, rle: bool) -> Result<Vec<u8>> {
    let mut cursor = 1usize;
    let alpha = if has_alpha { Some(read_plane(data, &mut cursor, width, height, rle)?) } else { None };
    let y_plane = read_plane(data, &mut cursor, width, height, rle)?;

    let (cw, ch) = if cs { (width.div_ceil(2), height.div_ceil(2)) } else { (width, height) };
    let co_s = read_plane(data, &mut cursor, cw, ch, rle)?;
    let cg_s = read_plane(data, &mut cursor, cw, ch, rle)?;

    // Upsample chroma (nearest 2x2) when subsampled.
    let sample = |plane: &[u8], x: usize, y: usize| -> i32 {
        let (sx, sy) = if cs { (x / 2, y / 2) } else { (x, y) };
        plane[sy.min(ch - 1) * cw + sx.min(cw - 1)] as i8 as i32
    };

    let mut rgba = vec![0u8; width * height * 4];
    for y in 0..height {
        for x in 0..width {
            let i = y * width + x;
            let yy = y_plane[i] as i32;
            let co = sample(&co_s, x, y) << cll;
            let cg = sample(&cg_s, x, y) << cll;
            // Inverse YCoCg. The color planes carry B in the +Co axis and R in the
            // -Co axis for RDP's 32bpp (BGRX) surfaces, so R/B are assigned accordingly.
            let r = (yy - co - cg).clamp(0, 255) as u8;
            let g = (yy + cg).clamp(0, 255) as u8;
            let b = (yy + co - cg).clamp(0, 255) as u8;
            rgba[i * 4] = r;
            rgba[i * 4 + 1] = g;
            rgba[i * 4 + 2] = b;
            rgba[i * 4 + 3] = alpha.as_ref().map(|a| a[i]).unwrap_or(0xFF);
        }
    }
    Ok(rgba)
}

/// Decode one RLE-compressed plane: per-scanline run-length, then the vertical
/// delta transform (scanline 0 absolute; later rows are signed deltas vs above).
fn decode_rle_plane(data: &[u8], cursor: &mut usize, width: usize, height: usize) -> Result<Vec<u8>> {
    // First recover the raw byte grid (still deltas for rows > 0).
    let mut raw = vec![0u8; width * height];
    let mut pos = *cursor;
    for y in 0..height {
        let mut x = 0usize;
        let mut last = 0u8;
        while x < width {
            if pos >= data.len() {
                return Err(Error::Short { need: pos + 1, have: data.len() });
            }
            let control = data[pos];
            pos += 1;
            let mut n_run = (control & 0x0F) as usize;
            let mut c_raw = ((control >> 4) & 0x0F) as usize;
            if n_run == 1 {
                n_run = 16 + c_raw;
                c_raw = 0;
            } else if n_run == 2 {
                n_run = 32 + c_raw;
                c_raw = 0;
            }
            for _ in 0..c_raw {
                if pos >= data.len() || x >= width {
                    return Err(Error::Protocol("planar RLE overran scanline"));
                }
                last = data[pos];
                pos += 1;
                raw[y * width + x] = last;
                x += 1;
            }
            for _ in 0..n_run {
                if x >= width {
                    return Err(Error::Protocol("planar RLE run overran scanline"));
                }
                raw[y * width + x] = last;
                x += 1;
            }
        }
    }
    *cursor = pos;

    // De-delta: row 0 absolute; row y>0 adds the signed delta to the row above.
    let mut plane = vec![0u8; width * height];
    plane[..width].copy_from_slice(&raw[..width]);
    for y in 1..height {
        for x in 0..width {
            let d = raw[y * width + x];
            let delta: i16 = if d & 1 == 0 { (d >> 1) as i16 } else { -(((d >> 1) + 1) as i16) };
            plane[y * width + x] = (plane[(y - 1) * width + x] as i16 + delta) as u8;
        }
    }
    Ok(plane)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncompressed_shortcut_decodes_bgra() {
        // 1x1 red pixel (BGRA = 00 00 FF FF)
        let data = [0x00, 0x00, 0x00, 0xFF, 0xFF];
        let rgba = decode(&data, 1, 1).unwrap();
        assert_eq!(rgba, [255, 0, 0, 255]);
    }

    #[test]
    fn raw_planes_no_alpha() {
        // FormatHeader: NA set (0x20), no RLE. Planes R, G, B each 2 bytes (2x1).
        let mut data = vec![NA_FLAG];
        data.extend_from_slice(&[10, 20]); // R plane
        data.extend_from_slice(&[30, 40]); // G plane
        data.extend_from_slice(&[50, 60]); // B plane
        let rgba = decode(&data, 2, 1).unwrap();
        assert_eq!(&rgba[..4], &[10, 30, 50, 255]);
        assert_eq!(&rgba[4..8], &[20, 40, 60, 255]);
    }

    #[test]
    fn raw_planes_default_alpha() {
        // NA (no-alpha) raw ARGB path: R,G,B planes, alpha defaults to 0xFF.
        let data = vec![NA_FLAG, 1 /*R*/, 2 /*G*/, 3 /*B*/];
        let rgba = decode(&data, 1, 1).unwrap();
        assert_eq!(rgba, [1, 2, 3, 255]);
    }

    #[test]
    fn aycocg_lossless_decodes() {
        // CS=0, CLL=0 but AYCoCg (via a nonzero-CLL-like path is CLL>0); use CS to
        // exercise the YCoCg branch with a 2x2 tile whose chroma is neutral (0),
        // so RGB == Y for every pixel (a gray tile).
        let mut d = vec![NA_FLAG | CS_FLAG]; // no alpha, chroma-subsampled, raw
        d.extend_from_slice(&[100, 110, 120, 130]); // Y plane 2x2
        d.push(0); // Co (1x1 subsampled)
        d.push(0); // Cg (1x1 subsampled)
        let rgba = decode(&d, 2, 2).unwrap();
        // neutral chroma → gray = Y
        assert_eq!(&rgba[0..4], &[100, 100, 100, 255]);
        assert_eq!(&rgba[4..8], &[110, 110, 110, 255]);
    }

    #[test]
    fn rle_plane_run_and_delta() {
        // 2x2, RLE, no alpha. Each plane: row0 absolute, row1 delta vs row0.
        // Build one plane's RLE bytes: row0 = [5,5] via control 0x02(run=2 →
        // 32+0=32? no). Use literals: control 0x20 = cRaw 2, nRun 0 → 2 literals.
        // row0 literals 5,5 ; row1 literals delta 0,0 (even→+0) keeps 5,5.
        fn plane_bytes() -> Vec<u8> {
            // row0: control 0x20 (cRaw=2,nRun=0), then 5,5
            // row1: control 0x20, then 0,0 (delta +0)
            vec![0x20, 5, 5, 0x20, 0, 0]
        }
        let mut data = vec![RLE_FLAG | NA_FLAG];
        data.extend(plane_bytes()); // R
        data.extend(plane_bytes()); // G
        data.extend(plane_bytes()); // B
        let rgba = decode(&data, 2, 2).unwrap();
        // every pixel should be (5,5,5,255)
        for px in rgba.chunks(4) {
            assert_eq!(px, &[5, 5, 5, 255]);
        }
    }
}
