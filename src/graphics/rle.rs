//! Interleaved RLE bitmap decompression ([MS-RDPEGDI] 2.2.2.5.1, decode per
//! [MS-RDPBCGR] 2.2.9.1.1.3.1.2.4). The classic RDP bitmap codec: a stream of
//! run/image orders that reconstruct a bottom-up bitmap, with foreground/
//! background orders XOR-ing against the previous scanline.
//!
//! Output matches the uncompressed layout ([`super::bitmap::to_rgba`] then flips
//! and converts it): `width*height` pixels of `PS` bytes each, bottom-up.

use crate::{Error, Result};

/// Pixel size in bytes for a bpp.
fn pixel_size(bpp: u16) -> Result<usize> {
    match bpp {
        8 => Ok(1),
        15 | 16 => Ok(2),
        24 => Ok(3),
        _ => Err(Error::Protocol("unsupported RLE bpp")),
    }
}

fn white_pixel(bpp: u16) -> u32 {
    match bpp {
        15 => 0x7FFF,
        16 => 0xFFFF,
        24 => 0xFF_FFFF,
        _ => 0xFF,
    }
}

// Code IDs (from ExtractCodeId), [MS-RDPBCGR] 2.2.9.1.1.3.1.2.4.
const BG_RUN: u8 = 0x0;
const FG_RUN: u8 = 0x1;
const FGBG_IMAGE: u8 = 0x2;
const COLOR_RUN: u8 = 0x3;
const COLOR_IMAGE: u8 = 0x4;
const LITE_SET_FG_FG_RUN: u8 = 0xC;
const LITE_SET_FG_FGBG_IMAGE: u8 = 0xD;
const LITE_DITHERED_RUN: u8 = 0xE;
const MEGA_BG_RUN: u8 = 0xF0;
const MEGA_FG_RUN: u8 = 0xF1;
const MEGA_FGBG_IMAGE: u8 = 0xF2;
const MEGA_COLOR_RUN: u8 = 0xF3;
const MEGA_COLOR_IMAGE: u8 = 0xF4;
const MEGA_SET_FG_RUN: u8 = 0xF6;
const MEGA_SET_FGBG_IMAGE: u8 = 0xF7;
const MEGA_DITHERED_RUN: u8 = 0xF8;
const SPECIAL_FGBG_1: u8 = 0xF9;
const SPECIAL_FGBG_2: u8 = 0xFA;
const WHITE: u8 = 0xFD;
const BLACK: u8 = 0xFE;

fn code_id(hdr: u8) -> u8 {
    if hdr & 0xC0 != 0xC0 {
        hdr >> 5
    } else if hdr & 0xF0 == 0xF0 {
        hdr
    } else {
        hdr >> 4
    }
}

/// (run length, header byte count) for an order at `src`.
fn run_length(code: u8, src: &[u8]) -> Result<(usize, usize)> {
    let b0 = src[0] as usize;
    let get1 = || src.get(1).map(|&b| b as usize).ok_or(Error::Short { need: 2, have: src.len() });
    match code {
        FGBG_IMAGE => {
            let r = b0 & 0x1F;
            if r != 0 { Ok((r * 8, 1)) } else { Ok((get1()? + 1, 2)) }
        }
        LITE_SET_FG_FGBG_IMAGE => {
            let r = b0 & 0x0F;
            if r != 0 { Ok((r * 8, 1)) } else { Ok((get1()? + 1, 2)) }
        }
        BG_RUN | FG_RUN | COLOR_RUN | COLOR_IMAGE => {
            let r = b0 & 0x1F;
            if r != 0 { Ok((r, 1)) } else { Ok((get1()? + 32, 2)) }
        }
        LITE_SET_FG_FG_RUN | LITE_DITHERED_RUN => {
            let r = b0 & 0x0F;
            if r != 0 { Ok((r, 1)) } else { Ok((get1()? + 16, 2)) }
        }
        MEGA_BG_RUN..=MEGA_DITHERED_RUN => {
            if src.len() < 3 {
                return Err(Error::Short { need: 3, have: src.len() });
            }
            Ok((src[1] as usize | ((src[2] as usize) << 8), 3))
        }
        _ => Ok((0, 1)), // special / white / black
    }
}

/// Decompress interleaved-RLE `data` into `width*height` pixels of `bpp` bits
/// (bottom-up, PS bytes/pixel), matching the uncompressed bitmap layout.
pub fn decompress(data: &[u8], width: usize, height: usize, bpp: u16) -> Result<Vec<u8>> {
    let ps = pixel_size(bpp)?;
    let white = white_pixel(bpp);
    let row_delta = width * ps;
    let mut dst = vec![0u8; row_delta * height];

    let read_px = |buf: &[u8], idx: usize| -> u32 {
        let mut v = 0u32;
        for k in 0..ps {
            v |= (buf[idx + k] as u32) << (8 * k);
        }
        v
    };
    let write_px = |buf: &mut [u8], idx: usize, val: u32| {
        for k in 0..ps {
            buf[idx + k] = (val >> (8 * k)) as u8;
        }
    };

    let mut i = 0usize; // src cursor
    let mut d = 0usize; // dst byte cursor
    let mut fg_pel = white;
    let mut insert_fg = false;
    let mut first_line = true;

    // bounds helpers
    macro_rules! need_src {
        ($n:expr) => {
            if i + $n > data.len() {
                return Err(Error::Short { need: i + $n, have: data.len() });
            }
        };
    }

    while i < data.len() {
        if first_line && d >= row_delta {
            first_line = false;
            insert_fg = false;
        }
        let code = code_id(data[i]);
        let src = &data[i..];

        match code {
            BG_RUN | MEGA_BG_RUN => {
                let (mut len, hlen) = run_length(code, src)?;
                i += hlen;
                if first_line {
                    if insert_fg && len > 0 {
                        write_px(&mut dst, d, fg_pel);
                        d += ps;
                        len -= 1;
                    }
                    for _ in 0..len {
                        write_px(&mut dst, d, 0); // BLACK
                        d += ps;
                    }
                } else {
                    if insert_fg && len > 0 {
                        let above = read_px(&dst, d - row_delta);
                        write_px(&mut dst, d, above ^ fg_pel);
                        d += ps;
                        len -= 1;
                    }
                    for _ in 0..len {
                        let above = read_px(&dst, d - row_delta);
                        write_px(&mut dst, d, above);
                        d += ps;
                    }
                }
                insert_fg = true;
                continue;
            }
            _ => {}
        }
        insert_fg = false;

        match code {
            FG_RUN | MEGA_FG_RUN | LITE_SET_FG_FG_RUN | MEGA_SET_FG_RUN => {
                let (len, hlen) = run_length(code, src)?;
                i += hlen;
                if matches!(code, LITE_SET_FG_FG_RUN | MEGA_SET_FG_RUN) {
                    need_src!(ps);
                    fg_pel = read_px(data, i);
                    i += ps;
                }
                for _ in 0..len {
                    let px = if first_line { fg_pel } else { read_px(&dst, d - row_delta) ^ fg_pel };
                    write_px(&mut dst, d, px);
                    d += ps;
                }
            }
            LITE_DITHERED_RUN | MEGA_DITHERED_RUN => {
                let (len, hlen) = run_length(code, src)?;
                i += hlen;
                need_src!(2 * ps);
                let a = read_px(data, i);
                let b = read_px(data, i + ps);
                i += 2 * ps;
                for _ in 0..len {
                    write_px(&mut dst, d, a);
                    d += ps;
                    write_px(&mut dst, d, b);
                    d += ps;
                }
            }
            COLOR_RUN | MEGA_COLOR_RUN => {
                let (len, hlen) = run_length(code, src)?;
                i += hlen;
                need_src!(ps);
                let a = read_px(data, i);
                i += ps;
                for _ in 0..len {
                    write_px(&mut dst, d, a);
                    d += ps;
                }
            }
            FGBG_IMAGE | MEGA_FGBG_IMAGE | LITE_SET_FG_FGBG_IMAGE | MEGA_SET_FGBG_IMAGE => {
                let (mut len, hlen) = run_length(code, src)?;
                i += hlen;
                if matches!(code, LITE_SET_FG_FGBG_IMAGE | MEGA_SET_FGBG_IMAGE) {
                    need_src!(ps);
                    fg_pel = read_px(data, i);
                    i += ps;
                }
                while len > 0 {
                    let bits = len.min(8);
                    need_src!(1);
                    let mask = data[i];
                    i += 1;
                    d = write_fgbg(&mut dst, d, row_delta, mask, fg_pel, bits, first_line, ps, &read_px, &write_px);
                    len -= bits;
                }
            }
            COLOR_IMAGE | MEGA_COLOR_IMAGE => {
                let (len, hlen) = run_length(code, src)?;
                i += hlen;
                let byte_count = len * ps;
                need_src!(byte_count);
                dst[d..d + byte_count].copy_from_slice(&data[i..i + byte_count]);
                i += byte_count;
                d += byte_count;
            }
            SPECIAL_FGBG_1 => {
                i += 1;
                d = write_fgbg(&mut dst, d, row_delta, 0x03, fg_pel, 8, first_line, ps, &read_px, &write_px);
            }
            SPECIAL_FGBG_2 => {
                i += 1;
                d = write_fgbg(&mut dst, d, row_delta, 0x05, fg_pel, 8, first_line, ps, &read_px, &write_px);
            }
            WHITE => {
                i += 1;
                write_px(&mut dst, d, white);
                d += ps;
            }
            BLACK => {
                i += 1;
                write_px(&mut dst, d, 0);
                d += ps;
            }
            _ => return Err(Error::Protocol("unknown RLE order")),
        }
    }
    Ok(dst)
}

#[allow(clippy::too_many_arguments)]
fn write_fgbg(
    dst: &mut [u8],
    mut d: usize,
    row_delta: usize,
    mask: u8,
    fg_pel: u32,
    bits: usize,
    first_line: bool,
    ps: usize,
    read_px: &impl Fn(&[u8], usize) -> u32,
    write_px: &impl Fn(&mut [u8], usize, u32),
) -> usize {
    for k in 0..bits {
        let set = mask & (1 << k) != 0;
        let px = if first_line {
            if set { fg_pel } else { 0 }
        } else {
            let above = read_px(dst, d - row_delta);
            if set { above ^ fg_pel } else { above }
        };
        write_px(dst, d, px);
        d += ps;
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_run_fills_pixels() {
        // COLOR_RUN (code 0x3 → raw 0x60) len 4, 16bpp red 0xF800.
        let data = [0x64, 0x00, 0xF8];
        let out = decompress(&data, 4, 1, 16).unwrap();
        assert_eq!(out, [0x00, 0xF8, 0x00, 0xF8, 0x00, 0xF8, 0x00, 0xF8]);
    }

    #[test]
    fn color_image_is_raw_copy() {
        // COLOR_IMAGE (0x4 → raw 0x80) len 2, two 16bpp pixels.
        let data = [0x82, 0x00, 0xF8, 0x1F, 0x00];
        let out = decompress(&data, 2, 1, 16).unwrap();
        assert_eq!(out, [0x00, 0xF8, 0x1F, 0x00]);
    }

    #[test]
    fn black_and_white_single_pixels() {
        // WHITE, BLACK on a 2x1 8bpp image.
        let data = [WHITE, BLACK];
        let out = decompress(&data, 2, 1, 8).unwrap();
        assert_eq!(out, [0xFF, 0x00]);
    }

    #[test]
    fn background_run_on_first_line_is_black() {
        // BG_RUN (0x0 → raw 0x00) len 3 on 8bpp: first line → black pixels.
        let data = [0x03];
        let out = decompress(&data, 3, 1, 8).unwrap();
        assert_eq!(out, [0, 0, 0]);
    }

    #[test]
    fn foreground_run_first_line_writes_fgpel() {
        // FG_RUN (0x1 → raw 0x20) len 2 on 8bpp: first line writes fgPel (white).
        let data = [0x22];
        let out = decompress(&data, 2, 1, 8).unwrap();
        assert_eq!(out, [0xFF, 0xFF]);
    }

    #[test]
    fn fgbg_second_line_xors_against_row_above() {
        // 8x2 8bpp. Line 1 (bottom): color image of 8 distinct bytes.
        // Line 2 (top): FGBG image with a mask — set bits XOR fgPel(white) over above.
        let mut data = vec![0x88]; // COLOR_IMAGE len 8
        data.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        // FGBG_IMAGE (0x2 → raw 0x40), len 8 → r=1 (1*8=8): raw byte 0x41, mask 0x0F.
        data.push(0x41);
        data.push(0x0F); // low 4 bits set → first 4 pixels XOR white
        let out = decompress(&data, 8, 2, 8).unwrap();
        // second scanline (bytes 8..16): first 4 = above ^ 0xFF, last 4 = above.
        assert_eq!(&out[8..16], &[1 ^ 0xFF, 2 ^ 0xFF, 3 ^ 0xFF, 4 ^ 0xFF, 5, 6, 7, 8]);
    }
}
