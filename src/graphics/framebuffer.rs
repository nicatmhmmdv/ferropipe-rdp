//! A simple RGBA framebuffer the decoders blit decoded rectangles into. The
//! final byte order is `[R, G, B, A]` per pixel, ready to hand to egui as a
//! texture.

/// An RGBA (8 bits/channel) framebuffer.
#[derive(Clone)]
pub struct Framebuffer {
    width: usize,
    height: usize,
    pixels: Vec<u8>, // width*height*4, RGBA
}

impl Framebuffer {
    pub fn new(width: usize, height: usize) -> Framebuffer {
        Framebuffer { width, height, pixels: vec![0u8; width * height * 4] }
    }

    pub fn width(&self) -> usize {
        self.width
    }
    pub fn height(&self) -> usize {
        self.height
    }
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    /// Blit an RGBA rectangle whose top-left is (x, y). Pixels outside the
    /// framebuffer are clipped. `rgba` is `rect_w * rect_h * 4` bytes, row-major.
    pub fn blit_rgba(&mut self, x: usize, y: usize, rect_w: usize, rect_h: usize, rgba: &[u8]) {
        debug_assert!(rgba.len() >= rect_w * rect_h * 4);
        for row in 0..rect_h {
            let dst_y = y + row;
            if dst_y >= self.height {
                break;
            }
            let copy_w = rect_w.min(self.width.saturating_sub(x));
            if copy_w == 0 {
                continue;
            }
            let src_off = row * rect_w * 4;
            let dst_off = (dst_y * self.width + x) * 4;
            self.pixels[dst_off..dst_off + copy_w * 4].copy_from_slice(&rgba[src_off..src_off + copy_w * 4]);
        }
    }

    /// Read a pixel as (R, G, B, A). Panics if out of bounds (test helper).
    #[cfg(test)]
    pub fn pixel(&self, x: usize, y: usize) -> (u8, u8, u8, u8) {
        let o = (y * self.width + x) * 4;
        (self.pixels[o], self.pixels[o + 1], self.pixels[o + 2], self.pixels[o + 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blit_places_pixels_at_offset() {
        let mut fb = Framebuffer::new(4, 4);
        // a 2x2 red rect at (1,1)
        let red = [255u8, 0, 0, 255].repeat(4);
        fb.blit_rgba(1, 1, 2, 2, &red);
        assert_eq!(fb.pixel(1, 1), (255, 0, 0, 255));
        assert_eq!(fb.pixel(2, 2), (255, 0, 0, 255));
        assert_eq!(fb.pixel(0, 0), (0, 0, 0, 0)); // untouched
    }

    #[test]
    fn blit_clips_at_edges() {
        let mut fb = Framebuffer::new(3, 3);
        let green = [0u8, 255, 0, 255].repeat(4);
        // 2x2 rect at (2,2) — only the top-left pixel lands inside.
        fb.blit_rgba(2, 2, 2, 2, &green);
        assert_eq!(fb.pixel(2, 2), (0, 255, 0, 255));
    }
}
