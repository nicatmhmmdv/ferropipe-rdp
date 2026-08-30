//! Graphics: the fast-path update framing, bitmap decode, and the RGBA
//! framebuffer that decoded rectangles blit into (Phase 4). The framebuffer is
//! handed to egui as a texture for display.

pub mod bitmap;
pub mod fastpath;
pub mod planar;
pub mod pointer;
pub mod framebuffer;
pub mod rle;
pub mod update;

pub use framebuffer::Framebuffer;
