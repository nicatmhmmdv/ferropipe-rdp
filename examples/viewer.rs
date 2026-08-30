//! A native RDP viewer: connects with the full ferropipe-rdp stack (TLS → NLA →
//! MCS → graphics) and renders the remote desktop in an egui window, forwarding
//! mouse and keyboard input.
//!
//!   cargo run --example viewer -- <host> <username> <password> [domain]
//!
//! This is the end-to-end integration demo — the same pieces Ferropipe embeds.
//! It needs a real RDP server to display anything.

use eframe::egui;
use ferropipe_rdp::input::{mouse_event, unicode_event, PTRFLAGS_BUTTON1, PTRFLAGS_DOWN, PTRFLAGS_MOVE};
use ferropipe_rdp::session::{RdpSession, SessionParams};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

/// A batch of fast-path input event byte-blobs.
type InputBatch = Vec<Vec<u8>>;

#[derive(Default)]
struct SharedFrame {
    rgba: Vec<u8>,
    width: usize,
    height: usize,
    generation: u64,
    error: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: viewer <host> <username> <password> [domain]");
        std::process::exit(2);
    }
    let mut params = SessionParams::new(&args[1], &args[2], &args[3]);
    if let Some(domain) = args.get(4) {
        params.domain = domain.clone();
    }

    let frame = Arc::new(Mutex::new(SharedFrame::default()));
    let (input_tx, input_rx): (Sender<InputBatch>, Receiver<InputBatch>) = mpsc::channel();

    // Background thread: drive the session and publish framebuffer snapshots.
    let frame_bg = frame.clone();
    thread::spawn(move || match RdpSession::connect(&params) {
        Ok(mut session) => loop {
            while let Ok(events) = input_rx.try_recv() {
                let _ = session.send_input(&events);
            }
            match session.pump() {
                Ok(true) => {
                    let fb = session.framebuffer();
                    let mut f = frame_bg.lock().unwrap();
                    f.rgba = fb.pixels().to_vec();
                    f.width = fb.width();
                    f.height = fb.height();
                    f.generation += 1;
                }
                Ok(false) => {}
                Err(e) => {
                    frame_bg.lock().unwrap().error = Some(format!("session ended: {e}"));
                    break;
                }
            }
        },
        Err(e) => {
            frame_bg.lock().unwrap().error = Some(format!("connect failed: {e}"));
        }
    });

    let app = Viewer { frame, input_tx, texture: None, last_generation: 0 };
    let options = eframe::NativeOptions::default();
    eframe::run_native("ferropipe-rdp viewer", options, Box::new(|_cc| Ok(Box::new(app))))?;
    Ok(())
}

struct Viewer {
    frame: Arc<Mutex<SharedFrame>>,
    input_tx: Sender<InputBatch>,
    texture: Option<egui::TextureHandle>,
    last_generation: u64,
}

impl eframe::App for Viewer {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();

        // Upload the newest framebuffer to a texture when it changes.
        {
            let f = self.frame.lock().unwrap();
            if let Some(err) = &f.error {
                ui.centered_and_justified(|ui| ui.label(err));
                return;
            }
            if f.generation != self.last_generation && f.width > 0 {
                let image = egui::ColorImage::from_rgba_unmultiplied([f.width, f.height], &f.rgba);
                self.texture = Some(ctx.load_texture("desktop", image, egui::TextureOptions::LINEAR));
                self.last_generation = f.generation;
            }
        }

        let Some(tex) = &self.texture else {
            ui.centered_and_justified(|ui| ui.label("connecting…"));
            ctx.request_repaint();
            return;
        };
        let size = tex.size_vec2();
        let response =
            ui.add(egui::Image::new(egui::load::SizedTexture::new(tex.id(), size)).sense(egui::Sense::click_and_drag()));

        // Translate pointer + keyboard into fast-path input events.
        let mut events: Vec<Vec<u8>> = Vec::new();
        if let Some(pos) = response.hover_pos() {
            let rel = pos - response.rect.min;
            let (x, y) = (rel.x.max(0.0) as u16, rel.y.max(0.0) as u16);
            let mut flags = PTRFLAGS_MOVE;
            if response.is_pointer_button_down_on() {
                flags |= PTRFLAGS_DOWN | PTRFLAGS_BUTTON1;
            }
            events.push(mouse_event(flags, x, y));
        }
        ctx.input(|i| {
            for ev in &i.events {
                if let egui::Event::Text(text) = ev {
                    for ch in text.chars() {
                        events.push(unicode_event(ch as u16, true));
                        events.push(unicode_event(ch as u16, false));
                    }
                }
            }
        });
        if !events.is_empty() {
            let _ = self.input_tx.send(events);
        }

        ctx.request_repaint();
    }
}
