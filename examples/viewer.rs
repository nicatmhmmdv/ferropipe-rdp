//! A native RDP viewer: connects with the full ferropipe-rdp stack (TLS → NLA →
//! MCS → graphics) and renders the remote desktop in an egui window, forwarding
//! mouse and keyboard input.
//!
//!   cargo run --example viewer --features egui -- <host> <username> <password> [domain]
//!
//! This is the end-to-end integration demo — the same pieces Ferropipe embeds.
//! It needs a real RDP server to display anything.
//!
//! Keyboard: every `egui::Event::Key` goes out as a scan code for the *physical*
//! key (`keymap::egui`), so modifiers, arrows, F-keys, Escape, Tab and friends
//! reach the server and non-US layouts work (the server applies its own
//! layout). `Event::Text` is sent as a Unicode event only when no scan code
//! already carried it — a key `keymap::KeyCode` cannot express (the ISO `<>`
//! key, F13+) or an IME commit. A toolbar button sends Ctrl+Alt+Del.

use eframe::egui;
use ferropipe_rdp::input::{mouse_event, unicode_event, PTRFLAGS_BUTTON1, PTRFLAGS_DOWN, PTRFLAGS_MOVE};
use ferropipe_rdp::keymap::egui::KeyboardBridge;
use ferropipe_rdp::keymap::{key_event, secure_attention_sequence, KeyCode, KeyEvent};
use ferropipe_rdp::session::{RdpSession, SessionParams};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

/// A batch of fast-path input event byte-blobs.
type InputBatch = Vec<Vec<u8>>;

/// Keep Tab, arrows and Escape on the desktop instead of letting egui move its
/// own focus around (otherwise Tab lands on the toolbar button and Enter would
/// click it).
const DESKTOP_EVENT_FILTER: egui::EventFilter = egui::EventFilter {
    tab: true,
    horizontal_arrows: true,
    vertical_arrows: true,
    escape: true,
};

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

    let app = Viewer {
        frame,
        input_tx,
        texture: None,
        last_generation: 0,
        keyboard: KeyboardBridge::new(),
    };
    let options = eframe::NativeOptions::default();
    eframe::run_native("ferropipe-rdp viewer", options, Box::new(|_cc| Ok(Box::new(app))))?;
    Ok(())
}

struct Viewer {
    frame: Arc<Mutex<SharedFrame>>,
    input_tx: Sender<InputBatch>,
    texture: Option<egui::TextureHandle>,
    last_generation: u64,
    keyboard: KeyboardBridge,
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
        let (tex_id, size) = (tex.id(), tex.size_vec2());

        let mut events: InputBatch = Vec::new();
        ui.horizontal(|ui| {
            if ui.button("Ctrl+Alt+Del").clicked() {
                events.extend(encode(secure_attention_sequence()));
            }
        });
        let response =
            ui.add(egui::Image::new(egui::load::SizedTexture::new(tex_id, size)).sense(egui::Sense::click_and_drag()));
        // The desktop always owns keyboard focus, so every key is the server's.
        response.request_focus();
        ui.memory_mut(|m| m.set_focus_lock_filter(response.id, DESKTOP_EVENT_FILTER));

        // Translate pointer + keyboard into fast-path input events.
        if let Some(pos) = response.hover_pos() {
            let rel = pos - response.rect.min;
            let (x, y) = (rel.x.max(0.0) as u16, rel.y.max(0.0) as u16);
            let mut flags = PTRFLAGS_MOVE;
            if response.is_pointer_button_down_on() {
                flags |= PTRFLAGS_DOWN | PTRFLAGS_BUTTON1;
            }
            events.push(mouse_event(flags, x, y));
        }
        ctx.input(|i| events.extend(self.keyboard_events(i)));
        if !events.is_empty() {
            let _ = self.input_tx.send(events);
        }

        ctx.request_repaint();
    }
}

impl Viewer {
    /// This frame's keyboard events as fast-path blobs, in order.
    ///
    /// Keys go out as scan codes and the bridge keeps modifier state straight;
    /// a `Text` event is sent as Unicode only when the bridge says no scan code
    /// already carried it (see `KeyboardBridge::text_wanted`).
    fn keyboard_events(&mut self, input: &egui::InputState) -> InputBatch {
        let mut out = InputBatch::new();
        for event in &input.events {
            match event {
                egui::Event::Key { key, physical_key, pressed, repeat, modifiers } => {
                    out.extend(encode(self.keyboard.key(*key, *physical_key, *pressed, *repeat, *modifiers)));
                }
                egui::Event::ModifiersChanged(modifiers) => {
                    out.extend(encode(self.keyboard.modifiers_changed(*modifiers)));
                }
                egui::Event::Text(text) => {
                    if self.keyboard.text_wanted(input.modifiers) {
                        out.extend(text.encode_utf16().flat_map(|unit| [unicode_event(unit, true), unicode_event(unit, false)]));
                    }
                }
                // egui-winit turns Ctrl+C/X/V into these instead of key events. Ctrl is
                // already down on the server, so tapping the letter completes the chord
                // there; clipboard redirection is out of scope for the viewer.
                egui::Event::Copy => out.extend(tap(KeyCode::C)),
                egui::Event::Cut => out.extend(tap(KeyCode::X)),
                egui::Event::Paste(_) => out.extend(tap(KeyCode::V)),
                // Never leave a modifier stuck down on the server when the window goes away.
                egui::Event::WindowFocused(false) => out.extend(encode(self.keyboard.release_all())),
                _ => {}
            }
        }
        out
    }
}

fn encode(events: Vec<KeyEvent>) -> impl Iterator<Item = Vec<u8>> {
    events.into_iter().map(KeyEvent::encode)
}

/// Press and release one key.
fn tap(key: KeyCode) -> [Vec<u8>; 2] {
    [key_event(key, true).encode(), key_event(key, false).encode()]
}
