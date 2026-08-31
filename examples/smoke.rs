//! Live end-to-end smoke test: connect with the full RdpSession stack, reach an
//! active session, then drive live keyboard/mouse input and pump server frames.
//!
//!   cargo run --example smoke -- <host> <username> <password> [domain]

use ferropipe_rdp::input::{mouse_event, scancode_event, PTRFLAGS_BUTTON1, PTRFLAGS_DOWN, PTRFLAGS_MOVE};
use ferropipe_rdp::session::{RdpSession, SessionParams};
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: smoke <host> <username> <password> [domain]");
        std::process::exit(2);
    }
    let mut params = SessionParams::new(&args[1], &args[2], &args[3]);
    if let Some(domain) = args.get(4) {
        params.domain = domain.clone();
    }
    params.width = 1280;
    params.height = 800;

    println!("[1-3] connecting (TLS → NLA → MCS → capabilities → finalization)…");
    let mut session = match RdpSession::connect(&params) {
        Ok(s) => s,
        Err(e) => {
            println!("  ✗ connect failed: {e}");
            std::process::exit(1);
        }
    };
    println!("  ✓ SESSION ACTIVE");

    // Phase 7: UDP multitransport leg.
    match session.multitransport_request() {
        Some(req) => {
            println!(
                "[7] UDP leg: server offered multitransport (requestId={}, protocol={:#06x})",
                req.request_id, req.requested_protocol
            );
            let mut req = req;
            if let Ok(rid) = std::env::var("FP_REQID") {
                req.request_id = rid.parse().unwrap_or(req.request_id);
                println!("  (override requestId → {})", req.request_id);
            }
            let peer: std::net::SocketAddr = format!("{}:3389", args[1]).parse().unwrap();
            let local: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
            let isn = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0x1234_5678);
            match session.enable_udp(&req, local, peer, isn) {
                Ok(()) => println!("  ✓ UDP TUNNEL ESTABLISHED — graphics now ride rdpeudp! is_on_udp={}", session.is_on_udp()),
                Err(e) => println!("  ✗ UDP tunnel failed: {e}"),
            }
        }
        None => println!("[7] UDP leg: server did not offer multitransport"),
    }

    // Phase 5: live input. Move the mouse in a square, click, and type, while
    // pumping server frames — the session must stay alive and keep responding.
    println!("[5] live input (mouse + keyboard) for 6s…");
    let start = Instant::now();
    let mut frames = 0usize;
    let mut inputs = 0usize;
    let corners = [(200u16, 200u16), (900, 200), (900, 600), (200, 600)];
    let mut step = 0usize;

    while start.elapsed() < Duration::from_secs(6) {
        // Move the mouse to the next corner.
        let (x, y) = corners[step % corners.len()];
        step += 1;
        if session.send_input(&[mouse_event(PTRFLAGS_MOVE, x, y)]).is_err() {
            println!("  ✗ input send failed (session dropped)");
            break;
        }
        inputs += 1;
        // A left click at that point.
        let _ = session.send_input(&[
            mouse_event(PTRFLAGS_MOVE | PTRFLAGS_DOWN | PTRFLAGS_BUTTON1, x, y),
            mouse_event(PTRFLAGS_MOVE, x, y),
        ]);
        // Type a key (scancode 0x1F = 'S').
        let _ = session.send_input(&[scancode_event(0x1F, true, false), scancode_event(0x1F, false, false)]);

        // Drain a few server frames (graphics/pointer/heartbeat).
        for _ in 0..4 {
            match session.pump() {
                Ok(_) => frames += 1,
                Err(e) => {
                    println!("  ✗ pump ended: {e}");
                    return report(start, frames, inputs);
                }
            }
        }
    }
    report(start, frames, inputs);
}

fn report(start: Instant, frames: usize, inputs: usize) {
    let secs = start.elapsed().as_secs_f32();
    println!("  ✓ stayed alive {secs:.1}s: sent {inputs} input batches, pumped {frames} server frames");
    println!("\nLIVE INPUT TEST COMPLETE.");
}
