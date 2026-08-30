//! Headless, phase-by-phase smoke test against a real RDP server. Reports exactly
//! how far the connection sequence gets so interop issues can be pinpointed.
//!
//!   cargo run --example smoke -- <host> <username> <password> [domain]

use ferropipe_rdp::connection::{PduTransport, SessionConfig};
use ferropipe_rdp::gcc::ChannelDef;
use ferropipe_rdp::nego::SecurityProtocol;
use ferropipe_rdp::nla::client::CredSspClient;
use ferropipe_rdp::tls::{Frame, TlsTransport};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: smoke <host> <username> <password> [domain]");
        std::process::exit(2);
    }
    let (host, user, pass) = (&args[1], &args[2], &args[3]);
    let domain = args.get(4).cloned().unwrap_or_default();
    let addr = format!("{host}:3389");

    // Phase 1: TCP + X.224 negotiation + TLS.
    println!("[1] TLS + X.224 negotiation → {addr}");
    let requested = SecurityProtocol::SSL | SecurityProtocol::HYBRID;
    let mut transport = match TlsTransport::connect(&addr, requested, Some(user.clone())) {
        Ok(t) => t,
        Err(e) => {
            println!("    ✗ FAILED at TLS/negotiation: {e}");
            return;
        }
    };
    let protocol = transport.selected_protocol();
    let names = SecurityProtocol(protocol);
    println!("    ✓ TLS up. selected protocol = {names:?}");
    println!("    ✓ server public key: {} bytes", transport.server_public_key().len());

    // Phase 2: NLA/CredSSP.
    if protocol & SecurityProtocol::HYBRID != 0 {
        println!("[2] NLA / CredSSP (NTLMv2)");
        let mut nla = CredSspClient::new(&domain, user, pass, transport.server_public_key().to_vec());
        if let Err(e) = (|| -> ferropipe_rdp::Result<()> {
            transport.write_raw(&nla.start())?;
            let challenge = transport.read_credssp()?;
            println!("    ✓ received CHALLENGE ({} bytes)", challenge.len());
            transport.write_raw(&nla.process_challenge(&challenge)?)?;
            let pubkey_reply = transport.read_credssp()?;
            println!("    ✓ received pubKeyAuth ({} bytes)", pubkey_reply.len());
            transport.write_raw(&nla.process_pubkey(&pubkey_reply)?)?;
            Ok(())
        })() {
            println!("    ✗ FAILED at NLA: {e}");
            return;
        }
        println!("    ✓ NLA authenticated");
    } else {
        println!("[2] NLA skipped (server did not select HYBRID)");
    }

    // Phase 3: MCS / GCC / capability exchange — driven step by step.
    println!("[3] MCS + GCC + capability exchange");
    let cfg = SessionConfig {
        width: 1280,
        height: 800,
        domain,
        username: user.clone(),
        selected_protocol: protocol,
        channels: vec![ChannelDef { name: "drdynvc".into(), options: 0xC000_0000 }],
    };
    use ferropipe_rdp::connection::{
        basic_settings_exchange, channel_connection, send_client_info, send_confirm_active,
        wait_for_demand_active,
    };
    let server_net = match basic_settings_exchange(&mut transport, &cfg) {
        Ok(n) => {
            println!("    ✓ basic settings: io_channel={} vchannels={:?}", n.io_channel_id, n.channel_ids);
            n
        }
        Err(e) => {
            println!("    ✗ basic settings (Connect Initial/Response): {e}");
            return;
        }
    };
    let (user_id, joined) = match channel_connection(&mut transport, &cfg, &server_net) {
        Ok(x) => {
            println!("    ✓ channel connection: user_id={} joined={:?}", x.0, x.1);
            x
        }
        Err(e) => {
            println!("    ✗ channel connection (erect/attach/join): {e}");
            return;
        }
    };
    let _ = joined;
    if let Err(e) = send_client_info(&mut transport, user_id, &cfg) {
        println!("    ✗ client info: {e}");
        return;
    }
    println!("    ✓ client info sent");
    let demand = match wait_for_demand_active(&mut transport) {
        Ok(d) => {
            println!("    ✓ demand active: share_id={:#x}, {} caps", d.share_id, d.capability_sets.len());
            d
        }
        Err(e) => {
            println!("    ✗ waiting for demand active: {e}");
            return;
        }
    };
    if let Err(e) = send_confirm_active(&mut transport, user_id, demand.share_id, &cfg) {
        println!("    ✗ confirm active: {e}");
        return;
    }
    println!("    ✓ confirm active sent");
    // Read the first server PDU; if it's a Set Error Info, decode the errorInfo.
    if let Ok(mcs) = transport.recv() {
        if let Ok((_c, rdp)) = ferropipe_rdp::mcs::domain::parse_send_data_indication(&mcs) {
            if let Ok((_h, body)) = ferropipe_rdp::pdu::parse_share_control(rdp) {
                if let Ok((47, err)) = ferropipe_rdp::pdu::parse_share_data(body) {
                    let code = u32::from_le_bytes([err[0], err[1], err[2], err[3]]);
                    println!("    >>> server SET_ERROR_INFO code = {code:#010x}");
                }
            }
        }
    }
    if let Err(e) = ferropipe_rdp::connection::finalization(&mut transport, user_id, demand.share_id) {
        println!("    ✗ finalization: {e}");
        return;
    }
    println!("    ✓ session ACTIVE (finalization complete)");
    let _ = &server_net;

    // Phase 4: read server frames and DECODE the graphics into a framebuffer.
    println!("[4] reading + decoding server graphics");
    let mut display = ferropipe_rdp::graphics::update::Display::new(cfg.width as usize, cfg.height as usize);
    let (mut fast, mut slow) = (0, 0);
    for _ in 0..60 {
        match transport.read_frame() {
            Ok(Frame::FastPath(pdu)) => {
                fast += 1;
                if let Ok(updates) = ferropipe_rdp::graphics::fastpath::parse_output_pdu(&pdu) {
                    let _ = display.apply_all(&updates);
                }
            }
            Ok(Frame::SlowPath(mcs)) => {
                slow += 1;
                if slow <= 5 {
                    println!("    slow-path PDU: {} bytes", mcs.len());
                }
            }
            Err(e) => {
                println!("    read ended: {e}");
                break;
            }
        }
    }
    println!("    ✓ received {fast} fast-path + {slow} slow-path PDUs");
    // Count non-black pixels to prove the desktop actually decoded.
    let fb = display.framebuffer.pixels();
    let painted = fb.chunks(4).filter(|p| p[0] != 0 || p[1] != 0 || p[2] != 0).count();
    let total = display.framebuffer.width() * display.framebuffer.height();
    println!("    ✓ framebuffer {}x{}: {painted}/{total} pixels painted ({:.0}%)",
        display.framebuffer.width(), display.framebuffer.height(), 100.0 * painted as f64 / total as f64);
    // Save the decoded desktop as a PPM so it can be viewed.
    let out = std::env::temp_dir().join("ferropipe-rdp-desktop.ppm");
    let out = out.to_string_lossy().to_string();
    let mut ppm = format!("P6\n{} {}\n255\n", display.framebuffer.width(), display.framebuffer.height()).into_bytes();
    for p in fb.chunks(4) {
        ppm.extend_from_slice(&[p[0], p[1], p[2]]);
    }
    std::fs::write(&out, ppm).ok();
    println!("    ✓ saved decoded desktop to {out}");
    println!("\nSMOKE TEST COMPLETE — live RDP session rendered.");
}
