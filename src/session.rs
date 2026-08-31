//! The top-level RDP client session — the capstone that composes every layer:
//! the TLS transport + X.224 negotiation (Phase 1), NLA/CredSSP (Phase 2), the
//! MCS/GCC/capability connection sequence (Phase 3), and the fast-path graphics +
//! input loop (Phases 4-5). This is what Ferropipe drives.
//!
//! `connect()` brings a session all the way to "active"; `pump()` processes one
//! server frame into the framebuffer; `send_input()` sends keyboard/mouse.

use crate::connection::{establish, Session, SessionConfig};
use crate::gcc::ChannelDef;
use crate::graphics::fastpath::parse_output_pdu;
use crate::graphics::update::Display;
use crate::graphics::Framebuffer;
use crate::nego::SecurityProtocol;
use crate::nla::client::CredSspClient;
use crate::tls::{Frame, TlsTransport};
use crate::Result;

/// Connection parameters for an RDP session.
#[derive(Clone, Debug)]
pub struct SessionParams {
    pub host: String,
    pub port: u16,
    pub domain: String,
    pub username: String,
    pub password: String,
    pub width: u16,
    pub height: u16,
}

impl SessionParams {
    pub fn new(host: &str, username: &str, password: &str) -> SessionParams {
        SessionParams {
            host: host.to_string(),
            port: 3389,
            domain: String::new(),
            username: username.to_string(),
            password: password.to_string(),
            width: 1280,
            height: 800,
        }
    }
}

/// A live (or in-progress) RDP session.
pub struct RdpSession {
    transport: TlsTransport,
    #[allow(dead_code)]
    session: Session,
    display: Display,
    /// The secured UDP multitransport tunnel, once the session has migrated
    /// graphics onto UDP (via `enable_udp`).
    udp: Option<crate::udp_tunnel::UdpTunnel>,
}

impl RdpSession {
    /// Connect and run the full sequence to an active session.
    pub fn connect(params: &SessionParams) -> Result<RdpSession> {
        let addr = format!("{}:{}", params.host, params.port);

        // Phase 1: TLS + X.224 negotiation (request TLS and NLA).
        let requested = SecurityProtocol::SSL | SecurityProtocol::HYBRID;
        let mut transport = TlsTransport::connect(&addr, requested, Some(params.username.clone()))?;
        let protocol = transport.selected_protocol();

        // Phase 2: NLA/CredSSP when the server selected HYBRID.
        if protocol & SecurityProtocol::HYBRID != 0 {
            run_nla(&mut transport, params)?;
        }

        // Phase 3: MCS/GCC/capability exchange → active session.
        let cfg = SessionConfig {
            width: params.width,
            height: params.height,
            domain: params.domain.clone(),
            username: params.username.clone(),
            selected_protocol: protocol,
            // The dynamic-channel carrier for EGFX graphics.
            channels: vec![ChannelDef { name: "drdynvc".into(), options: 0xC000_0000 }],
        };
        let session = establish(&mut transport, &cfg)?;

        Ok(RdpSession {
            transport,
            session,
            display: Display::new(params.width as usize, params.height as usize),
            udp: None,
        })
    }

    /// Migrate graphics onto the UDP multitransport tunnel in response to a server
    /// Initiate Multitransport Request. `local`/`peer` are the UDP endpoints (the
    /// peer is normally the server host on the same UDP port). After this, `pump`
    /// reads graphics from UDP (via `rdpeudp`) instead of the TCP channel.
    pub fn enable_udp(
        &mut self,
        request: &crate::multitransport::InitiateRequest,
        local: std::net::SocketAddr,
        peer: std::net::SocketAddr,
        isn: u32,
    ) -> Result<()> {
        let tunnel = crate::udp_tunnel::UdpTunnel::establish(request, local, peer, isn)?;
        self.udp = Some(tunnel);
        Ok(())
    }

    /// Whether graphics are currently carried over UDP.
    pub fn is_on_udp(&self) -> bool {
        self.udp.is_some()
    }

    /// The server's Initiate Multitransport Request, if it offered a UDP sideband.
    pub fn multitransport_request(&self) -> Option<crate::multitransport::InitiateRequest> {
        self.session.multitransport_request.clone()
    }

    /// Process one inbound server frame. Returns true if the framebuffer changed.
    /// When the UDP tunnel is active, graphics are read from it; otherwise from the
    /// TCP channel.
    pub fn pump(&mut self) -> Result<bool> {
        self.display.dirty = false;
        if let Some(tunnel) = &mut self.udp {
            // Graphics ride the UDP tunnel as tunneled fast-path PDUs.
            let pdu = tunnel.recv_pdu()?;
            let updates = parse_output_pdu(&pdu)?;
            self.display.apply_all(&updates)?;
            return Ok(self.display.dirty);
        }
        match self.transport.poll_frame(std::time::Duration::from_millis(50))? {
            Some(Frame::FastPath(pdu)) => {
                let updates = parse_output_pdu(&pdu)?;
                self.display.apply_all(&updates)?;
            }
            Some(Frame::SlowPath(_mcs)) => {
                // Slow-path share PDUs (deactivate/reactivate, set-error-info) are
                // handled in a later refinement; ignored for the graphics path.
            }
            None => {} // server quiet this cycle
        }
        Ok(self.display.dirty)
    }

    /// Send fast-path input events (keyboard/mouse) to the server.
    pub fn send_input(&mut self, events: &[Vec<u8>]) -> Result<()> {
        let pdu = crate::input::input_pdu(events);
        // Fast-path input is written directly, not TPKT/X.224-framed.
        self.transport.write_raw(&pdu)
    }

    /// The current desktop framebuffer (RGBA), ready to hand to a UI as a texture.
    pub fn framebuffer(&self) -> &Framebuffer {
        &self.display.framebuffer
    }

    /// The cursor image + hotspot, if the server has sent one.
    pub fn cursor(&self) -> Option<&crate::graphics::pointer::Cursor> {
        self.display.cursor.as_ref()
    }
}

/// Run the CredSSP/NTLMv2 exchange over the TLS channel.
fn run_nla(transport: &mut TlsTransport, params: &SessionParams) -> Result<()> {
    let mut nla = CredSspClient::new(
        &params.domain,
        &params.username,
        &params.password,
        transport.server_public_key().to_vec(),
    );
    // 1. client NEGOTIATE
    transport.write_raw(&nla.start())?;
    // 2. server CHALLENGE → 3. client AUTHENTICATE + pubKeyAuth
    let challenge = transport.read_credssp()?;
    transport.write_raw(&nla.process_challenge(&challenge)?)?;
    // 4. server pubKeyAuth → 5. client authInfo (sealed credentials)
    let pubkey_reply = transport.read_credssp()?;
    transport.write_raw(&nla.process_pubkey(&pubkey_reply)?)?;
    Ok(())
}
