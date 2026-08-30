//! **ferropipe-rdp** — a native Rust RDP client ([MS-RDPBCGR]) built from scratch,
//! with no FreeRDP and no IronRDP. The long-term goal is an RDP session rendered
//! by Ferropipe and carried over UDP via the sibling [`rdpeudp`] crate.
//!
//! This is built in phases (see `PLAN.md`). The current layer is the **connection
//! bootstrap**: the TPKT/X.224 framing and the RDP security-protocol negotiation
//! that precede the TLS upgrade.
//!
//! ## Byte order
//! TPKT headers are big-endian (RFC 1006); X.224 is byte-oriented; RDP PDUs
//! (negotiation and everything above MCS) are little-endian. Each module states
//! which it uses.

pub mod caps;
pub mod cert;
pub mod connection;
pub mod egfx;
pub mod emt;
pub mod gcc;
pub mod graphics;
pub mod mcs;
pub mod multitransport;
pub mod nego;
pub mod info;
pub mod input;
pub mod nla;
pub mod pdu;
pub mod session;
pub mod dvc;
pub mod tls;
pub mod udp_tunnel;
pub mod vchannel;
pub mod tpkt;
pub mod x224;

/// Errors from framing, parsing, or driving an RDP connection.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("buffer too short: need {need} bytes, have {have}")]
    Short { need: usize, have: usize },
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    #[error("server rejected negotiation: {0}")]
    NegotiationFailure(&'static str),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
