//! MCS (Multipoint Communication Service, ITU-T T.125) as used by RDP: the
//! Connect Initial/Response (BER) and the domain PDUs (PER) that carry every RDP
//! PDU once the channels are joined.
//!
//! Layout:
//! - [`ber`] / [`per`] — ASN.1 encoding primitives.
//! - `connect` — Connect Initial/Response + GCC user data (Phase 3, next).
//! - `domain` — Erect Domain / Attach User / Channel Join / Send Data (next).

pub mod ber;
pub mod connect;
pub mod domain;
pub mod per;
