//! Network Level Authentication (NLA): CredSSP ([MS-CSSP]) carrying NTLMv2
//! ([MS-NLMP]) over the TLS channel established in Phase 1.
//!
//! Layout:
//! - [`crypto`] — MD4/MD5/HMAC-MD5/RC4 primitives + NTOWFv2.
//! - `ntlm` — the three NTLM messages and NTLMv2 key computation (next).
//! - `credssp` — TSRequest DER and the CredSSP message state machine (next).

pub mod client;
pub mod credssp;
pub mod crypto;
pub mod der;
pub mod ntlm;
pub mod ntlmv2;
pub mod sspi;
