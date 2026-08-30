//! CredSSP client state machine ([MS-CSSP] §3.1.5) — the capstone that drives
//! NLA end to end: it emits the NTLM NEGOTIATE, consumes the server CHALLENGE to
//! produce the AUTHENTICATE + sealed pubKeyAuth, verifies the server's pubKeyAuth
//! reply, and finally seals the credentials as authInfo.
//!
//! The three random inputs (client challenge, nonce, exported session key) come
//! from the OS RNG in production; tests inject fixed [`Entropy`] so the flow can
//! be checked against the [MS-NLMP] §4.2.4 vectors.

use super::credssp::{
    client_server_binding_hash, server_client_binding_hash, ts_credentials_password, PasswordCreds, TsRequest,
};
use super::ntlm::{av_id, parse_av_pairs, AuthenticateMessage, ChallengeMessage, NegotiateFlags, NegotiateMessage};
use super::ntlmv2::{
    encrypted_random_session_key, lm_challenge_response, nt_challenge_response, nt_proof_str, session_base_key, temp,
};
use super::sspi::{Role, SecurityContext};
use crate::{Error, Result};

/// CredSSP version this client speaks (v6 → uses the clientNonce binding hash).
pub const CREDSSP_VERSION: u32 = 6;

/// Windows-like NTLM VERSION field (major 10, build 19041, NTLMSSP_REVISION_W2K3).
const NTLM_VERSION: [u8; 8] = [10, 0, 0x4A, 0x4A, 0, 0, 0, 0x0F];

/// The three random values the NTLMv2/CredSSP flow needs.
#[derive(Clone, Copy, Debug)]
pub struct Entropy {
    pub client_challenge: [u8; 8],
    pub nonce: [u8; 32],
    pub exported_session_key: [u8; 16],
}

impl Entropy {
    /// Draw fresh entropy from the OS RNG.
    pub fn random() -> Entropy {
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;
        let mut e = Entropy { client_challenge: [0; 8], nonce: [0; 32], exported_session_key: [0; 16] };
        rng.fill_bytes(&mut e.client_challenge);
        rng.fill_bytes(&mut e.nonce);
        rng.fill_bytes(&mut e.exported_session_key);
        e
    }
}

fn client_flags() -> NegotiateFlags {
    NegotiateFlags::default()
        .with(NegotiateFlags::UNICODE)
        .with(NegotiateFlags::NTLM)
        .with(NegotiateFlags::EXTENDED_SESSIONSECURITY)
        .with(NegotiateFlags::ALWAYS_SIGN)
        .with(NegotiateFlags::SIGN)
        .with(NegotiateFlags::SEAL)
        .with(NegotiateFlags::KEY_EXCH)
        .with(NegotiateFlags::TARGET_INFO)
        .with(NegotiateFlags::VERSION)
        .with(NegotiateFlags::NEGOTIATE_128)
        .with(NegotiateFlags::NEGOTIATE_56)
}

/// Drives the CredSSP/NTLMv2 exchange for one connection.
pub struct CredSspClient {
    domain: String,
    username: String,
    password: String,
    /// The server's TLS-cert SubjectPublicKey bytes (bound into pubKeyAuth).
    server_public_key: Vec<u8>,
    entropy: Entropy,
    flags: NegotiateFlags,
    negotiate_bytes: Vec<u8>,
    security: Option<SecurityContext>,
}

impl CredSspClient {
    pub fn new(domain: &str, username: &str, password: &str, server_public_key: Vec<u8>) -> CredSspClient {
        Self::with_entropy(domain, username, password, server_public_key, Entropy::random())
    }

    pub fn with_entropy(
        domain: &str,
        username: &str,
        password: &str,
        server_public_key: Vec<u8>,
        entropy: Entropy,
    ) -> CredSspClient {
        CredSspClient {
            domain: domain.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            server_public_key,
            entropy,
            flags: client_flags(),
            negotiate_bytes: Vec::new(),
            security: None,
        }
    }

    /// Step 1: produce the first TSRequest carrying the NTLM NEGOTIATE message.
    pub fn start(&mut self) -> Vec<u8> {
        let neg = NegotiateMessage { flags: self.flags, version: Some(NTLM_VERSION) };
        self.negotiate_bytes = neg.encode().to_vec();
        let mut req = TsRequest::new(CREDSSP_VERSION);
        req.nego_tokens = vec![self.negotiate_bytes.clone()];
        req.encode()
    }

    /// Step 3: consume the server's TSRequest (with the NTLM CHALLENGE) and return
    /// the TSRequest carrying the NTLM AUTHENTICATE plus the sealed pubKeyAuth.
    pub fn process_challenge(&mut self, server_ts_request: &[u8]) -> Result<Vec<u8>> {
        let server_req = TsRequest::decode(server_ts_request)?;
        let challenge_bytes = server_req
            .nego_tokens
            .first()
            .ok_or(Error::Protocol("server TSRequest has no CHALLENGE token"))?
            .clone();
        let challenge = ChallengeMessage::decode(&challenge_bytes)?;

        // NTLMv2 response computation.
        let ntowf = super::crypto::ntowf_v2(&self.password, &self.username, &self.domain);
        let (timestamp, has_timestamp) = extract_timestamp(&challenge.target_info);
        let t = temp(timestamp, self.entropy.client_challenge, &challenge.target_info);
        let proof = nt_proof_str(&ntowf, &challenge.server_challenge, &t);
        let nt_response = nt_challenge_response(&proof, &t);
        // When the target info carries a timestamp the LM response is all zeros.
        let lm_response = if has_timestamp {
            vec![0u8; 24]
        } else {
            lm_challenge_response(&ntowf, &challenge.server_challenge, &self.entropy.client_challenge).to_vec()
        };

        let sbk = session_base_key(&ntowf, &proof);
        let exported = self.entropy.exported_session_key;
        let encrypted_session_key = encrypted_random_session_key(&sbk, &exported).to_vec();

        let mut auth = AuthenticateMessage {
            flags: self.flags,
            domain: super::crypto::unicode(&self.domain),
            user: super::crypto::unicode(&self.username),
            workstation: Vec::new(),
            lm_response,
            nt_response,
            encrypted_session_key,
            version: NTLM_VERSION,
            mic: [0u8; 16],
        };
        auth.compute_mic(&exported, &self.negotiate_bytes, &challenge_bytes);
        let authenticate_bytes = auth.encode().to_vec();

        // Establish the confidentiality context and seal the public-key binding hash.
        let mut ctx = SecurityContext::new(Role::Client, &exported);
        let hash = client_server_binding_hash(&self.entropy.nonce, &self.server_public_key);
        let pub_key_auth = ctx.seal(&hash);
        self.security = Some(ctx);

        let mut req = TsRequest::new(CREDSSP_VERSION);
        req.nego_tokens = vec![authenticate_bytes];
        req.pub_key_auth = Some(pub_key_auth);
        req.client_nonce = Some(self.entropy.nonce);
        Ok(req.encode())
    }

    /// Step 5: verify the server's pubKeyAuth reply and return the TSRequest
    /// carrying the sealed credentials (authInfo).
    pub fn process_pubkey(&mut self, server_ts_request: &[u8]) -> Result<Vec<u8>> {
        let server_req = TsRequest::decode(server_ts_request)?;
        if let Some(code) = server_req.error_code {
            if code != 0 {
                return Err(Error::NegotiationFailure("server returned CredSSP errorCode"));
            }
        }
        let sealed = server_req
            .pub_key_auth
            .ok_or(Error::Protocol("server TSRequest has no pubKeyAuth"))?;
        let ctx = self.security.as_mut().ok_or(Error::Protocol("no security context"))?;
        let server_hash = ctx.unseal(&sealed)?;
        let expected = server_client_binding_hash(&self.entropy.nonce, &self.server_public_key);
        if server_hash != expected {
            return Err(Error::Protocol("server pubKeyAuth binding hash mismatch"));
        }

        // Seal the credentials as authInfo.
        let creds = PasswordCreds {
            domain: self.domain.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
        };
        let auth_info = ctx.seal(&ts_credentials_password(&creds));
        let mut req = TsRequest::new(CREDSSP_VERSION);
        req.auth_info = Some(auth_info);
        Ok(req.encode())
    }
}

/// Pull the MsvAvTimestamp (8-byte FILETIME) out of a target-info blob, if present.
fn extract_timestamp(target_info: &[u8]) -> ([u8; 8], bool) {
    for (id, value) in parse_av_pairs(target_info) {
        if id == av_id::TIMESTAMP && value.len() == 8 {
            let mut ts = [0u8; 8];
            ts.copy_from_slice(&value);
            return (ts, true);
        }
    }
    ([0u8; 8], false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nla::ntlm::NegotiateFlags;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // The §4.2.4 target info (Domain/Server AV pairs, no timestamp).
    fn target_info() -> Vec<u8> {
        hex("02000c0044006f006d00610069006e0001000c005300650072007600650072000000000000000000")[..36].to_vec()
    }

    fn fixed_entropy() -> Entropy {
        Entropy {
            client_challenge: [0xaa; 8],
            nonce: [0x5a; 32],
            exported_session_key: [0x55; 16],
        }
    }

    #[test]
    fn start_emits_negotiate_token() {
        let mut c = CredSspClient::with_entropy("Domain", "User", "Password", vec![1, 2, 3], fixed_entropy());
        let ts = c.start();
        let req = TsRequest::decode(&ts).unwrap();
        assert_eq!(req.version, CREDSSP_VERSION);
        let neg = NegotiateMessage::decode(&req.nego_tokens[0]).unwrap();
        assert!(neg.flags.has(NegotiateFlags::EXTENDED_SESSIONSECURITY));
    }

    #[test]
    fn process_challenge_produces_correct_ntproofstr() {
        let mut c = CredSspClient::with_entropy("Domain", "User", "Password", vec![9, 9, 9, 9], fixed_entropy());
        c.start();

        // Craft the server CHALLENGE with the §4.2.4 server challenge + target info.
        let challenge = ChallengeMessage {
            flags: NegotiateFlags::default()
                .with(NegotiateFlags::UNICODE)
                .with(NegotiateFlags::TARGET_INFO)
                .with(NegotiateFlags::EXTENDED_SESSIONSECURITY),
            server_challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            target_name: crate::nla::crypto::unicode("Server"),
            target_info: target_info(),
        };
        let server_ts = {
            let mut r = TsRequest::new(CREDSSP_VERSION);
            r.nego_tokens = vec![challenge.encode().to_vec()];
            r.encode()
        };

        let out = c.process_challenge(&server_ts).unwrap();
        let req = TsRequest::decode(&out).unwrap();
        let auth = AuthenticateMessage::decode(&req.nego_tokens[0]).unwrap();

        // The NtChallengeResponse begins with the verified §4.2.4 NTProofStr.
        assert_eq!(&auth.nt_response[..16], &hex("68cd0ab851e51c96aabc927bebef6a1c")[..]);
        // pubKeyAuth + clientNonce present, and a security context now exists.
        assert!(req.pub_key_auth.is_some());
        assert_eq!(req.client_nonce, Some([0x5a; 32]));
        assert!(c.security.is_some());
    }

    #[test]
    fn full_flow_round_trips_against_a_mock_server() {
        // A minimal "server" that mirrors the CredSSP crypto to prove the client's
        // pubKeyAuth verification and authInfo sealing are self-consistent.
        let server_pubkey = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];
        let ent = fixed_entropy();
        let mut c = CredSspClient::with_entropy("Domain", "User", "Password", server_pubkey.clone(), ent);
        c.start();

        let challenge = ChallengeMessage {
            flags: NegotiateFlags::default().with(NegotiateFlags::UNICODE).with(NegotiateFlags::TARGET_INFO),
            server_challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            target_name: crate::nla::crypto::unicode("Server"),
            target_info: target_info(),
        };
        let server_ts1 = {
            let mut r = TsRequest::new(CREDSSP_VERSION);
            r.nego_tokens = vec![challenge.encode().to_vec()];
            r.encode()
        };
        let out1 = c.process_challenge(&server_ts1).unwrap();
        let client_pubkeyauth = TsRequest::decode(&out1).unwrap().pub_key_auth.unwrap();

        // Server side: derive the same keys, unseal the client's pubKeyAuth (this
        // advances the client-direction handle + seq, exactly as on the wire), and
        // verify it carries the client-direction binding hash.
        let mut server_ctx = SecurityContext::new(Role::Server, &ent.exported_session_key);
        let client_hash = server_ctx.unseal(&client_pubkeyauth).unwrap();
        assert_eq!(client_hash, client_server_binding_hash(&ent.nonce, &server_pubkey));

        // Server seals its own-direction hash as the reply.
        let server_hash = server_client_binding_hash(&ent.nonce, &server_pubkey);
        let server_pubkeyauth = server_ctx.seal(&server_hash);
        let server_ts2 = {
            let mut r = TsRequest::new(CREDSSP_VERSION);
            r.pub_key_auth = Some(server_pubkeyauth);
            r.encode()
        };

        // Client verifies and produces authInfo; the server can open it.
        let auth_info_ts = c.process_pubkey(&server_ts2).unwrap();
        let req = TsRequest::decode(&auth_info_ts).unwrap();
        let sealed_creds = req.auth_info.unwrap();
        let creds_der = server_ctx.unseal(&sealed_creds).unwrap();
        // The recovered DER is TSCredentials; just assert it is a SEQUENCE.
        assert_eq!(creds_der[0], 0x30);
    }
}
