//! NTLM message confidentiality/integrity (SSPI SEAL/SIGN) for CredSSP
//! ([MS-NLMP] §3.4). CredSSP always negotiates Extended Session Security + SEAL +
//! KEY_EXCH + 128-bit, so this implements exactly that profile:
//!
//! - Signing keys: `MD5(ExportedSessionKey ‖ magic)`.
//! - Sealing keys (ESS+128): `MD5(ExportedSessionKey ‖ magic)`, feeding an RC4
//!   stream handle that persists across messages.
//! - Message signature (2.2.2.9.1): `Version(1) ‖ RC4(HMAC_MD5(SignKey, seq ‖
//!   plaintext)[..8]) ‖ SeqNum`.
//! - SEAL: RC4 the plaintext, then RC4 the 8 checksum bytes on the same handle.
//!
//! No official sealed-message test vectors exist; correctness is checked by a
//! client→server→client roundtrip (the two independent RC4 handles stay in
//! lockstep, exactly as they would across the wire).

use super::crypto::hmac_md5;
use crate::{Error, Result};
use rc4::{consts::U16, KeyInit, Rc4, StreamCipher};

const CLIENT_SIGN_MAGIC: &[u8] = b"session key to client-to-server signing key magic constant\0";
const SERVER_SIGN_MAGIC: &[u8] = b"session key to server-to-client signing key magic constant\0";
const CLIENT_SEAL_MAGIC: &[u8] = b"session key to client-to-server sealing key magic constant\0";
const SERVER_SEAL_MAGIC: &[u8] = b"session key to server-to-client sealing key magic constant\0";

/// Which side of the CredSSP exchange this context represents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

fn derive_key(exported: &[u8; 16], magic: &[u8]) -> [u8; 16] {
    let mut data = Vec::with_capacity(16 + magic.len());
    data.extend_from_slice(exported);
    data.extend_from_slice(magic);
    super::crypto::md5(&data)
}

/// An NTLM confidentiality context: signs+seals outbound, verifies+opens inbound.
pub struct SecurityContext {
    own_signing: [u8; 16],
    peer_signing: [u8; 16],
    own_seal: Rc4<U16>,
    peer_seal: Rc4<U16>,
    send_seq: u32,
    recv_seq: u32,
}

impl SecurityContext {
    /// Derive all four keys from the exported session key for the given role.
    pub fn new(role: Role, exported_session_key: &[u8; 16]) -> SecurityContext {
        let client_sign = derive_key(exported_session_key, CLIENT_SIGN_MAGIC);
        let server_sign = derive_key(exported_session_key, SERVER_SIGN_MAGIC);
        let client_seal = derive_key(exported_session_key, CLIENT_SEAL_MAGIC);
        let server_seal = derive_key(exported_session_key, SERVER_SEAL_MAGIC);

        let (own_signing, peer_signing, own_seal_key, peer_seal_key) = match role {
            Role::Client => (client_sign, server_sign, client_seal, server_seal),
            Role::Server => (server_sign, client_sign, server_seal, client_seal),
        };
        SecurityContext {
            own_signing,
            peer_signing,
            own_seal: Rc4::<U16>::new((&own_seal_key).into()),
            peer_seal: Rc4::<U16>::new((&peer_seal_key).into()),
            send_seq: 0,
            recv_seq: 0,
        }
    }

    /// Signature checksum for `plaintext` at `seq`, RC4-encrypted with `handle`.
    fn checksum(signing: &[u8; 16], seq: u32, plaintext: &[u8], handle: &mut Rc4<U16>) -> [u8; 8] {
        let mut hmac_input = Vec::with_capacity(4 + plaintext.len());
        hmac_input.extend_from_slice(&seq.to_le_bytes());
        hmac_input.extend_from_slice(plaintext);
        let full = hmac_md5(signing, &hmac_input);
        let mut cs = [0u8; 8];
        cs.copy_from_slice(&full[..8]);
        handle.apply_keystream(&mut cs); // continues the keystream after the message
        cs
    }

    /// SEAL a message: returns the 16-byte signature followed by the ciphertext.
    pub fn seal(&mut self, message: &[u8]) -> Vec<u8> {
        // 1. Encrypt the plaintext (keystream [0..len)).
        let mut ciphertext = message.to_vec();
        self.own_seal.apply_keystream(&mut ciphertext);
        // 2. Checksum over the PLAINTEXT, RC4'd on the same handle (keystream [len..len+8)).
        let cs = Self::checksum(&self.own_signing, self.send_seq, message, &mut self.own_seal);

        let mut out = Vec::with_capacity(16 + ciphertext.len());
        out.extend_from_slice(&1u32.to_le_bytes()); // Version
        out.extend_from_slice(&cs); // Checksum
        out.extend_from_slice(&self.send_seq.to_le_bytes()); // SeqNum
        out.extend_from_slice(&ciphertext);
        self.send_seq = self.send_seq.wrapping_add(1);
        out
    }

    /// Open a sealed message from the peer (signature ‖ ciphertext), verifying it.
    pub fn unseal(&mut self, blob: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < 16 {
            return Err(Error::Short { need: 16, have: blob.len() });
        }
        let signature = &blob[..16];
        let ciphertext = &blob[16..];
        // Decrypt (keystream [0..len)).
        let mut plaintext = ciphertext.to_vec();
        self.peer_seal.apply_keystream(&mut plaintext);
        // Recompute the checksum over the recovered plaintext (keystream [len..len+8)).
        let expected = Self::checksum(&self.peer_signing, self.recv_seq, &plaintext, &mut self.peer_seal);
        if signature[4..12] != expected {
            return Err(Error::Protocol("NTLM message signature mismatch"));
        }
        self.recv_seq = self.recv_seq.wrapping_add(1);
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_roundtrips_across_two_contexts() {
        let esk = [0x55u8; 16];
        let mut client = SecurityContext::new(Role::Client, &esk);
        let mut server = SecurityContext::new(Role::Server, &esk);

        // Client → server, several messages, keystream stays in lockstep.
        for msg in [b"pubKeyAuth".as_slice(), b"credentials", b"third message here"] {
            let sealed = client.seal(msg);
            assert_ne!(&sealed[16..], msg, "payload is encrypted");
            assert_eq!(server.unseal(&sealed).unwrap(), msg);
        }
        // Server → client direction.
        let sealed = server.seal(b"server pubKeyAuth reply");
        assert_eq!(client.unseal(&sealed).unwrap(), b"server pubKeyAuth reply");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let esk = [0x11u8; 16];
        let mut client = SecurityContext::new(Role::Client, &esk);
        let mut server = SecurityContext::new(Role::Server, &esk);
        let mut sealed = client.seal(b"important");
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff; // flip a ciphertext bit
        assert!(matches!(server.unseal(&sealed), Err(Error::Protocol(_))));
    }

    #[test]
    fn signature_layout_is_versioned_and_sequenced() {
        let esk = [0x42u8; 16];
        let mut client = SecurityContext::new(Role::Client, &esk);
        let s0 = client.seal(b"a");
        let s1 = client.seal(b"b");
        assert_eq!(&s0[..4], &1u32.to_le_bytes()); // Version = 1
        assert_eq!(&s0[12..16], &0u32.to_le_bytes()); // SeqNum 0
        assert_eq!(&s1[12..16], &1u32.to_le_bytes()); // SeqNum 1
    }
}
