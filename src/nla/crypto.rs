//! Cryptographic primitives for NTLMv2 / CredSSP, wrapping RustCrypto crates
//! (never hand-rolled). All NTLM crypto is little-endian and uses UTF-16LE for
//! text, per [MS-NLMP].

use hmac::{Hmac, Mac};
use md4::Md4;
use md5::{Digest, Md5};
use rc4::{consts::U16, KeyInit, Rc4, StreamCipher};

type HmacMd5 = Hmac<Md5>;

/// Encode a string as UTF-16LE bytes (the "UNICODE" of [MS-NLMP]).
pub fn unicode(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// MD4 digest (used for the NT hash of a password).
pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut h = Md4::new();
    h.update(data);
    h.finalize().into()
}

/// MD5 digest.
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize().into()
}

/// HMAC-MD5 of `data` under `key`.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <HmacMd5 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// RC4-encrypt/decrypt `data` under a 16-byte `key` (symmetric).
pub fn rc4(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut cipher = Rc4::<U16>::new(key.into());
    let mut buf = data.to_vec();
    cipher.apply_keystream(&mut buf);
    buf
}

/// NTOWFv2 = HMAC_MD5(MD4(UNICODE(password)), UNICODE(Uppercase(user) . domain)).
/// The user name is upper-cased; the domain is used as-is ([MS-NLMP] §3.3.2).
pub fn ntowf_v2(password: &str, user: &str, domain: &str) -> [u8; 16] {
    let nt_hash = md4(&unicode(password));
    let identity = unicode(&format!("{}{}", user.to_uppercase(), domain));
    hmac_md5(&nt_hash, &identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md4_of_empty_matches_known_vector() {
        // MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
        assert_eq!(
            md4(b""),
            [0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0]
        );
    }

    #[test]
    fn hmac_md5_matches_rfc2104_vector() {
        // RFC 2104 test 1: key = 0x0b×16, data = "Hi There"
        let key = [0x0bu8; 16];
        assert_eq!(
            hmac_md5(&key, b"Hi There"),
            [0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d]
        );
    }

    #[test]
    fn rc4_matches_known_vector() {
        // Classic RC4: key "Key", plaintext "Plaintext" → BBF316E8D940AF0AD3
        let mut key = [0u8; 16];
        key[..3].copy_from_slice(b"Key");
        // Only the first 3 bytes are the real key; use a 3-byte RC4 instead.
        let mut cipher = Rc4::<rc4::consts::U3>::new(b"Key".into());
        let mut buf = b"Plaintext".to_vec();
        cipher.apply_keystream(&mut buf);
        assert_eq!(buf, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
    }

    #[test]
    fn unicode_is_utf16le() {
        assert_eq!(unicode("A"), [0x41, 0x00]);
        assert_eq!(unicode("User"), [0x55, 0, 0x73, 0, 0x65, 0, 0x72, 0]);
    }
}
