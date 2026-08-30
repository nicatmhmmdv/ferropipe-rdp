//! NTLMv2 response and key computation ([MS-NLMP] §3.3.2, §3.4.5). Verified
//! against the published §4.2.4 test vectors (see the tests below).
//!
//! Flow: `NTOWFv2` (in [`super::crypto`]) → `temp` blob → `NTProofStr` →
//! `NtChallengeResponse` → `SessionBaseKey` → `ExportedSessionKey`.

use super::crypto::{hmac_md5, rc4};

/// Build the NTLMv2 `temp` blob ([MS-NLMP] §3.3.2).
///
/// `temp = 0x01, 0x01, Z(6), time(8), client_challenge(8), Z(4), target_info, Z(4)`.
pub fn temp(time: [u8; 8], client_challenge: [u8; 8], target_info: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(28 + target_info.len());
    t.push(0x01); // Responserversion
    t.push(0x01); // HiResponserversion
    t.extend_from_slice(&[0u8; 6]); // Z(6)
    t.extend_from_slice(&time); // FILETIME, little-endian
    t.extend_from_slice(&client_challenge);
    t.extend_from_slice(&[0u8; 4]); // Z(4)
    t.extend_from_slice(target_info);
    t.extend_from_slice(&[0u8; 4]); // Z(4)
    t
}

/// NTProofStr = HMAC_MD5(NTOWFv2, ServerChallenge . temp).
pub fn nt_proof_str(ntowf_v2: &[u8; 16], server_challenge: &[u8; 8], temp: &[u8]) -> [u8; 16] {
    let mut data = Vec::with_capacity(8 + temp.len());
    data.extend_from_slice(server_challenge);
    data.extend_from_slice(temp);
    hmac_md5(ntowf_v2, &data)
}

/// NtChallengeResponse = NTProofStr . temp.
pub fn nt_challenge_response(nt_proof_str: &[u8; 16], temp: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(16 + temp.len());
    r.extend_from_slice(nt_proof_str);
    r.extend_from_slice(temp);
    r
}

/// LmChallengeResponse (v2) = HMAC_MD5(NTOWFv2, ServerChallenge . ClientChallenge) . ClientChallenge.
pub fn lm_challenge_response(
    ntowf_v2: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
) -> [u8; 24] {
    let mut data = [0u8; 16];
    data[..8].copy_from_slice(server_challenge);
    data[8..].copy_from_slice(client_challenge);
    let mac = hmac_md5(ntowf_v2, &data);
    let mut out = [0u8; 24];
    out[..16].copy_from_slice(&mac);
    out[16..].copy_from_slice(client_challenge);
    out
}

/// SessionBaseKey = HMAC_MD5(NTOWFv2, NTProofStr). For NTLMv2 this is also the
/// KeyExchangeKey.
pub fn session_base_key(ntowf_v2: &[u8; 16], nt_proof_str: &[u8; 16]) -> [u8; 16] {
    hmac_md5(ntowf_v2, nt_proof_str)
}

/// EncryptedRandomSessionKey = RC4(KeyExchangeKey, ExportedSessionKey), sent when
/// NTLMSSP_NEGOTIATE_KEY_EXCH is set.
pub fn encrypted_random_session_key(kx_key: &[u8; 16], exported: &[u8; 16]) -> [u8; 16] {
    let out = rc4(kx_key, exported);
    let mut k = [0u8; 16];
    k.copy_from_slice(&out);
    k
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nla::crypto::{md4, ntowf_v2, unicode};

    // Inputs from [MS-NLMP] §4.2.1.
    const SERVER_CHALLENGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    const CLIENT_CHALLENGE: [u8; 8] = [0xaa; 8];
    const TIME: [u8; 8] = [0u8; 8];
    // TargetInfo from §4.2.4.
    const TARGET_INFO: [u8; 36] = [
        0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e,
        0x00, 0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00,
        0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn md4_of_password_matches_4241() {
        assert_eq!(md4(&unicode("Password")).to_vec(), hex("a4f49c406510bdcab6824ee7c30fd852"));
    }

    #[test]
    fn ntowfv2_matches_4241() {
        assert_eq!(ntowf_v2("Password", "User", "Domain").to_vec(), hex("0c868a403bfd7a93a3001ef22ef02e3f"));
    }

    #[test]
    fn temp_matches_4244() {
        let t = temp(TIME, CLIENT_CHALLENGE, &TARGET_INFO);
        // temp = 0x01,0x01, Z(6), Time(8), ClientChallenge(8), Z(4), TargetInfo, Z(4).
        let mut expected = Vec::new();
        expected.extend_from_slice(&hex("01010000000000000000000000000000")); // 01 01 + Z6 + Time
        expected.extend_from_slice(&CLIENT_CHALLENGE);
        expected.extend_from_slice(&[0, 0, 0, 0]);
        expected.extend_from_slice(&TARGET_INFO);
        expected.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(t, expected);
        assert_eq!(t.len(), 68);
    }

    #[test]
    fn nt_proof_and_response_match_4244() {
        let key = ntowf_v2("Password", "User", "Domain");
        let t = temp(TIME, CLIENT_CHALLENGE, &TARGET_INFO);
        let proof = nt_proof_str(&key, &SERVER_CHALLENGE, &t);
        assert_eq!(proof.to_vec(), hex("68cd0ab851e51c96aabc927bebef6a1c"));

        let resp = nt_challenge_response(&proof, &t);
        assert_eq!(&resp[..16], &proof);
        assert_eq!(resp.len(), 16 + t.len());
    }

    #[test]
    fn lm_response_matches_4244() {
        let key = ntowf_v2("Password", "User", "Domain");
        let lm = lm_challenge_response(&key, &SERVER_CHALLENGE, &CLIENT_CHALLENGE);
        assert_eq!(lm.to_vec(), hex("86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn session_base_key_matches_4244() {
        let key = ntowf_v2("Password", "User", "Domain");
        let proof = nt_proof_str(&key, &SERVER_CHALLENGE, &temp(TIME, CLIENT_CHALLENGE, &TARGET_INFO));
        let sbk = session_base_key(&key, &proof);
        assert_eq!(sbk.to_vec(), hex("8de40ccadbc14a82f15cb0ad0de95ca3"));
    }

    #[test]
    fn encrypted_session_key_matches_4244() {
        let kx = {
            let mut k = [0u8; 16];
            k.copy_from_slice(&hex("8de40ccadbc14a82f15cb0ad0de95ca3"));
            k
        };
        let exported = [0x55u8; 16];
        let enc = encrypted_random_session_key(&kx, &exported);
        assert_eq!(enc.to_vec(), hex("c5dad2544fc9799094ce1ce90bc9d03e"));
    }
}
