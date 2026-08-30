//! CredSSP protocol structures ([MS-CSSP] 2.2.1): TSRequest, TSCredentials,
//! TSPasswordCreds, and the version-5+ pubKeyAuth binding hash.
//!
//! These ride inside the TLS channel. The message flow (§3.1.5) is:
//! 1. client → negoTokens = NTLM NEGOTIATE
//! 2. server → negoTokens = NTLM CHALLENGE
//! 3. client → negoTokens = NTLM AUTHENTICATE + pubKeyAuth (+ clientNonce for v5+)
//! 4. server → pubKeyAuth (server-direction hash)
//! 5. client → authInfo = SEAL(DER(TSCredentials))

use super::der::{self, context, context_tag, integer, octet_string, sequence, Reader, TAG_OCTET_STRING, TAG_SEQUENCE};
use crate::Result;
use sha2::{Digest, Sha256};

/// Magic string for the client→server binding hash (a trailing NUL is appended).
const CLIENT_SERVER_MAGIC: &[u8] = b"CredSSP Client-To-Server Binding Hash";
/// Magic string for the server→client binding hash.
const SERVER_CLIENT_MAGIC: &[u8] = b"CredSSP Server-To-Client Binding Hash";

/// SHA256(magic ‖ 0x00 ‖ nonce(32) ‖ subject_public_key) for the client direction.
pub fn client_server_binding_hash(nonce: &[u8; 32], subject_public_key: &[u8]) -> [u8; 32] {
    binding_hash(CLIENT_SERVER_MAGIC, nonce, subject_public_key)
}

/// The server-direction binding hash the server should return in step 4.
pub fn server_client_binding_hash(nonce: &[u8; 32], subject_public_key: &[u8]) -> [u8; 32] {
    binding_hash(SERVER_CLIENT_MAGIC, nonce, subject_public_key)
}

fn binding_hash(magic: &[u8], nonce: &[u8; 32], key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(magic);
    h.update([0x00]); // trailing NUL of the magic string
    h.update(nonce);
    h.update(key);
    h.finalize().into()
}

/// TSPasswordCreds ([MS-CSSP] 2.2.1.2.1) — the actual credentials. Strings are
/// UTF-16LE with no BOM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordCreds {
    pub domain: String,
    pub username: String,
    pub password: String,
}

impl PasswordCreds {
    pub fn encode(&self) -> Vec<u8> {
        use super::crypto::unicode;
        let body = [
            context(0, &octet_string(&unicode(&self.domain))),
            context(1, &octet_string(&unicode(&self.username))),
            context(2, &octet_string(&unicode(&self.password))),
        ]
        .concat();
        sequence(&body)
    }
}

/// TSCredentials ([MS-CSSP] 2.2.1.2) wrapping password credentials (credType 1).
pub fn ts_credentials_password(creds: &PasswordCreds) -> Vec<u8> {
    let body = [context(0, &integer(1)), context(1, &octet_string(&creds.encode()))].concat();
    sequence(&body)
}

/// TSRequest ([MS-CSSP] 2.2.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TsRequest {
    pub version: u32,
    /// Zero or more nego tokens (NTLM/SPNEGO messages); usually exactly one.
    pub nego_tokens: Vec<Vec<u8>>,
    pub auth_info: Option<Vec<u8>>,
    pub pub_key_auth: Option<Vec<u8>>,
    pub error_code: Option<u32>,
    pub client_nonce: Option<[u8; 32]>,
}

impl TsRequest {
    pub fn new(version: u32) -> TsRequest {
        TsRequest { version, ..Default::default() }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut body = context(0, &integer(self.version as u64));

        if !self.nego_tokens.is_empty() {
            // NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
            let mut items = Vec::new();
            for token in &self.nego_tokens {
                let inner = context(0, &octet_string(token));
                items.extend_from_slice(&sequence(&inner));
            }
            body.extend_from_slice(&context(1, &sequence(&items)));
        }
        if let Some(ai) = &self.auth_info {
            body.extend_from_slice(&context(2, &octet_string(ai)));
        }
        if let Some(pk) = &self.pub_key_auth {
            body.extend_from_slice(&context(3, &octet_string(pk)));
        }
        if let Some(code) = self.error_code {
            body.extend_from_slice(&context(4, &integer(code as u64)));
        }
        if let Some(nonce) = &self.client_nonce {
            body.extend_from_slice(&context(5, &octet_string(nonce)));
        }
        sequence(&body)
    }

    pub fn decode(buf: &[u8]) -> Result<TsRequest> {
        let mut top = Reader::new(buf);
        let inner = top.expect(TAG_SEQUENCE)?;
        let mut r = Reader::new(inner);
        let mut req = TsRequest::default();

        while !r.is_empty() {
            let (tag, value) = r.read_tlv()?;
            match tag {
                t if t == context_tag(0) => {
                    req.version = Reader::new(value).read_integer()? as u32;
                }
                t if t == context_tag(1) => {
                    // NegoData: SEQUENCE OF SEQUENCE { [0] OCTET STRING }
                    let mut nd = Reader::new(value);
                    let list = nd.expect(TAG_SEQUENCE)?;
                    let mut lr = Reader::new(list);
                    while !lr.is_empty() {
                        let item = lr.expect(TAG_SEQUENCE)?;
                        let mut ir = Reader::new(item);
                        let tok = ir.expect(context_tag(0))?;
                        let bytes = Reader::new(tok).expect(TAG_OCTET_STRING)?;
                        req.nego_tokens.push(bytes.to_vec());
                    }
                }
                t if t == context_tag(2) => {
                    req.auth_info = Some(Reader::new(value).expect(TAG_OCTET_STRING)?.to_vec());
                }
                t if t == context_tag(3) => {
                    req.pub_key_auth = Some(Reader::new(value).expect(TAG_OCTET_STRING)?.to_vec());
                }
                t if t == context_tag(4) => {
                    req.error_code = Some(Reader::new(value).read_integer()? as u32);
                }
                t if t == context_tag(5) => {
                    let n = Reader::new(value).expect(TAG_OCTET_STRING)?;
                    let mut nonce = [0u8; 32];
                    if n.len() == 32 {
                        nonce.copy_from_slice(n);
                        req.client_nonce = Some(nonce);
                    }
                }
                _ => {} // ignore unknown context tags
            }
        }
        let _ = der::TAG_INTEGER; // keep the import meaningful across refactors
        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ts_request_with_nego_token_roundtrips() {
        let req = TsRequest {
            version: 6,
            nego_tokens: vec![b"\x4eTLMSSP-negotiate".to_vec()],
            pub_key_auth: Some(vec![0xAA; 40]),
            client_nonce: Some([0x5A; 32]),
            ..Default::default()
        };
        let bytes = req.encode();
        let back = TsRequest::decode(&bytes).unwrap();
        assert_eq!(back.version, 6);
        assert_eq!(back.nego_tokens, req.nego_tokens);
        assert_eq!(back.pub_key_auth, req.pub_key_auth);
        assert_eq!(back.client_nonce, req.client_nonce);
    }

    #[test]
    fn ts_request_version_only_roundtrips() {
        let req = TsRequest::new(2);
        let back = TsRequest::decode(&req.encode()).unwrap();
        assert_eq!(back.version, 2);
        assert!(back.nego_tokens.is_empty());
    }

    #[test]
    fn ts_request_error_code_roundtrips() {
        let mut req = TsRequest::new(6);
        req.error_code = Some(0xC0000225); // STATUS_NOT_FOUND-ish
        let back = TsRequest::decode(&req.encode()).unwrap();
        assert_eq!(back.error_code, Some(0xC0000225));
    }

    #[test]
    fn ts_credentials_password_is_well_formed_der() {
        let creds = PasswordCreds {
            domain: "DOMAIN".into(),
            username: "nicat".into(),
            password: "secret".into(),
        };
        let der = ts_credentials_password(&creds);
        // Outer SEQUENCE { [0] INTEGER 1, [1] OCTET STRING <inner> }
        let mut r = Reader::new(&der);
        let body = r.expect(TAG_SEQUENCE).unwrap();
        let mut br = Reader::new(body);
        let cred_type = Reader::new(br.expect(context_tag(0)).unwrap()).read_integer().unwrap();
        assert_eq!(cred_type, 1);
        let inner = Reader::new(br.expect(context_tag(1)).unwrap()).expect(TAG_OCTET_STRING).unwrap();
        // inner is DER(TSPasswordCreds) — parse the domain field back out.
        let mut ir = Reader::new(inner);
        let pw_seq = ir.expect(TAG_SEQUENCE).unwrap();
        let mut pr = Reader::new(pw_seq);
        let dom = Reader::new(pr.expect(context_tag(0)).unwrap()).expect(TAG_OCTET_STRING).unwrap();
        assert_eq!(dom, &super::super::crypto::unicode("DOMAIN")[..]);
    }

    #[test]
    fn binding_hashes_are_deterministic_and_direction_specific() {
        let nonce = [0x42u8; 32];
        let key = b"fake-subject-public-key-bytes";
        let c = client_server_binding_hash(&nonce, key);
        let s = server_client_binding_hash(&nonce, key);
        assert_eq!(c.len(), 32);
        assert_ne!(c, s, "client and server directions differ");
        // deterministic
        assert_eq!(c, client_server_binding_hash(&nonce, key));
    }
}
