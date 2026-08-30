//! Extract the `SubjectPublicKey` from a DER X.509 certificate — the exact bytes
//! CredSSP binds `pubKeyAuth` to ([MS-CSSP] §3.1.5: the inner `subjectPublicKey`
//! BIT STRING of `SubjectPublicKeyInfo`, not the whole `SubjectPublicKeyInfo`).

use crate::nla::der::{context_tag, Reader, TAG_SEQUENCE};
use crate::{Error, Result};

const TAG_BIT_STRING: u8 = 0x03;

/// Parse a DER certificate and return the `subjectPublicKey` bytes (the BIT
/// STRING contents, minus the leading unused-bits octet).
pub fn subject_public_key(cert_der: &[u8]) -> Result<Vec<u8>> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let mut top = Reader::new(cert_der);
    let certificate = top.expect(TAG_SEQUENCE)?;
    let mut cert = Reader::new(certificate);
    let tbs = cert.expect(TAG_SEQUENCE)?;

    // TBSCertificate fields, in order:
    //   [0] version (OPTIONAL), serialNumber, signature, issuer, validity,
    //   subject, subjectPublicKeyInfo, ...
    let mut r = Reader::new(tbs);
    let (first_tag, _) = r.read_tlv()?;
    // Skip the remaining fields up to (but not including) subjectPublicKeyInfo.
    // If the first field was the version tag [0], six fields precede SPKI;
    // otherwise the first was serialNumber and five precede it.
    let skip = if first_tag == context_tag(0) { 5 } else { 4 };
    for _ in 0..skip {
        r.read_tlv()?;
    }

    // subjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
    let spki = r.expect(TAG_SEQUENCE)?;
    let mut sr = Reader::new(spki);
    let _algorithm = sr.expect(TAG_SEQUENCE)?;
    let bit_string = sr.expect(TAG_BIT_STRING)?;
    if bit_string.is_empty() {
        return Err(Error::Protocol("empty subjectPublicKey"));
    }
    // First octet of a BIT STRING is the count of unused bits (0 for keys).
    Ok(bit_string[1..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcs::ber;

    /// Build a minimal DER certificate skeleton with a known public key.
    fn fake_cert(with_version: bool, pubkey: &[u8]) -> Vec<u8> {
        // BIT STRING = unused-bits(0) ‖ pubkey
        let mut bit_string_content = vec![0u8];
        bit_string_content.extend_from_slice(pubkey);
        let bit_string = ber_tlv(0x03, &bit_string_content);
        let algorithm = ber::sequence(&ber::integer(1)); // dummy AlgorithmIdentifier
        let spki = ber::sequence(&[algorithm, bit_string].concat());

        let mut tbs_body = Vec::new();
        if with_version {
            tbs_body.extend_from_slice(&ber_tlv(context_tag(0), &ber::integer(2)));
        }
        tbs_body.extend_from_slice(&ber::integer(0x1234)); // serialNumber
        tbs_body.extend_from_slice(&ber::sequence(&ber::integer(1))); // signature
        tbs_body.extend_from_slice(&ber::sequence(&[])); // issuer
        tbs_body.extend_from_slice(&ber::sequence(&[])); // validity
        tbs_body.extend_from_slice(&ber::sequence(&[])); // subject
        tbs_body.extend_from_slice(&spki);
        let tbs = ber::sequence(&tbs_body);

        ber::sequence(&[tbs, ber::sequence(&[]), ber_tlv(0x03, &[0, 0])].concat())
    }

    fn ber_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&ber::length(value.len()));
        out.extend_from_slice(value);
        out
    }

    #[test]
    fn extracts_public_key_with_version() {
        let key = b"the-servers-public-key-bytes";
        let cert = fake_cert(true, key);
        assert_eq!(subject_public_key(&cert).unwrap(), key);
    }

    #[test]
    fn extracts_public_key_without_version() {
        let key = b"another-key";
        let cert = fake_cert(false, key);
        assert_eq!(subject_public_key(&cert).unwrap(), key);
    }
}
