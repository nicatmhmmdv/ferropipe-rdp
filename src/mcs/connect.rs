//! MCS Connect-Initial / Connect-Response ([MS-RDPBCGR] 2.2.1.3-2.2.1.4,
//! ITU-T T.125). BER-encoded; the userData carries the PER-encoded GCC
//! ConferenceCreate (see [`crate::gcc`]).

use super::ber;
use crate::{Error, Result};

/// Connect-Initial = [APPLICATION 101]; Connect-Response = [APPLICATION 102].
const CONNECT_INITIAL: u32 = 101;
const CONNECT_RESPONSE: u32 = 102;

/// BER INTEGER encoded as **unsigned-minimal** (no sign-extension byte). MCS
/// DomainParameters are `INTEGER(0..MAX)`; real RDP encodes 65535 as `02 02 FF FF`
/// (which is -1 in signed BER), so an unsigned encoding is what interoperates.
fn uint(v: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut started = false;
    for shift in [24u32, 16, 8, 0] {
        let b = (v >> shift) as u8;
        if b != 0 || started || shift == 0 {
            bytes.push(b);
            started = true;
        }
    }
    let mut out = vec![0x02, bytes.len() as u8];
    out.extend_from_slice(&bytes);
    out
}

/// Encode a DomainParameters SEQUENCE from its eight INTEGER fields.
fn domain_parameters(vals: [u32; 8]) -> Vec<u8> {
    let body: Vec<u8> = vals.iter().flat_map(|&v| uint(v)).collect();
    ber::sequence(&body)
}

/// Build the MCS Connect-Initial PDU wrapping `gcc_ccr` (the GCC
/// ConferenceCreateRequest). Uses the canonical RDP DomainParameters.
pub fn connect_initial(gcc_ccr: &[u8]) -> Vec<u8> {
    // target / minimum / maximum DomainParameters (canonical RDP client values).
    let target = domain_parameters([34, 2, 0, 1, 0, 1, 0xFFFF, 2]);
    let minimum = domain_parameters([1, 1, 1, 1, 0, 1, 0x420, 2]);
    let maximum = domain_parameters([0xFFFF, 0xFC17, 0xFFFF, 1, 0, 1, 0xFFFF, 2]);

    let mut body = Vec::new();
    body.extend_from_slice(&ber::octet_string(&[0x01])); // callingDomainSelector
    body.extend_from_slice(&ber::octet_string(&[0x01])); // calledDomainSelector
    body.extend_from_slice(&ber::boolean(true)); // upwardFlag
    body.extend_from_slice(&target);
    body.extend_from_slice(&minimum);
    body.extend_from_slice(&maximum);
    body.extend_from_slice(&ber::octet_string(gcc_ccr)); // userData
    ber::application(CONNECT_INITIAL, &body)
}

/// Parse an MCS Connect-Response, returning the userData (the GCC
/// ConferenceCreateResponse bytes). Verifies the result is rt-successful.
pub fn parse_connect_response(pdu: &[u8]) -> Result<&[u8]> {
    let mut r = ber::Reader::new(pdu);
    let body = r.expect(&ber::application_tag_bytes(CONNECT_RESPONSE))?;

    let mut br = ber::Reader::new(body);
    let result = br.expect(&[0x0a])?; // ENUMERATED result
    if result.first() != Some(&0) {
        return Err(Error::NegotiationFailure("MCS Connect-Response not rt-successful"));
    }
    let _called_connect_id = br.read_integer()?; // INTEGER
    let _domain_params = br.expect(&[0x30])?; // DomainParameters SEQUENCE
    let user_data = br.expect(&[0x04])?; // OCTET STRING userData
    Ok(user_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_initial_has_application_101_tag() {
        let ccr = crate::gcc::conference_create_request(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let pdu = connect_initial(&ccr);
        assert_eq!(&pdu[..2], &[0x7f, 0x65]); // APPLICATION 101
    }

    #[test]
    fn connect_initial_embeds_the_gcc_userdata() {
        let blocks = crate::gcc::ClientCoreData::default().encode();
        let ccr = crate::gcc::conference_create_request(&blocks);
        let pdu = connect_initial(&ccr);
        // The "Duca" key must survive inside the encoded PDU.
        assert!(pdu.windows(4).any(|w| w == b"Duca"));
    }

    #[test]
    fn connect_response_roundtrips_and_extracts_userdata() {
        // Build a Connect-Response by hand: 7F 66 { result=0, calledConnectId=0,
        // DomainParameters, userData }.
        let user_data = b"GCC-response-bytes-here".to_vec();
        let mut body = Vec::new();
        body.extend_from_slice(&ber::enumerated(0)); // rt-successful
        body.extend_from_slice(&ber::integer(0)); // calledConnectId
        body.extend_from_slice(&domain_parameters([34, 3, 0, 1, 0, 1, 0xFFFF, 2]));
        body.extend_from_slice(&ber::octet_string(&user_data));
        let pdu = ber::application(CONNECT_RESPONSE, &body);

        let extracted = parse_connect_response(&pdu).unwrap();
        assert_eq!(extracted, &user_data[..]);
    }

    #[test]
    fn connect_response_rejects_failure_result() {
        let mut body = Vec::new();
        body.extend_from_slice(&ber::enumerated(1)); // not rt-successful
        body.extend_from_slice(&ber::integer(0));
        body.extend_from_slice(&domain_parameters([34, 3, 0, 1, 0, 1, 0xFFFF, 2]));
        body.extend_from_slice(&ber::octet_string(b"x"));
        let pdu = ber::application(CONNECT_RESPONSE, &body);
        assert!(matches!(parse_connect_response(&pdu), Err(Error::NegotiationFailure(_))));
    }
}
