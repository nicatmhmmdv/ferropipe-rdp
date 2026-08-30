//! Client Info PDU ([MS-RDPBCGR] 2.2.1.11) — sent after channel join to carry
//! logon settings. Under NLA the password is empty (credentials already went via
//! CredSSP). Preceded by a Basic Security Header with the SEC_INFO_PKT flag.

use crate::nla::crypto::unicode;
use bytes::{BufMut, BytesMut};

/// Basic Security Header flag: this PDU is a Client Info PDU.
pub const SEC_INFO_PKT: u16 = 0x0040;

/// TS_INFO_PACKET flags ([MS-RDPBCGR] 2.2.1.11.1.1.1).
pub const INFO_MOUSE: u32 = 0x0000_0001;
pub const INFO_DISABLECTRLALTDEL: u32 = 0x0000_0002;
pub const INFO_AUTOLOGON: u32 = 0x0000_0008;
pub const INFO_UNICODE: u32 = 0x0000_0010;
pub const INFO_MAXIMIZESHELL: u32 = 0x0000_0020;
pub const INFO_ENABLEWINDOWSKEY: u32 = 0x0000_0100;
pub const INFO_COMPRESSION: u32 = 0x0000_0080;

/// Size of the TS_TIME_ZONE_INFORMATION structure.
const TIMEZONE_LEN: usize = 172;

/// Logon settings for the Client Info PDU.
#[derive(Clone, Debug, Default)]
pub struct LogonInfo {
    pub domain: String,
    pub username: String,
    /// Empty under NLA (credentials already delivered via CredSSP).
    pub password: String,
    pub alternate_shell: String,
    pub working_dir: String,
}

/// A UTF-16LE string plus its 2-byte null terminator.
fn utf16_z(s: &str) -> Vec<u8> {
    let mut v = unicode(s);
    v.push(0);
    v.push(0);
    v
}

/// Build the Client Info PDU body: Basic Security Header + TS_INFO_PACKET.
/// (Wrap the result in MCS Send Data → X.224 → TPKT to send.)
pub fn client_info(info: &LogonInfo, autologon: bool) -> Vec<u8> {
    let mut flags = INFO_MOUSE | INFO_DISABLECTRLALTDEL | INFO_UNICODE | INFO_MAXIMIZESHELL | INFO_ENABLEWINDOWSKEY;
    if autologon && !info.password.is_empty() {
        flags |= INFO_AUTOLOGON;
    }

    let domain = utf16_z(&info.domain);
    let username = utf16_z(&info.username);
    let password = utf16_z(&info.password);
    let shell = utf16_z(&info.alternate_shell);
    let workdir = utf16_z(&info.working_dir);

    // cb* fields are byte lengths EXCLUDING the null terminator.
    let cb = |field: &[u8]| (field.len() - 2) as u16;

    let mut b = BytesMut::new();
    // Basic Security Header.
    b.put_u16_le(SEC_INFO_PKT); // flags
    b.put_u16_le(0); // flagsHi

    // TS_INFO_PACKET.
    b.put_u32_le(0); // CodePage
    b.put_u32_le(flags);
    b.put_u16_le(cb(&domain));
    b.put_u16_le(cb(&username));
    b.put_u16_le(cb(&password));
    b.put_u16_le(cb(&shell));
    b.put_u16_le(cb(&workdir));
    b.extend_from_slice(&domain);
    b.extend_from_slice(&username);
    b.extend_from_slice(&password);
    b.extend_from_slice(&shell);
    b.extend_from_slice(&workdir);

    // TS_EXTENDED_INFO_PACKET (RDP5+).
    b.put_u16_le(2); // clientAddressFamily = AF_INET
    let addr = utf16_z("0.0.0.0");
    b.put_u16_le(addr.len() as u16); // cbClientAddress (includes null)
    b.extend_from_slice(&addr);
    let dir = utf16_z("");
    b.put_u16_le(dir.len() as u16); // cbClientDir (includes null)
    b.extend_from_slice(&dir);
    b.extend_from_slice(&[0u8; TIMEZONE_LEN]); // clientTimeZone
    b.put_u32_le(0); // clientSessionId
    b.put_u32_le(0); // performanceFlags
    b.put_u16_le(0); // cbAutoReconnectCookie

    b.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_info_starts_with_security_header() {
        let info = LogonInfo { domain: "DOM".into(), username: "nicat".into(), ..Default::default() };
        let pdu = client_info(&info, false);
        assert_eq!(u16::from_le_bytes([pdu[0], pdu[1]]), SEC_INFO_PKT);
        assert_eq!(u16::from_le_bytes([pdu[2], pdu[3]]), 0); // flagsHi
    }

    #[test]
    fn cb_fields_exclude_null_terminator() {
        let info = LogonInfo { username: "ab".into(), ..Default::default() };
        let pdu = client_info(&info, false);
        // Layout after security header (4) + CodePage(4) + flags(4) = offset 12:
        // cbDomain(2) cbUserName(2) ...
        let cb_domain = u16::from_le_bytes([pdu[12], pdu[13]]);
        let cb_username = u16::from_le_bytes([pdu[14], pdu[15]]);
        assert_eq!(cb_domain, 0); // empty domain
        assert_eq!(cb_username, 4); // "ab" = 2 UTF-16 chars = 4 bytes, no null
    }

    #[test]
    fn autologon_flag_only_with_password() {
        let with_pw = LogonInfo { username: "u".into(), password: "p".into(), ..Default::default() };
        let pdu = client_info(&with_pw, true);
        let flags = u32::from_le_bytes([pdu[8], pdu[9], pdu[10], pdu[11]]);
        assert!(flags & INFO_AUTOLOGON != 0);

        let no_pw = LogonInfo { username: "u".into(), ..Default::default() };
        let pdu = client_info(&no_pw, true);
        let flags = u32::from_le_bytes([pdu[8], pdu[9], pdu[10], pdu[11]]);
        assert!(flags & INFO_AUTOLOGON == 0);
    }
}
