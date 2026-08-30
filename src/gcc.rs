//! GCC user-data blocks ([MS-RDPBCGR] 2.2.1.3-2.2.1.4): the client and server
//! data blocks carried inside the GCC ConferenceCreate PDUs. Each block is a
//! `TS_UD_HEADER` (type u16 LE, length u16 LE, length includes the header)
//! followed by a little-endian body.
//!
//! The GCC/T.124 PER wrapper around these blocks lives in `mcs::connect`; this
//! module is just the RDP-specific payload.

use crate::nla::crypto::unicode;
use crate::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};

// Client data block types.
pub const CS_CORE: u16 = 0xC001;
pub const CS_SECURITY: u16 = 0xC002;
pub const CS_NET: u16 = 0xC003;
pub const CS_CLUSTER: u16 = 0xC004;
// Server data block types.
pub const SC_CORE: u16 = 0x0C01;
pub const SC_SECURITY: u16 = 0x0C02;
pub const SC_NET: u16 = 0x0C03;

/// Emit a TS_UD block: type, total length (incl. 4-byte header), then body.
fn ud_block(block_type: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&block_type.to_le_bytes());
    out.extend_from_slice(&((body.len() + 4) as u16).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// Write a fixed-width UTF-16LE string field, null-padded/truncated to `bytes`.
fn utf16_fixed(s: &str, bytes: usize) -> Vec<u8> {
    let mut v = unicode(s);
    v.resize(bytes, 0);
    v
}

/// TS_UD_CS_CORE ([MS-RDPBCGR] 2.2.1.3.2).
#[derive(Clone, Debug)]
pub struct ClientCoreData {
    pub desktop_width: u16,
    pub desktop_height: u16,
    pub client_name: String,
    pub keyboard_layout: u32,
    pub client_build: u32,
    /// The protocol selected during X.224 negotiation (echoed back here).
    pub server_selected_protocol: u32,
    /// RNS_UD_CS_* early capability flags.
    pub early_capability_flags: u16,
}

impl Default for ClientCoreData {
    fn default() -> Self {
        ClientCoreData {
            desktop_width: 1024,
            desktop_height: 768,
            client_name: "FERROPIPE".to_string(),
            keyboard_layout: 0x0000_0409, // US
            client_build: 2600,
            server_selected_protocol: 0,
            // SUPPORT_ERRINFO_PDU | WANT_32BPP_SESSION | SUPPORT_STATUSINFO_PDU
            // (deliberately NOT advertising DYNVC_GFX so the server uses legacy
            // fast-path bitmap updates, which the bitmap decoder renders directly)
            early_capability_flags: 0x0001 | 0x0002 | 0x0004,
        }
    }
}

impl ClientCoreData {
    pub const VERSION_RDP5: u32 = 0x0008_0004;
    pub const COLOR_8BPP: u16 = 0xCA01;
    pub const COLOR_16BPP_565: u16 = 0xCA03;
    pub const SAS_DEL: u16 = 0xAA03;
    pub const HIGH_COLOR_24BPP: u16 = 0x0018;
    pub const SUPPORT_ALL_COLOR_DEPTHS: u16 = 0x000F;

    pub fn encode(&self) -> Vec<u8> {
        let mut b = BytesMut::new();
        b.put_u32_le(Self::VERSION_RDP5);
        b.put_u16_le(self.desktop_width);
        b.put_u16_le(self.desktop_height);
        b.put_u16_le(Self::COLOR_8BPP);
        b.put_u16_le(Self::SAS_DEL);
        b.put_u32_le(self.keyboard_layout);
        b.put_u32_le(self.client_build);
        b.extend_from_slice(&utf16_fixed(&self.client_name, 32));
        b.put_u32_le(4); // keyboardType = IBM enhanced (101/102 keys)
        b.put_u32_le(0); // keyboardSubType
        b.put_u32_le(12); // keyboardFunctionKey
        b.extend_from_slice(&[0u8; 64]); // imeFileName
        b.put_u16_le(Self::COLOR_8BPP); // postBeta2ColorDepth
        b.put_u16_le(1); // clientProductId
        b.put_u32_le(0); // serialNumber
        b.put_u16_le(Self::HIGH_COLOR_24BPP); // highColorDepth = 24bpp
        b.put_u16_le(Self::SUPPORT_ALL_COLOR_DEPTHS); // supportedColorDepths
        b.put_u16_le(self.early_capability_flags);
        b.extend_from_slice(&[0u8; 64]); // clientDigProductId
        b.put_u8(0); // connectionType
        b.put_u8(0); // pad1octet
        b.put_u32_le(self.server_selected_protocol);
        ud_block(CS_CORE, &b)
    }
}

/// TS_UD_CS_SEC ([MS-RDPBCGR] 2.2.1.3.3). Under TLS/NLA no RDP encryption is used.
pub fn client_security_data() -> Vec<u8> {
    let mut b = BytesMut::new();
    b.put_u32_le(0); // encryptionMethods = none (TLS handles confidentiality)
    b.put_u32_le(0); // extEncryptionMethods
    ud_block(CS_SECURITY, &b)
}

/// One virtual channel definition (CHANNEL_DEF): 8-byte ASCII name + options.
#[derive(Clone, Debug)]
pub struct ChannelDef {
    pub name: String,
    pub options: u32,
}

/// TS_UD_CS_NET ([MS-RDPBCGR] 2.2.1.3.4).
pub fn client_network_data(channels: &[ChannelDef]) -> Vec<u8> {
    let mut b = BytesMut::new();
    b.put_u32_le(channels.len() as u32);
    for ch in channels {
        let mut name = ch.name.clone().into_bytes();
        name.resize(8, 0);
        b.extend_from_slice(&name[..8]);
        b.put_u32_le(ch.options);
    }
    ud_block(CS_NET, &b)
}

/// Client multitransport data block type.
pub const CS_MULTITRANSPORT: u16 = 0xC00A;

/// TS_UD_CS_MULTITRANSPORTCHANNELDATA ([MS-RDPBCGR] 2.2.1.3.8): advertise UDP
/// multitransport support so the server may offer to migrate onto UDP/rdpeudp.
pub fn client_multitransport_data(flags: u32) -> Vec<u8> {
    let mut b = BytesMut::new();
    b.put_u32_le(flags);
    ud_block(CS_MULTITRANSPORT, &b)
}

/// TS_UD_CS_CLUSTER ([MS-RDPBCGR] 2.2.1.3.5).
pub fn client_cluster_data() -> Vec<u8> {
    let mut b = BytesMut::new();
    // REDIRECTION_SUPPORTED | ServerSessionRedirectionVersion = 4.
    b.put_u32_le(0x0000_000D);
    b.put_u32_le(0); // RedirectedSessionID
    ud_block(CS_CLUSTER, &b)
}

/// The invariant T.124 ConnectData prefix: Key = OID {0 0 20 124 0 1}.
const GCC_CONNECT_DATA_PREFIX: [u8; 7] = [0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01];
/// Client H.221 non-standard key.
const H221_CLIENT_KEY: [u8; 4] = *b"Duca";
/// Server H.221 non-standard key.
const H221_SERVER_KEY: [u8; 4] = *b"McDn";

/// Wrap concatenated client `data_blocks` in a GCC ConferenceCreateRequest
/// ([MS-RDPBCGR] 2.2.1.3.1). The result becomes the MCS Connect-Initial userData.
pub fn conference_create_request(data_blocks: &[u8]) -> Vec<u8> {
    use crate::mcs::per;
    use bytes::BytesMut;

    // ConnectGCCPDU: CCR choice(0), preamble, conferenceName "1", pad, userData
    // SET-OF count(1), UserData member (value present + h221 key), "Duca",
    // then the PER-length-prefixed data blocks.
    let mut gcc = BytesMut::new();
    gcc.extend_from_slice(&[0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00]);
    gcc.extend_from_slice(&H221_CLIENT_KEY);
    per::write_length(&mut gcc, data_blocks.len());
    gcc.extend_from_slice(data_blocks);

    let mut out = BytesMut::new();
    out.extend_from_slice(&GCC_CONNECT_DATA_PREFIX);
    per::write_length(&mut out, gcc.len());
    out.extend_from_slice(&gcc);
    out.to_vec()
}

/// Extract the concatenated server data blocks from a GCC ConferenceCreateResponse
/// ([MS-RDPBCGR] 2.2.1.4.1) by locating the "McDn" key and its PER length.
pub fn parse_conference_create_response(gcc: &[u8]) -> Result<&[u8]> {
    use crate::mcs::per;
    let pos = gcc
        .windows(4)
        .position(|w| w == H221_SERVER_KEY)
        .ok_or(Error::Protocol("GCC response missing McDn key"))?;
    let mut rest = &gcc[pos + 4..];
    let len = per::read_length(&mut rest)?;
    if rest.len() < len {
        return Err(Error::Short { need: len, have: rest.len() });
    }
    Ok(&rest[..len])
}

/// Parsed TS_UD_SC_NET ([MS-RDPBCGR] 2.2.1.4.4): the I/O channel plus any joined
/// virtual-channel IDs the server assigned, in request order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerNetworkData {
    pub io_channel_id: u16,
    pub channel_ids: Vec<u16>,
}

/// Walk the concatenated server data blocks and extract SC_NET.
pub fn parse_server_network_data(server_user_data: &[u8]) -> Result<ServerNetworkData> {
    let mut buf = server_user_data;
    while buf.len() >= 4 {
        let block_type = u16::from_le_bytes([buf[0], buf[1]]);
        let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
        if len < 4 || buf.len() < len {
            return Err(Error::Protocol("bad SC data block length"));
        }
        let body = &buf[4..len];
        if block_type == SC_NET {
            let mut b = body;
            if b.len() < 4 {
                return Err(Error::Short { need: 4, have: b.len() });
            }
            let io_channel_id = b.get_u16_le();
            let count = b.get_u16_le() as usize;
            let mut channel_ids = Vec::with_capacity(count);
            for _ in 0..count {
                if b.len() < 2 {
                    return Err(Error::Short { need: 2, have: b.len() });
                }
                channel_ids.push(b.get_u16_le());
            }
            return Ok(ServerNetworkData { io_channel_id, channel_ids });
        }
        buf = &buf[len..];
    }
    Err(Error::Protocol("SC_NET block not found"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cs_core_has_ud_header_and_selected_protocol() {
        let core = ClientCoreData { server_selected_protocol: 0x02, ..Default::default() };
        let enc = core.encode();
        assert_eq!(u16::from_le_bytes([enc[0], enc[1]]), CS_CORE);
        assert_eq!(u16::from_le_bytes([enc[2], enc[3]]) as usize, enc.len());
        // version is the first body field.
        assert_eq!(u32::from_le_bytes([enc[4], enc[5], enc[6], enc[7]]), ClientCoreData::VERSION_RDP5);
    }

    #[test]
    fn cs_net_lists_channels() {
        let chans = [
            ChannelDef { name: "rdpdr".into(), options: 0x8000_0000 },
            ChannelDef { name: "cliprdr".into(), options: 0xC000_0000 },
        ];
        let enc = client_network_data(&chans);
        assert_eq!(u16::from_le_bytes([enc[0], enc[1]]), CS_NET);
        assert_eq!(u32::from_le_bytes([enc[4], enc[5], enc[6], enc[7]]), 2);
    }

    #[test]
    fn parse_sc_net_extracts_channel_ids() {
        // Build a fake SC_NET block: io channel 1003, two vchannels 1004, 1005.
        let mut body = BytesMut::new();
        body.put_u16_le(1003);
        body.put_u16_le(2);
        body.put_u16_le(1004);
        body.put_u16_le(1005);
        let block = ud_block(SC_NET, &body);
        let parsed = parse_server_network_data(&block).unwrap();
        assert_eq!(parsed.io_channel_id, 1003);
        assert_eq!(parsed.channel_ids, vec![1004, 1005]);
    }

    #[test]
    fn parse_sc_net_skips_other_blocks() {
        let core = ud_block(SC_CORE, &[0, 0, 8, 0]);
        let mut netbody = BytesMut::new();
        netbody.put_u16_le(1003);
        netbody.put_u16_le(0);
        let net = ud_block(SC_NET, &netbody);
        let combined = [core, net].concat();
        let parsed = parse_server_network_data(&combined).unwrap();
        assert_eq!(parsed.io_channel_id, 1003);
        assert!(parsed.channel_ids.is_empty());
    }
}
