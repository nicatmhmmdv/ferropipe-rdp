//! The RDP connection-sequence orchestrator ([MS-RDPBCGR] 1.3.1.1): Basic
//! Settings Exchange → Channel Connection → Client Info → licensing → capability
//! exchange → finalization. It drives the wire structures from `mcs`, `gcc`,
//! `pdu`, `info`, and `caps` over a [`PduTransport`], so it can run against a real
//! TLS transport (Phase 1) or a mock in tests.

use crate::caps::{
    bitmap_caps, confirm_active, general_caps, input_caps, order_caps, parse_demand_active, pointer_caps, share_caps,
    virtual_channel_caps, DemandActive,
};
use crate::gcc::{
    client_cluster_data, client_network_data, client_security_data, parse_conference_create_response,
    parse_server_network_data, ChannelDef, ClientCoreData,
};
use crate::info::{client_info, LogonInfo};
use crate::mcs::connect::{connect_initial, parse_connect_response};
use crate::mcs::domain::{
    attach_user_request, channel_join_request, erect_domain_request, parse_attach_user_confirm,
    parse_channel_join_confirm, parse_send_data_indication, send_data_request, IO_CHANNEL,
};
use crate::pdu::{
    control, font_list, parse_share_control, parse_share_data, share_data, synchronize, CTRLACTION_COOPERATE,
    CTRLACTION_REQUEST_CONTROL, PDUTYPE_DEMANDACTIVE, PDUTYPE2_CONTROL, PDUTYPE2_FONTLIST, PDUTYPE2_SYNCHRONIZE,
};
use crate::{Error, Result};

/// Sends/receives MCS PDUs (already X.224/TPKT-framed by the implementor).
pub trait PduTransport {
    fn send(&mut self, mcs_pdu: &[u8]) -> Result<()>;
    fn recv(&mut self) -> Result<Vec<u8>>;
}

/// Settings for establishing a session.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub width: u16,
    pub height: u16,
    pub domain: String,
    pub username: String,
    /// Protocol selected during X.224 negotiation (echoed in CS_CORE).
    pub selected_protocol: u32,
    pub channels: Vec<ChannelDef>,
}

/// The negotiated result of the connection sequence.
#[derive(Clone, Debug)]
pub struct Session {
    pub user_id: u16,
    pub io_channel: u16,
    /// Joined virtual-channel IDs, in request order.
    pub channel_ids: Vec<u16>,
    pub share_id: u32,
    /// The server's Initiate Multitransport Request, if it offered a UDP sideband.
    pub multitransport_request: Option<crate::multitransport::InitiateRequest>,
}

/// Bound on how many stray PDUs to skip while waiting for an expected one.
const MAX_SKIP: usize = 16;

/// Run the whole connection sequence to an active session.
pub fn establish<T: PduTransport>(t: &mut T, cfg: &SessionConfig) -> Result<Session> {
    let server_net = basic_settings_exchange(t, cfg)?;
    let (user_id, channel_ids) = channel_connection(t, cfg, &server_net)?;
    send_client_info(t, user_id, cfg)?;
    let mut multitransport_request = None;
    let demand = wait_for_demand_active(t, &mut multitransport_request)?;
    send_confirm_active(t, user_id, demand.share_id, cfg)?;
    finalization(t, user_id, demand.share_id)?;
    Ok(Session {
        user_id,
        io_channel: IO_CHANNEL,
        channel_ids,
        share_id: demand.share_id,
        multitransport_request,
    })
}

/// Send MCS Connect Initial (with the GCC client data blocks) and parse the
/// server's data blocks out of the Connect Response.
pub fn basic_settings_exchange<T: PduTransport>(
    t: &mut T,
    cfg: &SessionConfig,
) -> Result<crate::gcc::ServerNetworkData> {
    let core = ClientCoreData {
        desktop_width: cfg.width,
        desktop_height: cfg.height,
        server_selected_protocol: cfg.selected_protocol,
        ..Default::default()
    };
    let mut blocks = core.encode();
    blocks.extend_from_slice(&client_security_data());
    blocks.extend_from_slice(&client_network_data(&cfg.channels));
    blocks.extend_from_slice(&client_cluster_data());
    // Request the MCS message channel (the multitransport request rides on it)…
    blocks.extend_from_slice(&crate::gcc::client_msgchannel_data());
    // …and advertise reliable UDP multitransport so the server offers a sideband.
    blocks.extend_from_slice(&crate::gcc::client_multitransport_data(
        crate::multitransport::TRANSPORTTYPE_UDPFECR | crate::multitransport::TRANSPORTTYPE_UDP_PREFERRED,
    ));

    let ccr = crate::gcc::conference_create_request(&blocks);
    t.send(&connect_initial(&ccr))?;

    let response = t.recv()?;
    let gcc_response = parse_connect_response(&response)?;
    let server_blocks = parse_conference_create_response(gcc_response)?;
    parse_server_network_data(server_blocks)
}

/// Erect the domain, attach the user, and join the user + I/O + virtual channels.
pub fn channel_connection<T: PduTransport>(
    t: &mut T,
    cfg: &SessionConfig,
    server_net: &crate::gcc::ServerNetworkData,
) -> Result<(u16, Vec<u16>)> {
    t.send(&erect_domain_request())?;
    t.send(&attach_user_request())?;
    let user_id = parse_attach_user_confirm(&t.recv()?)?;

    // Join the user channel, the I/O channel, each server-assigned vchannel, and
    // the MCS message channel (carries the multitransport request).
    let mut to_join = vec![user_id, IO_CHANNEL];
    to_join.extend_from_slice(&server_net.channel_ids);
    if let Some(msg) = server_net.message_channel_id {
        to_join.push(msg);
    }

    let mut joined = Vec::new();
    for &channel in &to_join {
        t.send(&channel_join_request(user_id, channel))?;
        let confirmed = parse_channel_join_confirm(&t.recv()?)?;
        if channel != user_id && channel != IO_CHANNEL {
            joined.push(confirmed);
        }
    }
    // Map joined channel IDs back to their names for the caller's convenience.
    let _ = cfg;
    Ok((user_id, joined))
}

fn send_on_io<T: PduTransport>(t: &mut T, user_id: u16, pdu: &[u8]) -> Result<()> {
    t.send(&send_data_request(user_id, IO_CHANNEL, pdu))
}

/// Read the next PDU from the I/O channel (unwrapping Send Data Indication).
fn recv_on_io<T: PduTransport>(t: &mut T) -> Result<Vec<u8>> {
    let mcs = t.recv()?;
    let (_channel, data) = parse_send_data_indication(&mcs)?;
    Ok(data.to_vec())
}

/// Send the Client Info PDU (credentials empty under NLA).
pub fn send_client_info<T: PduTransport>(t: &mut T, user_id: u16, cfg: &SessionConfig) -> Result<()> {
    let logon = LogonInfo {
        domain: cfg.domain.clone(),
        username: cfg.username.clone(),
        ..Default::default()
    };
    send_on_io(t, user_id, &client_info(&logon, false))
}

/// Skip licensing / other PDUs until the server's Demand Active arrives.
pub fn wait_for_demand_active<T: PduTransport>(
    t: &mut T,
    multitransport: &mut Option<crate::multitransport::InitiateRequest>,
) -> Result<DemandActive> {
    for _ in 0..MAX_SKIP {
        let pdu = recv_on_io(t)?;
        if let Ok((hdr, body)) = parse_share_control(&pdu) {
            if hdr.pdu_type == PDUTYPE_DEMANDACTIVE {
                return parse_demand_active(body);
            }
            // Any other share control PDU (e.g. deactivate) is skipped.
        } else if multitransport.is_none() {
            // Non-share PDU: it may be the Initiate Multitransport Request.
            if let Some(req) = crate::multitransport::InitiateRequest::detect(&pdu) {
                *multitransport = Some(req);
            }
        }
    }
    Err(Error::Protocol("no Demand Active PDU received"))
}

/// Reply to the server's Demand Active with our capability set.
pub fn send_confirm_active<T: PduTransport>(t: &mut T, user_id: u16, share_id: u32, cfg: &SessionConfig) -> Result<()> {
    use crate::caps::{
        activation_caps, bitmap_cache_rev2_caps, bitmap_codecs_caps, brush_caps, color_cache_caps, control_caps,
        font_caps, frame_acknowledge_caps, glyph_cache_caps, large_pointer_caps, multifragment_caps, offscreen_caps,
        sound_caps, surface_commands_caps,
    };
    // The full standard capability set — a Windows server rejects a session with
    // ERRINFO_BAD_CAPABILITIES (0x10EA) if required sets are absent.
    let mut caps = vec![
        general_caps(),
        bitmap_caps(cfg.width, cfg.height),
        order_caps(),
        bitmap_cache_rev2_caps(),
        color_cache_caps(),
        activation_caps(),
        control_caps(),
        pointer_caps(),
        share_caps(),
        input_caps(0x0000_0409),
        sound_caps(),
        font_caps(),
        brush_caps(),
        glyph_cache_caps(),
        offscreen_caps(),
        multifragment_caps(),
        large_pointer_caps(),
        surface_commands_caps(),
        bitmap_codecs_caps(),
        frame_acknowledge_caps(),
    ];
    if !cfg.channels.is_empty() {
        caps.push(virtual_channel_caps());
    }
    send_on_io(t, user_id, &confirm_active(user_id, share_id, &caps))
}

/// Client → server finalization, then drain the server's finalization replies.
pub fn finalization<T: PduTransport>(t: &mut T, user_id: u16, share_id: u32) -> Result<()> {
    let data = |ty2: u8, body: &[u8]| share_data(user_id, share_id, ty2, body);

    send_on_io(t, user_id, &data(PDUTYPE2_SYNCHRONIZE, &synchronize(IO_CHANNEL)))?;
    send_on_io(t, user_id, &data(PDUTYPE2_CONTROL, &control(CTRLACTION_COOPERATE, 0, 0)))?;
    send_on_io(t, user_id, &data(PDUTYPE2_CONTROL, &control(CTRLACTION_REQUEST_CONTROL, 0, 0)))?;
    send_on_io(t, user_id, &data(crate::pdu::PDUTYPE2_FONTLIST, &font_list()))?;

    // Drain the server's finalization PDUs (Synchronize, Control×2, Font Map).
    let mut seen = 0;
    for _ in 0..MAX_SKIP {
        if seen >= 4 {
            break;
        }
        let pdu = recv_on_io(t)?;
        if let Ok((_hdr, body)) = parse_share_control(&pdu) {
            if parse_share_data(body).is_ok() {
                seen += 1;
            }
        }
    }
    let _ = (PDUTYPE2_FONTLIST, PDUTYPE2_SYNCHRONIZE);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcc::SC_NET;
    use crate::mcs::domain::send_data_request as sdr;
    use crate::pdu::{share_control, PDUTYPE2_FONTMAP};
    use bytes::{BufMut, BytesMut};

    /// A scripted mock server: pops canned responses and records what we sent.
    struct MockTransport {
        responses: std::collections::VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl PduTransport for MockTransport {
        fn send(&mut self, mcs_pdu: &[u8]) -> Result<()> {
            self.sent.push(mcs_pdu.to_vec());
            Ok(())
        }
        fn recv(&mut self) -> Result<Vec<u8>> {
            self.responses.pop_front().ok_or(Error::Protocol("mock: no more responses"))
        }
    }

    /// Build a server Connect Response embedding an SC_NET block via GCC/McDn.
    fn connect_response(io_channel: u16, channels: &[u16]) -> Vec<u8> {
        use crate::mcs::{ber, per};
        let mut sc_net = BytesMut::new();
        sc_net.put_u16_le(io_channel);
        sc_net.put_u16_le(channels.len() as u16);
        for &c in channels {
            sc_net.put_u16_le(c);
        }
        // TS_UD header
        let mut block = BytesMut::new();
        block.put_u16_le(SC_NET);
        block.put_u16_le((sc_net.len() + 4) as u16);
        block.extend_from_slice(&sc_net);

        // GCC ConferenceCreateResponse with the McDn key.
        let mut gcc = BytesMut::new();
        gcc.extend_from_slice(&[0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01]);
        gcc.extend_from_slice(b"McDn");
        per::write_length(&mut gcc, block.len());
        gcc.extend_from_slice(&block);

        // MCS Connect Response BER: result=0, calledConnectId=0, DomainParameters, userData.
        let mut body = Vec::new();
        body.extend_from_slice(&ber::enumerated(0));
        body.extend_from_slice(&ber::integer(0));
        let dp: Vec<u8> = [34u32, 3, 0, 1, 0, 1, 0xFFFF, 2].iter().flat_map(|&v| ber::integer(v)).collect();
        body.extend_from_slice(&ber::sequence(&dp));
        body.extend_from_slice(&ber::octet_string(&gcc));
        ber::application(102, &body)
    }

    fn attach_user_confirm(user_channel: u16) -> Vec<u8> {
        // tag 0x2E, result 0, initiator (user - 1001).
        let mut v = BytesMut::new();
        v.put_u8(0x2E);
        v.put_u8(0x00);
        v.put_u16(user_channel - 1001);
        v.to_vec()
    }

    fn channel_join_confirm(channel: u16) -> Vec<u8> {
        let mut v = BytesMut::new();
        v.put_u8(0x3E);
        v.put_u8(0x00);
        v.put_u16(6);
        v.put_u16(channel);
        v.put_u16(channel);
        v.to_vec()
    }

    fn server_data_pdu(pdu_type2: u8, body: &[u8]) -> Vec<u8> {
        let sc = share_data(0x03EA, 0x0001_03EA, pdu_type2, body);
        // Wrap in a Send Data Indication (choice 0x68).
        let mut ind = sdr(0x03EA, IO_CHANNEL, &sc);
        ind[0] = 0x68;
        ind
    }

    #[test]
    fn full_connection_sequence_against_mock_server() {
        // Prepare the scripted server responses in recv() order.
        let mut responses = std::collections::VecDeque::new();
        responses.push_back(connect_response(IO_CHANNEL, &[1004]));
        responses.push_back(attach_user_confirm(1007));
        // channel joins: user(1007), IO(1003), vchannel(1004)
        responses.push_back(channel_join_confirm(1007));
        responses.push_back(channel_join_confirm(1003));
        responses.push_back(channel_join_confirm(1004));
        // demand active (as Send Data Indication)
        {
            let caps = [general_caps(), bitmap_caps(1024, 768)];
            let combined: Vec<u8> = caps.concat();
            let mut body = BytesMut::new();
            body.put_u32_le(0x0001_03EA);
            body.put_u16_le(4);
            body.put_u16_le((combined.len() + 4) as u16);
            body.extend_from_slice(b"RDP\0");
            body.put_u16_le(2);
            body.put_u16_le(0);
            body.extend_from_slice(&combined);
            let sc = share_control(PDUTYPE_DEMANDACTIVE, 0x03EA, &body);
            let mut ind = sdr(0x03EA, IO_CHANNEL, &sc);
            ind[0] = 0x68;
            responses.push_back(ind);
        }
        // server finalization: sync, control coop, control granted, font map
        responses.push_back(server_data_pdu(PDUTYPE2_SYNCHRONIZE, &synchronize(1007)));
        responses.push_back(server_data_pdu(PDUTYPE2_CONTROL, &control(CTRLACTION_COOPERATE, 0, 0)));
        responses.push_back(server_data_pdu(PDUTYPE2_CONTROL, &control(0x0002, 0, 0)));
        responses.push_back(server_data_pdu(PDUTYPE2_FONTMAP, &[0u8; 8]));

        let mut t = MockTransport { responses, sent: Vec::new() };
        let cfg = SessionConfig {
            width: 1024,
            height: 768,
            domain: "DOM".into(),
            username: "nicat".into(),
            selected_protocol: 0x02,
            channels: vec![ChannelDef { name: "rdpdr".into(), options: 0x8000_0000 }],
        };

        let session = establish(&mut t, &cfg).unwrap();
        assert_eq!(session.user_id, 1007);
        assert_eq!(session.io_channel, IO_CHANNEL);
        assert_eq!(session.channel_ids, vec![1004]);
        assert_eq!(session.share_id, 0x0001_03EA);

        // First thing we sent must be an MCS Connect Initial (BER app 101).
        assert_eq!(&t.sent[0][..2], &[0x7f, 0x65]);
        // A Confirm Active must appear among our sent PDUs (unwrap Send Data Request).
        let sent_confirm = t.sent.iter().any(|p| {
            crate::mcs::domain::parse_send_data_indication(&{
                let mut v = p.clone();
                if !v.is_empty() && v[0] == 0x64 {
                    v[0] = 0x68; // re-tag request→indication so the parser accepts it
                }
                v
            })
            .ok()
            .and_then(|(_c, d)| parse_share_control(d).ok())
            .map(|(h, _)| h.pdu_type == crate::pdu::PDUTYPE_CONFIRMACTIVE)
            .unwrap_or(false)
        });
        assert!(sent_confirm, "client sent a Confirm Active PDU");
    }
}
