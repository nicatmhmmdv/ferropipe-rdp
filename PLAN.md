# ferropipe-rdp — native RDP client roadmap

A from-scratch Rust RDP client ([MS-RDPBCGR] and friends) with **no FreeRDP and no
IronRDP**. The end goal: an RDP session that Ferropipe renders in its own egui
window, carried over UDP via the sibling [`rdpeudp`](../rdpeudp) crate.

Built in phases, each wire-format unit-tested the way `rdpeudp` was. Honest
milestones are marked. A *visible desktop* first appears at Phase 4 (over TCP);
the *rdpeudp payoff* — the session actually riding UDP — is Phase 7, because the
session must exist over TCP before it can be migrated onto the UDP transport.

| Phase | Deliverable | Milestone |
|------:|-------------|-----------|
| **1** | **Connection bootstrap**: TPKT + X.224 CR/CC, RDP_NEG_REQ/RSP, TLS upgrade | secure channel to a server |
| 2 | **NLA/CredSSP**: TSRequest (ASN.1 DER), SPNEGO + NTLMv2, pubKeyAuth, TSCredentials | authenticated |
| 3 | **MCS + capabilities**: GCC Connect Initial/Response, channel join, Client Info, licensing, Demand/Confirm Active, finalization | session active |
| 4 | **Graphics (slow/fast path)**: fast-path updates, bitmap (RLE/planar) → framebuffer → egui texture | **first picture (TCP)** |
| 5 | **Input**: fast-path keyboard scancodes + mouse | interactive |
| 6 | **DRDYNVC + GFX (MS-RDPEGFX)**: dynamic vchannels, EGFX caps + surface commands, RFX-progressive / H.264 (AVC420/444) decode | modern codec path |
| 7 | **Multitransport / UDP**: Initiate Multitransport Request, open UDP via `rdpeudp` (cookieHash = SHA-256 of securityCookie), DTLS, move GFX to UDP | **session over rdpeudp** |
| 8 | **Ferropipe integration**: native RDP window replacing/augmenting the Remmina launch | shipped |

## Wire-format notes

- **TPKT** header is big-endian (RFC 1006). **X.224** is byte-oriented.
- **RDP PDUs** (negotiation, MCS user data, capabilities, PDUs) are **little-endian**.
- Security protocols requested via RDP_NEG_REQ: `SSL=0x1`, `HYBRID=0x2` (NLA),
  `RDSTLS=0x4`, `HYBRID_EX=0x8`.

## Status

- **Phase 1 framing/negotiation: done & tested** — `tpkt` (RFC 1006), `x224`
  (CR/CC/Data TPDU), `nego` (RDP_NEG_REQ/RSP/FAILURE). 11 unit tests.
- **Phase 2 NLA/CredSSP: done & tested** — `nla/` modules:
  - `crypto` (MD4/MD5/HMAC-MD5/RC4/UTF-16LE/NTOWFv2), `ntlm`
    (NEGOTIATE/CHALLENGE/AUTHENTICATE + flags + security buffers + AV_PAIRs + MIC),
    `ntlmv2` (temp → NTProofStr → NtChallengeResponse → SessionBaseKey →
    EncryptedRandomSessionKey), `sspi` (SIGNKEY/SEALKEY + RC4 handles + SEAL),
    `der` (minimal ASN.1), `credssp` (TSRequest/TSCredentials + v6 binding hashes),
    `client` (`CredSspClient` orchestrator).
  - **NTLMv2 verified byte-for-byte against the [MS-NLMP] §4.2.4 test vectors**;
    full CredSSP flow round-trips against a mock server. 31 NLA unit tests.
- **Phase 3 MCS/GCC/capabilities: done & tested** —
  - `mcs/ber` + `mcs/per` (ASN.1 primitives), `mcs/connect` (Connect
    Initial/Response), `mcs/domain` (Erect Domain / Attach User / Channel Join /
    Send Data), `gcc` (CS/SC data blocks + ConferenceCreate Req/Resp), `pdu`
    (share control/data headers + finalization), `info` (Client Info PDU), `caps`
    (capability sets + Demand/Confirm Active), `connection` (the sequence
    orchestrator over a `PduTransport` trait).
  - Full connection sequence (basic settings → channel join → client info →
    demand/confirm active → finalization) **round-trips against a mock server**.
    Domain PDU leading bytes verified against the research (`04/28/2E/38/3E/64/68`).
    Spec at `SPEC-NOTES-mcs.md`.
- **Phase 4 graphics: done & tested** — `graphics/`: `fastpath` (output PDU
  parsing), `framebuffer` (RGBA), `bitmap` (TS_BITMAP_DATA + pixel formats),
  `rle` (full interleaved-RLE decoder incl. FGBG XOR-against-prev-scanline),
  `pointer` (color/new cursor → RGBA), `update` (`Display` dispatcher: fast-path
  updates → framebuffer + cursor). Verified against the graphics research spec
  (`SPEC-NOTES-graphics.md`).
- **Phase 5 input: done & tested** — `input` (fast-path scancode/unicode/mouse
  events + input PDU assembly).
- **Phase 1 TLS transport: done** — `tls` (`TlsTransport`: X.224 negotiation, TLS
  upgrade via rustls/ring with a permissive verifier, `PduTransport` impl,
  frame-aware reads), `cert` (SubjectPublicKey extraction for NLA binding).
- **Phase 6 DRDYNVC + EGFX: done & tested** — `vchannel` (static channel
  reassembly), `dvc` (DRDYNVC), `egfx` (RDPGFX header/commands + surface store +
  UNCOMPRESSED decode). PLANAR + H.264 (AVC420/444) codecs are marked as clear
  decode boundaries (H.264 needs an external decoder; RFX/planar are follow-ups).
- **Phase 7 multitransport → rdpeudp: done & tested** — `multitransport`
  (Initiate Request/Response, cookie hash, `open_udp` opening an `rdpeudp`
  transport). **rdpeudp extended** to carry the `cookieHash` in a v3 SYNEX SYN —
  the binding that lets the session ride UDP.
- **Phase 8 integration: done** — `session` (`RdpSession`: the full connect →
  pump → send_input orchestrator composing every layer) + `examples/viewer.rs` (an
  eframe/egui window rendering the remote desktop with mouse/keyboard).
- **147 tests total (116 ferropipe-rdp + 31 rdpeudp), clippy clean.**
- Remaining for live interop (need a real server + display to exercise): the
  slow-path share-PDU handlers, EGFX PLANAR/H.264 codecs, DTLS + Tunnel Create for
  the UDP sideband, and a full scancode keymap. The wire/protocol layers for every
  phase are built and unit-tested.
