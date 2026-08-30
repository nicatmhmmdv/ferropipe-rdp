# Native Rust RDP Client — Phase 6 (DRDYNVC + EGFX) & Phase 7 (Multitransport/UDP) Implementation Reference

This document is the merged wire-format reference for the dynamic virtual channel layer, the graphics pipeline that rides on it, and the UDP sideband bootstrap. All multi-byte integers are **little-endian** unless a field is explicitly called out as network byte order. Every constant and hex example from the source research is preserved.

---

## Part 1 — [MS-RDPEDYC] DRDYNVC: Dynamic Virtual Channel wire layouts

### 1.1 How DRDYNVC rides the static "drdynvc" virtual channel

DRDYNVC is the payload of a **static** virtual channel named **"drdynvc"**, opened at connect time via the [MS-RDPBCGR] Channel Definition / Virtual Channel Capability Set. Full stack, outermost to innermost:

```
TPKT / X.224            ([MS-RDPBCGR] / [T123]/[T125])
  MCS SendDataRequest/Indication  (channel = the drdynvc static channel's MCS channel id)
    CHANNEL_PDU_HEADER  ([MS-RDPBCGR] §2.2.6.1.1)   <-- 8 bytes
      DVC PDU bytes     ([MS-RDPEDYC] §2.2.*)       <-- the header byte + id + payload
```

**CHANNEL_PDU_HEADER ([MS-RDPBCGR] §2.2.6.1.1) — 8 bytes:**

```
Offset  Size  Field
0       4     length  (UINT32 LE): total uncompressed length of the ENTIRE static-channel
                      message being reassembled (may span multiple CHANNEL_PDUs)
4       4     flags   (UINT32 LE): bitfield
```

Relevant `flags` bits:
- `CHANNEL_FLAG_FIRST  = 0x00000001` — first chunk of a static-channel message.
- `CHANNEL_FLAG_LAST   = 0x00000002` — last chunk. A message that fits in one chunk sets BOTH (`0x00000003`).
- `CHANNEL_FLAG_SHOW_PROTOCOL = 0x00000010`, plus `CHANNEL_PACKET_COMPRESSED (0x00200000)` and CompressionType bits when static-channel compression is in use.

There are **two independent, nested fragmentation/reassembly layers**:
- **Outer** — the static VC layer chops a large drdynvc payload into ~1600-byte (VCChunkSize) chunks, each with its own CHANNEL_PDU_HEADER and FIRST/LAST flags; the `length` field is the total drdynvc-payload size.
- **Inner** — the DVC layer's own DATA_FIRST/DATA fragmentation (§1.6), whose `Length` is the total DVC-message size. These operate at different granularities; a single DVC DATA PDU is one static-channel message that may itself be re-chunked by the outer layer.

### 1.2 The DVC PDU header first byte (§2.2.1)

Every DVC PDU begins with an 8-bit header byte. Bit numbering in [MS-RDPEDYC] is MSB-first.

```
 7 6 5 4 3 2 1 0   (MS numbers left→right as 0..7, so 0..3 = high nibble)
+-------+---+-----+
|  Cmd  |Sp |cbId |
+-------+---+-----+
```

- **Cmd** — high 4 bits, mask `0xF0`, value = `byte >> 4`. Command code.
- **Sp** — bits 4..5 (2 bits, mask `0x0C`). "Spare"/reuse field; meaning depends on Cmd. Unused/MUST be 0 for most PDUs; in **Data First** it carries the `Len` length-selector.
- **cbChId (cbId)** — low 2 bits, mask `0x03`. Byte-width selector for the ChannelId field that follows (§1.5).

Cmd values (§2.2.1):

| Cmd name | Value | High-nibble byte pattern |
|---|---|---|
| CREATE_EVENT (Create Request/Response) | 0x01 | `0x1_` |
| DATA_FIRST | 0x02 | `0x2_` |
| DATA | 0x03 | `0x3_` |
| CLOSE_EVENT (Close Request/Response) | 0x04 | `0x4_` |
| CAPABILITY (Capabilities Request/Response) | 0x05 | `0x5_` |
| DATA_FIRST_COMPRESSED | 0x06 | `0x6_` |
| DATA_COMPRESSED | 0x07 | `0x7_` |
| SOFT_SYNC_REQUEST | 0x08 | `0x8_` |
| SOFT_SYNC_RESPONSE | 0x09 | `0x9_` |

**Quick decode recipe for any DVC first byte:**
```
Cmd    = b >> 4            // 1..9 per table
lenSel = (b >> 2) & 0x03   // meaningful for DATA_FIRST*: width of Length
cbChId = b & 0x03          // 0->1B, 1->2B, 2->4B channel id width
```
Header byte quick reference: CREATE=`0x1X`, DATA_FIRST=`0x2X`, DATA=`0x3X`, CLOSE=`0x4X`, CAPABILITY=`0x5X` (`0x50`), DATA_FIRST_COMPRESSED=`0x6X`, DATA_COMPRESSED=`0x7X`, SOFT_SYNC_REQ=`0x8X`, SOFT_SYNC_RESP=`0x9X`.

### 1.3 Capabilities PDUs (§2.2.2.1 / §2.2.2.2 / §2.2.2.3)

**Capabilities Request PDU (DVC server → client)** — advertises the highest supported version:

```
Offset  Size  Field
0       1     first byte = 0x50   (Cmd=CAPABILITY=5, Sp=0, cbId=0)
1       1     Pad             = 0x00
2       2     Version         (UINT16 LE): 0x0001, 0x0002, or 0x0003
--- Version 2 and 3 only: ---
4       2     PriorityCharge0 (UINT16 LE)
6       2     PriorityCharge1 (UINT16 LE)
8       2     PriorityCharge2 (UINT16 LE)
10      2     PriorityCharge3 (UINT16 LE)
```

- Version 1: 4 bytes total (`50 00 01 00`).
- Version 2 / 3: 12 bytes total. Version 3 uses the same wire format as Version 2 (Version = `0x0003`); the difference is Version 3 enables Soft-Sync.

Example Capabilities Request, Version 3:
```
50 00 03 00 <pc0 LE> <pc1 LE> <pc2 LE> <pc3 LE>
```

**Capabilities Response PDU (DVC client → server)** — §2.2.2.2:

```
Offset  Size  Field
0       1     first byte = 0x50   (Cmd=CAPABILITY=5, cbId=0, Sp=0)
1       1     Pad         = 0x00
2       2     Version     (UINT16 LE) = version the client selects (<= server's)
```

Total 4 bytes, e.g. `50 00 02 00` selects Version 2. The response never carries PriorityCharge fields. In caps PDUs the byte after Cmd is a dedicated `Pad` (0x00) — there is no ChannelId, so the first byte is always `0x50`.

### 1.4 Create Request / Response PDU (§2.2.2.1 / §2.2.2.2)

**Create Request PDU (server → client)** — opens a dynamic channel:

```
Offset  Size            Field
0       1               Header byte: Cmd=CREATE(1)<<4 | Sp | cbChId
1       1/2/4           ChannelId  (width per cbChId, UINT LE)
1+w     variable        ChannelName: null-terminated ASCII string (includes the 0x00)
```

No length field for the name — it is a C-style NUL-terminated ANSI/ASCII string that runs to the 0x00, bounded by the outer CHANNEL_PDU length. Header byte with cbChId=0: `0x10`; cbChId=1: `0x11`; cbChId=2: `0x12`.

Example — create channel id 3, name "ECHO":
```
10 03 45 43 48 4F 00
│  │  └──────────────┘ "ECHO\0"  (45='E' 43='C' 48='H' 4F='O' 00=NUL)
│  └ ChannelId = 0x03 (1 byte, cbChId=0)
└ 0x10 = Cmd 1 (CREATE), cbChId 0
```

Example — 2-byte channel id 0x0102, name "AB":
```
11 02 01 41 42 00
│  └──┘ id 0x0102 LE
└ 0x11 = CREATE, cbChId=1 (2-byte id)
```

**Create Response PDU (client → server)** — §2.2.2.2:

```
Offset  Size            Field
0       1               Header byte: Cmd=CREATE(1)<<4 | Sp | cbChId (same width as request)
1       1/2/4           ChannelId  (echoes the request's id, same width)
1+w     4               CreationStatus (INT32 LE) — 0x00000000 = success (S_OK);
                        negative NTSTATUS/HRESULT = failure/rejected
```

Example — accept channel id 3:
```
10 03 00 00 00 00
│  │  └─────────┘ CreationStatus = 0 (success)
│  └ ChannelId 0x03
└ 0x10 = CREATE, cbChId 0
```
On a nonzero (negative) CreationStatus the server closes the channel.

### 1.5 channelId length encoding — cbChId (§2.2.1, §3.1.5.1)

| cbChId | ChannelId width | Range |
|---|---|---|
| 0 | 1 byte  (UINT8)  | 0 .. 255 |
| 1 | 2 bytes (UINT16 LE) | 0 .. 65535 |
| 2 | 4 bytes (UINT32 LE) | 0 .. 2^32-1 |
| 3 | reserved / not used | — |

The sender picks the smallest width that fits the id; every PDU carries its own cbChId, so the same channel may appear with different widths across PDUs. ChannelId is always little-endian.

### 1.6 Data First / Data PDU — fragmentation (§2.2.3.1 / §2.2.3.2 / §3.1.5.1)

A DVC message larger than one chunk is split into **exactly one DATA_FIRST** followed by **zero or more DATA** PDUs.

**Data First PDU (§2.2.3.1):**

```
Offset  Size            Field
0       1               Header byte: Cmd=DATA_FIRST(2)<<4 | Len | cbChId
1       1/2/4           ChannelId (width per cbChId)
next    1/2/4           Length (total reassembled length of the WHOLE message; width per Len)
next    variable        Data (first fragment of payload)
```

- The **Len** field (bits at the Sp position, `(firstByte >> 2) & 0x03`) selects the width of the **Length** field, using the same 0/1/2 → 1/2/4-byte convention as cbChId:
  - Len=0 → Length is 1 byte (UINT8)
  - Len=1 → Length is 2 bytes (UINT16 LE)
  - Len=2 → Length is 4 bytes (UINT32 LE)
- **Length is the total length of the entire reassembled message**, NOT this fragment. The receiver reads `Length` bytes across DATA_FIRST + subsequent DATA payloads, then delivers.

Example — channel id 3, total message length 300 (0x012C), Len=1, first fragment `AA BB ...`:
```
26 03 2C 01 AA BB ...
│  │  └──┘ Length = 0x012C = 300 (UINT16 LE), total message size
│  └ ChannelId 0x03 (cbChId 0)
└ 0x26 = Cmd 2 (DATA_FIRST), Len=1 ((0x26>>2)&3 = 1), cbChId=0
```
Decode of `0x26`: `Cmd = 0x26>>4 = 2` (DATA_FIRST); `Len = (0x26>>2)&3 = 1` (2-byte Length); `cbChId = 0x26&3 = 0` (1-byte id).

**Data PDU (§2.2.3.2):**

```
Offset  Size            Field
0       1               Header byte: Cmd=DATA(3)<<4 | Sp | cbChId
1       1/2/4           ChannelId (width per cbChId)
next    variable        Data (continuation fragment; NO length field)
```

A DATA PDU has **no Length field** — its payload length is implied by the outer transport framing. The receiver appends each DATA payload until the DATA_FIRST `Length` byte-count is reached.

Example — DATA continuation on channel 3:
```
30 03 CC DD ...
│  │  └ payload continuation
│  └ ChannelId 0x03
└ 0x30 = Cmd 3 (DATA), Sp=0, cbChId=0
```

**Fragmentation rule (§3.1.5.1):**
1. Whole message fits in one chunk → send a single **DATA** PDU (Cmd 3), no DATA_FIRST.
2. Otherwise → send one **DATA_FIRST** (Cmd 2) whose `Length` = total message size and payload = first chunk, then **DATA** (Cmd 3) PDUs for each remaining chunk in order. Reassembly finishes when accumulated payload == `Length`.
3. DATA_FIRST_COMPRESSED (0x06) / DATA_COMPRESSED (0x07) are the RDP8-compression analogues (§2.2.3.3/§2.2.3.4) — same header/id/length structure, but the Data field is RDP8 bulk-compressed; negotiated via the Version 2+ capability.

**Concrete full frame** — Create Request for channel id 3 name "ECHO", single static chunk:
```
CHANNEL_PDU_HEADER:  07 00 00 00   03 00 00 00
                     └ length=7 ┘  └ flags = FIRST|LAST (0x00000003) ┘
DVC Create Request:  10 03 45 43 48 4F 00
                     (7 bytes: 0x10 CREATE cbId0, id=03, "ECHO\0")
```
The MCS SendData wrapping this targets the MCS channel id assigned to the "drdynvc" static channel during the [MS-RDPBCGR] channel-join sequence.

---

## Part 2 — [MS-RDPEGFX] Graphics Pipeline Extension

All byte layouts are little-endian, from the current [MS-RDPEGFX] revision (git_commit 1a26d38e / 565632bd, updated 2025–2026). Fields listed in wire order.

### 2.1 Transport (§2.1 / §2.2.1)

- Rides the **non-lossy dynamic virtual channel** (DVC, [MS-RDPEDYC]) named by the null-terminated ANSI string `"Microsoft::Windows::RDS::Graphics"`.
- **Server→client**: every graphics message is wrapped in an **RDP_SEGMENTED_DATA** structure (§2.2.5.1). One RDP_SEGMENTED_DATA decodes to one or more graphics messages; a message is never split across two RDP_SEGMENTED_DATA but may span multiple **RDP_DATA_SEGMENT** frames (§2.2.5.2). This is where per-frame ZGFX/RDP8 bulk compression lives (descriptor SINGLE `0xE0` / MULTIPART `0xE1`).
- **Client→server**: messages are sent raw, **not** wrapped in any external structure.

### 2.2 RDPGFX_HEADER (§2.2.1.5) — 8 bytes, prepended to every PDU

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| 0 | `cmdId` | u16 | command id (table below) |
| 2 | `flags` | u16 | no flags defined; MUST be 0 |
| 4 | `pduLength` | u32 | total PDU length in bytes, **including the 8-byte header** |

A decoder reads 8 bytes, then consumes `pduLength - 8` bytes of command body.

**Header example bytes** — STARTFRAME PDU (8 hdr + 4 timestamp + 4 frameId = 16 = 0x10):
```
0B 00   00 00   10 00 00 00
cmdId   flags   pduLength=16
=0x000B =0       (0x00000010)
```
CAPSADVERTISE header carrying one VERSION8 capset (8 hdr + 2 capsSetCount + [4 version + 4 capsDataLength + 4 capsData] = 22 = 0x16):
```
12 00   00 00   16 00 00 00
cmdId   flags   pduLength=22
=0x0012 =0       (0x00000016)
```
WIRETOSURFACE_1 header (variable): `01 00 00 00 <pduLength u32 LE> ...`.

### 2.3 cmdId values — RDPGFX_CMDID_* (§2.2.1.5)

| Name | Value | PDU (section) |
|------|-------|---------------|
| WIRETOSURFACE_1 | 0x0001 | RDPGFX_WIRE_TO_SURFACE_PDU_1 (2.2.2.1) |
| WIRETOSURFACE_2 | 0x0002 | RDPGFX_WIRE_TO_SURFACE_PDU_2 (2.2.2.2) |
| DELETEENCODINGCONTEXT | 0x0003 | (2.2.2.3) |
| SOLIDFILL | 0x0004 | (2.2.2.4) |
| SURFACETOSURFACE | 0x0005 | (2.2.2.5) |
| SURFACETOCACHE | 0x0006 | (2.2.2.6) |
| CACHETOSURFACE | 0x0007 | (2.2.2.7) |
| EVICTCACHEENTRY | 0x0008 | (2.2.2.8) |
| CREATESURFACE | 0x0009 | (2.2.2.9) |
| DELETESURFACE | 0x000A | (2.2.2.10) |
| STARTFRAME | 0x000B | (2.2.2.11) |
| ENDFRAME | 0x000C | (2.2.2.12) |
| FRAMEACKNOWLEDGE | 0x000D | (2.2.2.13) |
| RESETGRAPHICS | 0x000E | (2.2.2.14) |
| MAPSURFACETOOUTPUT | 0x000F | (2.2.2.15) |
| CACHEIMPORTOFFER | 0x0010 | (2.2.2.16) |
| CACHEIMPORTREPLY | 0x0011 | (2.2.2.17) |
| CAPSADVERTISE | 0x0012 | (2.2.2.18) |
| CAPSCONFIRM | 0x0013 | (2.2.2.19) |
| MAPSURFACETOWINDOW | 0x0015 | (2.2.2.20) |
| QOEFRAMEACKNOWLEDGE | 0x0016 | (2.2.2.21) |
| MAPSURFACETOSCALEDOUTPUT | 0x0017 | (2.2.2.22) |
| MAPSURFACETOSCALEDWINDOW | 0x0018 | (2.2.2.23) |

Note: 0x0014 is intentionally unassigned (gap between 0x0013 and 0x0015).

### 2.4 RDPGFX_WIRE_TO_SURFACE_PDU_1 (§2.2.2.1)

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| 0 | `header` | 8 | RDPGFX_HEADER, cmdId=0x0001, flags=0 |
| 8 | `surfaceId` | u16 | destination surface |
| 10 | `codecId` | u16 | codec table below |
| 12 | `pixelFormat` | u8 | RDPGFX_PIXELFORMAT (§2.2.1.4) — **1 byte** |
| 13 | `destRect` | 8 | RDPGFX_RECT16 (§2.2.1.2): left,top,right,bottom each u16. For AVC420/AVC444/AVC444v2 this is a *bounding* rect. |
| 21 | `bitmapDataLength` | u32 | length of bitmapData |
| 25 | `bitmapData` | variable | codec-encoded bytes |

RDPGFX_RECT16 (§2.2.1.2) is 4×u16 in order `left, top, right, bottom` (right/bottom exclusive; width = right-left, height = bottom-top). Total fixed part = 25 bytes before bitmapData.

WIRETOSURFACE_2 (0x0002) is the cache-context variant used for progressive/context-based codecs; parse per §2.2.2.2 when advertised.

### 2.5 codecId — RDPGFX_CODECID_* (§2.2.2.1) — pure-Rust vs H.264

| Name | Value | Codec | Pure-Rust-decodable? |
|------|-------|-------|-----------------|
| UNCOMPRESSED | 0x0000 | raw pixels, left→right then top→bottom | **YES — trivial, no codec** |
| CAVIDEO | 0x0003 | **RemoteFX (RFX)** per [MS-RDPRFX] — NOT H.264 | Needs RemoteFX (RLGR + DWT/quant) decoder, but no H.264 |
| CLEARCODEC | 0x0008 | ClearCodec (§2.2.4.1) | Needs ClearCodec decoder (no H.264) |
| PLANAR | 0x000A | Planar codec per [MS-RDPEGDI] §2.2.2.5.1 | **YES — simple RLE planar, no H.264** |
| AVC420 | 0x000B | MPEG-4 AVC/H.264 YUV420p (§2.2.4.4) | **Needs H.264** |
| ALPHA | 0x000C | Alpha codec (§2.2.4.3) | Pure-decodable (RLE alpha plane), no H.264 |
| AVC444 | 0x000E | H.264 YUV444 (§2.2.4.5) | **Needs H.264** |
| AVC444V2 | 0x000F | H.264 YUV444v2 (§2.2.4.6) | **Needs H.264** |

> **Correction to the original task brief:** the brief conflated CAVIDEO/H264=0x0003 and AVC420=0x0003 — both wrong. `CAVIDEO 0x0003` is **RemoteFX**, and `AVC420` is **0x000B**, not 0x0003. PLANAR=0x000A, ALPHA=0x000C, AVC444=0x000E are correct. There is no codecId 0x0001/0x0002/0x0004–0x0007/0x0009/0x000D in this enum.

**For a decode-only client with no H.264/RemoteFX stack, the pure-decodable path is: UNCOMPRESSED (0x0000) + PLANAR (0x000A)** (both simple), plus ALPHA (0x000C) and ClearCodec (0x0008) if you implement their RLE. Everything AVC* requires an H.264 decoder; CAVIDEO requires a RemoteFX decoder. Advertise only the capsets whose codecs you can decode so the server never sends AVC.

### 2.6 RDPGFX_PIXELFORMAT (§2.2.1.4) — 1 byte

| Name | Value | Meaning |
|------|-------|---------|
| PIXEL_FORMAT_XRGB_8888 | 0x20 | 32bpp, alpha ignored (XRGB) |
| PIXEL_FORMAT_ARGB_8888 | 0x21 | 32bpp with valid alpha (ARGB) |

### 2.7 RDPGFX_CREATE_SURFACE_PDU (§2.2.2.9)

| Offset | Field | Size |
|--------|-------|------|
| 0 | header (cmdId=0x0009) | 8 |
| 8 | `surfaceId` | u16 |
| 10 | `width` | u16 |
| 12 | `height` | u16 |
| 14 | `pixelFormat` | u8 (RDPGFX_PIXELFORMAT) |

Total 15 bytes. (DELETESURFACE 0x000A is header + surfaceId u16 = 10 bytes.)

### 2.8 RDPGFX_MAP_SURFACE_TO_OUTPUT_PDU (§2.2.2.15)

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| 0 | header (cmdId=0x000F) | 8 | |
| 8 | `surfaceId` | u16 | |
| 10 | `reserved` | u16 | MUST be 0 |
| 12 | `outputOriginX` | u32 | x on Graphics Output Buffer |
| 16 | `outputOriginY` | u32 | y on Graphics Output Buffer |

Total 20 bytes.

### 2.9 RDPGFX_START_FRAME_PDU (§2.2.2.11)

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| 0 | header (cmdId=0x000B) | 8 | |
| 8 | `timestamp` | u32 | packed bitfield: milliseconds(10) \| seconds(6) \| minutes(6) \| hours(10); 0 if none |
| 12 | `frameId` | u32 | unique frame id |

Total 16 bytes.

### 2.10 RDPGFX_END_FRAME_PDU (§2.2.2.12)

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| 0 | header (cmdId=0x000C) | 8 | |
| 8 | `frameId` | u32 | same id as the matching STARTFRAME |

Total 12 bytes. The client answers each ENDFRAME with a **FRAMEACKNOWLEDGE (0x000D)** carrying that frameId (flow control).

### 2.11 Capability negotiation (happens first, before any graphics)

**RDPGFX_CAPS_ADVERTISE_PDU (§2.2.2.18) — client→server:**

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| 0 | header (cmdId=0x0012) | 8 | |
| 8 | `capsSetCount` | u16 | number of capsets |
| 10 | `capsSets` | variable | array of RDPGFX_CAPSET |

**RDPGFX_CAPS_CONFIRM_PDU (§2.2.2.19) — server→client:**

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| 0 | header (cmdId=0x0013) | 8 | |
| 8 | `capsSet` | variable | exactly one RDPGFX_CAPSET the server selected |

**RDPGFX_CAPSET (§2.2.1.6):**

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| 0 | `version` | u32 | RDPGFX_CAPVERSION_* |
| 4 | `capsDataLength` | u32 | size of capsData |
| 8 | `capsData` | variable | version-specific (typically a 4-byte `flags` field for V8/V8.1, e.g. RDPGFX_CAPS_FLAG_THINCLIENT/SMALL_CACHE/AVC_DISABLED) |

**RDPGFX_CAPVERSION_* version constants:**

| Name | Value |
|------|-------|
| CAPVERSION_8 | 0x00080004 |
| CAPVERSION_81 | 0x00080105 |
| CAPVERSION_10 | 0x000A0002 |
| CAPVERSION_101 | 0x000A0100 |
| CAPVERSION_102 | 0x000A0200 |
| CAPVERSION_103 | 0x000A0301 |
| CAPVERSION_104 | 0x000A0400 |
| CAPVERSION_105 | 0x000A0502 |
| CAPVERSION_106 | 0x000A0600 |
| CAPVERSION_107 | 0x000A0701 |

**Decode-only guidance:** to keep the server from ever sending H.264, advertise **CAPVERSION_8 (0x00080004)** (and/or 8.1) with `capsData` flags set to `RDPGFX_CAPS_FLAG_AVC_DISABLED` where the version supports it; V8 predates AVC444 so it naturally restricts the server to RemoteFX/planar/uncompressed. Advertising 10.x versions invites AVC420/AVC444. Only advertise a version whose codec set you can decode.

### 2.12 Minimal decoder state machine (server→client)

1. DVC opens `Microsoft::Windows::RDS::Graphics`.
2. Client sends CAPSADVERTISE (0x0012); server replies CAPSCONFIRM (0x0013).
3. Server: RESETGRAPHICS (0x000E, defines monitor layout) → CREATESURFACE (0x0009) → MAPSURFACETOOUTPUT (0x000F).
4. Per repaint: STARTFRAME (0x000B) → one or more WIRETOSURFACE_1/2 (+ SOLIDFILL/SURFACETOSURFACE/cache ops) → ENDFRAME (0x000C).
5. Client: FRAMEACKNOWLEDGE (0x000D) per frame (flow-control window).

All server PDUs arrive inside RDP_SEGMENTED_DATA (§2.2.5.1) — de-segment/decompress that layer before parsing RDPGFX_HEADER.

---

## Part 3 — Multitransport bootstrap (TCP → UDP sideband)

The main RDP session is TCP (TPKT/X.224/MCS). Multitransport adds a *sideband* UDP transport ([MS-RDPEUDP]) that carries the same DVC traffic (notably EGFX) once up.

### 3.1 Bootstrap flow (all in [MS-RDPBCGR] unless noted)

1. Capability advertisement in the GCC Conference Create (MCS Connect Initial/Response) — client and server each send a **Multitransport Channel Data** block.
2. Over the established main channel, the server sends the **Server Initiate Multitransport Request PDU** (§2.2.15.1) carrying `requestId` + 16-byte `securityCookie`, on the **MCS message channel**.
3. Client opens a UDP socket (MS-RDPEUDP), and in the RDP-UDP SYN echoes a **SHA-256 hash of the securityCookie** — this binds the UDP flow to the TCP session.
4. Channel is secured with **TLS or DTLS** ([MS-RDPEMT] §1.4/§5.1). Client then sends the **Tunnel Create Request PDU** ([MS-RDPEMT] §2.2.2.1) over the new UDP channel, retransmitting the full 16-byte `securityCookie` in cleartext; server validates it against the stored request.
5. In soft-sync mode the client also acknowledges on the main channel with the **Client Initiate Multitransport Response PDU** (§2.2.15.2).

### 3.2 Server Initiate Multitransport Request PDU — §2.2.15.1

Delivery: server → client, encapsulated as `tpktHeader(4) | x224Data(3, Class 0 Data TPDU) | mcsSDin (MCS Send Data Indication, DomainMCSPDU choice 26) | securityHeader | <fields>`. **MUST be sent only over the MCS message channel** (id given in Server Message Channel Data §2.2.1.4.5). The securityHeader `flags` field MUST contain **SEC_TRANSPORT_REQ = 0x0002**.

| Field | Size | Notes |
|---|---|---|
| requestId | 4 bytes (u32) | Correlates this request with the later Tunnel Create Request PDU. |
| requestedProtocol | 2 bytes (u16) | `INITITATE_REQUEST_PROTOCOL_UDPFECR = 0x01` (reliable) / `INITITATE_REQUEST_PROTOCOL_UDPFECL = 0x02` (lossy). Spec spelling is "INITITATE". |
| reserved | 2 bytes (u16) | MUST be 0. |
| securityCookie | 16 bytes | 16-element array of random u8. Retransmitted by the client in the Tunnel Create Request PDU ([MS-RDPEMT] §3.2.5.1). |

The server saves `{requestId, requestedProtocol, securityCookie}` so the incoming sideband connection can be correlated and authenticated.

### 3.3 Client Initiate Multitransport Response PDU — §2.2.15.2

Delivery: client → server, `tpktHeader | x224Data | mcsSDrq (MCS Send Data Request, choice 25) | securityHeader | requestId | hrResponse`. Also **MCS message channel only**. securityHeader `flags` MUST contain **SEC_TRANSPORT_RSP = 0x0004**.

| Field | Size | Notes |
|---|---|---|
| requestId | 4 bytes (u32) | Echoes the §2.2.15.1 requestId. |
| hrResponse | 4 bytes (u32, HRESULT) | `S_OK = 0x00000000` (initiation completed) / `E_ABORT = 0x80004004` (could not establish). |

An `S_OK` response MUST only be sent to a server that advertised **SOFTSYNC_TCP_TO_UDP (0x200)**. In non-soft-sync mode the response PDU is used to report failure (E_ABORT); the successful path is signaled implicitly by the Tunnel Create Request arriving on the UDP channel.

### 3.4 Binding UDP → TCP session: the cookie hash — [MS-RDPEUDP] §3.1.5.1.1 + §2.2.2.9

Two independent bindings tie the UDP flow to the correct TCP session.

**(a) Cookie hash in the SYN (early bind).** The RDP-UDP SYN datagram is `RDPUDP_FEC_HEADER | RDPUDP_SYNDATA_PAYLOAD | [RDPUDP_CORRELATION_ID_PAYLOAD] | [RDPUDP_SYNDATAEX_PAYLOAD]`. In the FEC header the client sets `uFlags` with `RDPUDP_FLAG_SYN`, and `RDPUDP_FLAG_SYNEX` when the SYNDATAEX payload is appended (`snSourceAck` = -1).

`RDPUDP_SYNDATAEX_PAYLOAD` (§2.2.2.9):
- `uSynExFlags` (2 bytes): `RDPUDP_VERSION_INFO_VALID = 0x0001`.
- `uUdpVer` (2 bytes): `RDPUDP_PROTOCOL_VERSION_1 = 0x0001`, `_VERSION_2 = 0x0002`, `_VERSION_3 = 0x0101` (v3 data-transfer messages are in [MS-RDPEUDP2] §2.2).
- `cookieHash` (32 bytes, optional): **the SHA-256 hash of the data transmitted from the server to the client in the `securityCookie` field of the Initiate Multitransport Request PDU.** Interpreted as an array of 8 four-byte unsigned integers, each in network byte order.

What is hashed: **only the raw 16 bytes of `securityCookie`** — SHA-256, no salt, no concatenation, no prefix constant. Output is the full 32-byte digest.

Condition: `cookieHash` MUST be present in the client→server SYN **iff `uUdpVer == RDPUDP_PROTOCOL_VERSION_3 (0x0101)`**, and MUST NOT be present otherwise. The server SHOULD verify the hash; **if invalid, the connection resets the RDP-UDP protocol version down to RDPUDP_PROTOCOL_VERSION_2 (0x0002)** (drops to a mode without the cookie binding rather than hard-failing at the UDP layer). Because the cookie is echoed as a hash, a UDP-only eavesdropper cannot recover it.

**(b) Full cookie in the Tunnel Create Request (authoritative bind).** After the UDP channel is secured (DTLS/TLS), the client sends the Tunnel Create Request PDU ([MS-RDPEMT] §2.2.2.1) carrying the **full 16-byte securityCookie in clear** (now protected by DTLS/TLS). The server matches `{requestId, securityCookie}` against its stored Multitransport Request Data ([MS-RDPEMT] §3.2.5.1). This is the definitive correlation, because the cookie was only ever delivered to that client over the secured main channel.

### 3.5 Multitransport capability negotiation (GCC data blocks)

> **Correction to the premise:** there is **no `RNS_UD_CS_SUPPORT_MULTITRANSPORT` bit in `earlyCapabilityFlags`.** Multitransport is not advertised through Client Core Data (TS_UD_CS_CORE §2.2.1.3.2). The `earlyCapabilityFlags` value `0x0100` is `RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL` (EGFX support) — the *consumer* that typically rides UDP, not the multitransport flag.

Full earlyCapabilityFlags list (§2.2.1.3.2): 0x0001 SUPPORT_ERRINFO_PDU, 0x0002 WANT_32BPP_SESSION, 0x0004 SUPPORT_STATUSINFO_PDU, 0x0008 STRONG_ASYMMETRIC_KEYS, 0x0010 RELATIVE_MOUSE_INPUT, 0x0020 VALID_CONNECTION_TYPE, 0x0040 SUPPORT_MONITOR_LAYOUT_PDU, 0x0080 SUPPORT_NETCHAR_AUTODETECT, 0x0100 SUPPORT_DYNVC_GFX_PROTOCOL, 0x0200 SUPPORT_DYNAMIC_TIME_ZONE, 0x0400 SUPPORT_HEARTBEAT_PDU, 0x0800 SUPPORT_SKIP_CHANNELJOIN.

Multitransport is negotiated by two dedicated GCC user-data blocks inside the MCS Connect Initial/Response:

**Client Multitransport Channel Data — TS_UD_CS_MULTITRANSPORT (§2.2.1.3.8):**
- `header` (4 bytes): GCC user-data header, type = **CS_MULTITRANSPORT (0xC00A)**.
- `flags` (4 bytes, u32): client-supported transports.
- An *Extended Client Data Block* — MUST NOT be sent unless the server advertised `EXTENDED_CLIENT_DATA_SUPPORTED (0x00000001)`.

**Server Multitransport Channel Data — TS_UD_SC_MULTITRANSPORT (§2.2.1.4.6):**
- `header` (4 bytes): GCC user-data header, type = **SC_MULTITRANSPORT (0x0C08)**.
- `flags` (4 bytes, u32): server-supported transports.

**`flags` bit values (same namespace for both blocks):**

| Flag | Value | Meaning |
|---|---|---|
| TRANSPORTTYPE_UDPFECR | 0x01 | RDP-UDP FEC **reliable** transport ([MS-RDPEUDP]). |
| TRANSPORTTYPE_UDPFECL | 0x04 | RDP-UDP FEC **lossy** transport. |
| TRANSPORTTYPE_UDP_PREFERRED | 0x100 | Tunneling of **static** VC traffic over UDP supported ([MS-RDPEDYC] §3.1.5.4). |
| SOFTSYNC_TCP_TO_UDP | 0x200 | Switching **dynamic** VCs from TCP to UDP supported ([MS-RDPEDYC] §3.1.5.3). If the server sets this it MUST support processing an S_OK in the Initiate Multitransport Response PDU (§2.2.15.2). |

> **Note the bit asymmetry:** reliable is bit `0x01` but lossy is bit `0x04` in the channel-data `flags`, whereas in the §2.2.15.1 `requestedProtocol` field reliable=`0x01` / lossy=`0x02` are *enumerated values*, not the same bitfield. Do not reuse one encoding for the other.

### 3.6 After the UDP transport is up

Per §2.2.15.1 and [MS-RDPEMT] §1.4/§5.1: once the RDP-UDP SYN/SYN+ACK/ACK handshake completes, the client secures the channel with **DTLS** (lossy/unreliable UDP) or **TLS** (reliable), sends the **Tunnel Create Request PDU** with the cookie, receives the **Tunnel Create Response PDU**, and the transport then carries the same RDP PDUs — DVC data ([MS-RDPEDYC]), in particular EGFX PDUs — that would otherwise flow over TCP. Soft-sync (SOFTSYNC_TCP_TO_UDP) migrates already-open DVCs from TCP onto UDP without tearing them down.

### 3.7 Summary of what binds UDP → TCP session

1. `securityCookie` (16 random bytes) is minted by the server and delivered **only over the secured main TCP/MCS message channel** in the §2.2.15.1 request, keyed by `requestId`.
2. The client proves possession over UDP first as **SHA-256(securityCookie)** in the SYNEX `cookieHash` (v3 only; failure → downgrade to v2), then authoritatively as the **raw 16-byte cookie inside the DTLS/TLS-protected Tunnel Create Request PDU**, which the server matches against stored per-request state. No cookie match → the sideband is not accepted as belonging to that session.

---

## Part 4 — Open questions / low-confidence items

These are unresolved points, spec ambiguities, and corrections the implementer must verify against the live [MS-*] text and a reference server (rdesktop/FreeRDP/xrdp) before locking in the binary layout.

**DRDYNVC**
1. **Sp/Len field bit position confidence.** The decode `Len = (byte >> 2) & 0x03` for DATA_FIRST is the source's reading of the MSB-first diagram. Confirm against a FreeRDP capture that the length-selector occupies bits 4..5, not 2..3, since the MS bit-numbering convention (0=MSB) is easy to invert. **Verify with a real DATA_FIRST byte.**
2. **Create Request/Response section numbering.** The create-family sections were cited as §2.2.2.1/§2.2.2.2 — the same numbers used for the Capabilities PDUs. The MS doc separates channel-management (create/close) from capability PDUs; reconcile the exact section numbers before citing them in code comments.
3. **CreationStatus type.** Whether CreationStatus is HRESULT vs NTSTATUS in practice (both are signed 32-bit; sign test for success is what matters). Confirm the exact error code a real server returns on rejection.
4. **VCChunkSize default.** The ~1600-byte outer chunk size is the typical negotiated value, not a fixed constant; read the actual VCChunkSize from the [MS-RDPBCGR] VC capability set at runtime rather than hardcoding.
5. **Soft-Sync PDU layouts (§2.2.3.x / SOFT_SYNC_REQUEST 0x08 / RESPONSE 0x09).** Not detailed here — needed only if implementing TCP→UDP DVC migration (Phase 7 soft-sync). Their field layouts are not captured in this reference.

**EGFX**
6. **Spec revision drift.** Layouts are from git_commit 1a26d38e / 565632bd (2025–2026). Field offsets in CAPSET capsData and the newer CAPVERSION_10x flags evolve between revisions — pin to one revision and diff against a capture.
7. **WIRETOSURFACE_2 (0x0002) body.** Only the WIRETOSURFACE_1 layout is fully specified here; the _2 variant (cache-context/progressive) body is not, and is required if a progressive codec is ever negotiated.
8. **RDP_SEGMENTED_DATA / ZGFX (RDP8 bulk) decompression.** The de-segmentation and ZGFX decompression (descriptors 0xE0/0xE1) sit under the RDPGFX_HEADER parse and are only summarized. The ZGFX/RDP8.0 compression algorithm ([MS-RDPEGFX] §3 / RDP8 bulk) must be implemented for server→client and is non-trivial — treat as its own subtask.
9. **RESETGRAPHICS (0x000E) layout** (monitor-layout definition) is referenced in the state machine but not laid out here; needed to size the surface/output mapping.
10. **Whether AVC_DISABLED alone is sufficient.** Confidence is moderate that advertising only CAPVERSION_8 with AVC_DISABLED guarantees no AVC. Some servers may still probe; validate empirically that a V8-only advertise yields only PLANAR/UNCOMPRESSED/RemoteFX bitmapData.
11. **PLANAR codec exact byte format.** PLANAR is "pure-Rust-decodable" but its RLE format lives in [MS-RDPEGDI] §2.2.2.5.1 (a different spec) and is not reproduced here — the actual decode loop still needs that document.

**Multitransport / UDP**
12. **cookieHash byte order.** Stated as "8 four-byte unsigned integers each in network byte order." Whether this means the SHA-256 digest is emitted big-endian per-word (i.e. the natural digest byte order) or word-swapped needs a wire capture to confirm — a subtle bug source.
13. **Downgrade-on-bad-hash behavior.** The "reset to VERSION_2 on invalid hash" behavior is a SHOULD; server implementations vary. Do not rely on the downgrade as a fallback path.
14. **`requestedProtocol` vs `flags` encoding split** (0x02 vs 0x04 for lossy) is confirmed asymmetric but is exactly the kind of value that gets miswired — assert both encodings independently in code with named constants.
15. **DTLS vs TLS selection rule.** "DTLS for lossy, TLS for reliable" is the stated rule; confirm the exact version/ciphersuite constraints ([MS-RDPEMT] §5.1) and whether the reliable path can also use DTLS in some server builds.
16. **Tunnel Create Request/Response PDU field layout** ([MS-RDPEMT] §2.2.2.1/§2.2.2.2) is referenced but not laid out byte-by-byte here — required before Phase 7 can send it.
17. **MS-RDPEUDP2 (v3 data transfer).** If advertising RDPUDP_PROTOCOL_VERSION_3 (0x0101), the data-transfer framing moves to [MS-RDPEUDP2] §2.2, which is a distinct message set from the v1/v2 RDPUDP_FEC_HEADER path and not covered here.

**Cross-cutting**
18. All three parts were assembled from spec text, not from a byte-verified reference-client capture. Before freezing struct definitions, capture a real FreeRDP↔Windows session and diff every offset table above against the wire.