# RDP Phase 3 — MCS/GCC Connection Sequence & Capability Exchange

Implementation reference for a native Rust RDP client. Covers the MCS Connect
Initial/Response (BER), the MCS domain PDUs (PER), the GCC
ConferenceCreateRequest/Response (T.124 PER), the RDP TS_UD data blocks, the
capability exchange, and the Client Info / License / finalization PDUs.

**Endianness rules that never change:**

- **BER/PER wire integers** (MCS/GCC framing) follow ASN.1 rules (big-endian
  fields, PER length determinants).
- **RDP's own TLV structures** (everything from the TS_UD data blocks onward:
  CS_CORE, capability sets, share PDUs, Client Info, etc.) are **little-endian**.
  Strings marked "Unicode" are UTF-16LE.

**On-wire framing recap.** Every MCS PDU rides inside TPKT + X.224:

```
03 00 LL LL      TPKT: version=3, reserved=0, total length (16-bit BE, whole packet)
02 F0 80         X.224 Data TPDU: len=2, type=0xF0 (DT), EOT=0x80
<MCS PDU ...>
```

Primary references: **[MS-RDPBCGR]** (sections cited inline), **ITU-T T.125**
(MCS ASN.1), **ITU-T T.124** (GCC ASN.1), **ITU-T X.690** (BER), **ITU-T X.691**
(PER, ALIGNED variant).

---

## 1. MCS Connect-Initial / Connect-Response (BER)

Both PDUs are **BER-encoded** (X.690), unlike the GCC payload they carry, which
is **PER-encoded** (T.124). They sit directly after the TPKT + X.224 DT header.

Reference: [MS-RDPBCGR] §2.2.1.3 (Connect-Initial), §2.2.1.4 (Connect-Response),
§4.1.4 (worked sample); ASN.1 in T.125 §7 / Annex B.

### 1.1 BER tag byte reference

| ASN.1 type | Identifier octet(s) | Notes |
|---|---|---|
| BOOLEAN | `01` | `00`=FALSE, non-zero (`FF`)=TRUE |
| INTEGER | `02` | two's-complement, minimal (X.690 §8.3) |
| OCTET STRING | `04` | primitive form in RDP |
| ENUMERATED | `0A` | encoded like INTEGER |
| SEQUENCE | `30` | constructed |
| `[APPLICATION 101]` Connect-Initial | `7F 65` | high-tag-number form |
| `[APPLICATION 102]` Connect-Response | `7F 66` | high-tag-number form |

**Why APPLICATION 101 → `7F 65` (X.690 §8.1.2):** application class + constructed
= bits `011`; low 5 bits = `11111` signal "high tag number follows" → first octet
`0111 1111` = **`0x7F`**. Tag number 101 = `0x65` (< 128, single octet) → **`7F 65`**.
Connect-Response tag 102 = `0x66` → **`7F 66`**.

Because both PDUs are `[APPLICATION n] IMPLICIT SEQUENCE`, the implicit tag
**replaces** the universal `30` — the outer PDU shows only `7F 65` / `7F 66`,
never `30`. Nested `DomainParameters` is untagged, so it keeps `30`.

### 1.2 BER length encoding (X.690 §8.1.3)

- **Short form** (len ≤ 127): one octet, top bit 0. `25` → `19`, `5` → `05`.
- **Long form** (len ≥ 128): first octet `0x80 | k`, then `k` big-endian length octets:
  - 200 → `81 C8`; 307 (`0x133`) → `82 01 33`; 404 (`0x194`) → `82 01 94`.
- **Indefinite form** (`80` + EOC `00 00`): **not used** by RDP — always definite.

RDP encoders frequently emit a **fixed 2-octet long form `82 xx xx`** for the
outer PDU length and `userData`, even when a shorter form would fit. Parsers
**must accept both** short and long forms.

### 1.3 Connect-Initial structure

```
Connect-Initial ::= [APPLICATION 101] IMPLICIT SEQUENCE {
    callingDomainSelector   OCTET STRING,
    calledDomainSelector    OCTET STRING,
    upwardFlag              BOOLEAN,
    targetParameters        DomainParameters,
    minimumParameters       DomainParameters,
    maximumParameters       DomainParameters,
    userData                OCTET STRING }
DomainParameters ::= SEQUENCE {
    maxChannelIds, maxUserIds, maxTokenIds, numPriorities,
    minThroughput, maxHeight, maxMCSPDUsize, protocolVersion  -- all INTEGER(0..MAX) }
```

| Field | BER bytes | Meaning |
|---|---|---|
| Connect-Initial tag | `7F 65` | APPLICATION 101, constructed |
| outer length | `82 LL LL` | length of everything below |
| callingDomainSelector | `04 01 01` | OCTET STRING len 1 = `0x01` |
| calledDomainSelector | `04 01 01` | OCTET STRING len 1 = `0x01` |
| upwardFlag | `01 01 FF` | BOOLEAN TRUE (client→server = "upward") |
| targetParameters | `30 19` + 25B | SEQUENCE (§1.4) |
| minimumParameters | `30 19` + 25B | SEQUENCE |
| maximumParameters | `30 20` + 32B | SEQUENCE (values > 127 → longer) |
| userData | `04 82 LL LL` + N | OCTET STRING wrapping GCC ConferenceCreateRequest |

### 1.4 DomainParameters — canonical RDP values

**targetParameters** (standard RDP client set, §4.1.4):

| Field | Value | BER |
|---|---|---|
| maxChannelIds | 34 | `02 01 22` |
| maxUserIds | 2 | `02 01 02` |
| maxTokenIds | 0 | `02 01 00` |
| numPriorities | 1 | `02 01 01` |
| minThroughput | 0 | `02 01 00` |
| maxHeight | 1 | `02 01 01` |
| maxMCSPDUsize | 65535 | `02 02 FF FF` |
| protocolVersion | 2 | `02 01 02` |

Content = 3+3+3+3+3+3+4+3 = **25 bytes (0x19)**:
`30 19 02 01 22 02 01 02 02 01 00 02 01 01 02 01 00 02 01 01 02 02 FF FF 02 01 02`.

- **minimumParameters** (typical): 1,1,1,1,0,1,1056,2 → maxMCSPDUsize=1056 is `02 02 04 20`; total 25 bytes (`30 19`).
- **maximumParameters** (typical): 65535, 64535, 65535, 1, 0, 1, 65535, 2.

> **INTEGER sign caveat (X.690 §8.3):** INTEGER is signed two's-complement. Any
> value whose top bit would be 1 needs a leading `00` pad. Minimal 65535 =
> `02 03 00 FF FF`; 64535 (`0xFC17`) = `02 03 00 FC 17`. Hence maximumParameters
> = 5+5+5+3+3+3+5+3 = **32 bytes (0x20)** → `30 20 ...`.
>
> Real stacks are inconsistent: some encode `maxMCSPDUsize=65535` as `02 02 FF FF`
> (technically −1, interoperable because receivers treat these as unsigned per
> `(0..MAX)`), others as strict `02 03 00 FF FF`. **Robust parsers accept both
> and interpret DomainParameters INTEGERs as unsigned.**

### 1.5 Connect-Response structure

```
Connect-Response ::= [APPLICATION 102] IMPLICIT SEQUENCE {
    result              Result,          -- ENUMERATED
    calledConnectId     INTEGER(0..MAX),
    domainParameters    DomainParameters,
    userData            OCTET STRING }
Result ::= ENUMERATED {
    rt-successful(0), rt-domain-merging(1), rt-domain-not-hierarchical(2),
    rt-no-such-channel(3), rt-no-such-domain(4), rt-no-such-user(5),
    rt-not-admitted(6), rt-other-user-id(7), rt-parameters-unacceptable(8),
    rt-token-not-available(9), rt-token-not-possessed(10), rt-too-many-channels(11),
    rt-too-many-tokens(12), rt-too-many-users(13), rt-unspecified-failure(14),
    rt-user-rejected(15) }
```

| Field | BER bytes | Meaning |
|---|---|---|
| Connect-Response tag | `7F 66` | APPLICATION 102, constructed |
| outer length | `82 LL LL` | long form |
| result | `0A 01 00` | ENUMERATED = rt-successful(0) |
| calledConnectId | `02 01 00` | INTEGER = 0 |
| domainParameters | `30 19` + 25B | server-chosen (e.g. maxUserIds→3: `02 01 03`) |
| userData | `04 82 LL LL` + N | OCTET STRING wrapping GCC ConferenceCreateResponse |

Failure is signalled by non-zero `result` (e.g. `0A 01 01`).

### 1.6 Worked byte layout — Connect-Initial header

Assume GCC ConferenceCreateRequest blob N = 307 bytes (`0x133`).

```
callingDomainSelector  04 01 01            = 3
calledDomainSelector   04 01 01            = 3
upwardFlag             01 01 FF            = 3
targetParameters       30 19 + 25         = 27
minimumParameters      30 19 + 25         = 27
maximumParameters      30 20 + 32         = 34
userData tag+len       04 82 01 33        = 4
userData contents      (GCC blob)         = 307
                        outer body total  = 408  (0x198)
```

Outer length 408 → `82 01 98`:

```
7F 65 82 01 98                         Connect-Initial, len=408
04 01 01                               callingDomainSelector = {01}
04 01 01                               calledDomainSelector  = {01}
01 01 FF                               upwardFlag = TRUE
30 19                                  targetParameters SEQUENCE, len=25
   02 01 22  02 01 02  02 01 00        maxChannelIds=34, maxUserIds=2, maxTokenIds=0
   02 01 01  02 01 00  02 01 01        numPriorities=1, minThroughput=0, maxHeight=1
   02 02 FF FF  02 01 02               maxMCSPDUsize=65535, protocolVersion=2
30 19                                  minimumParameters SEQUENCE, len=25
   02 01 01  02 01 01  02 01 01        maxChannelIds=1, maxUserIds=1, maxTokenIds=1
   02 01 01  02 01 00  02 01 01        numPriorities=1, minThroughput=0, maxHeight=1
   02 02 04 20  02 01 02               maxMCSPDUsize=1056, protocolVersion=2
30 20                                  maximumParameters SEQUENCE, len=32
   02 03 00 FF FF                      maxChannelIds=65535
   02 03 00 FC 17                      maxUserIds=64535
   02 03 00 FF FF                      maxTokenIds=65535
   02 01 01  02 01 00  02 01 01        numPriorities=1, minThroughput=0, maxHeight=1
   02 03 00 FF FF                      maxMCSPDUsize=65535
   02 01 02                            protocolVersion=2
04 82 01 33                            userData OCTET STRING, len=307
   00 05 00 14 7C 00 01 ...            GCC ConnectData / ConferenceCreateRequest (PER)
   ... 44 75 63 61 (Duca) ...          client H.221 key, then client core/sec/net data
```

With TPKT+X.224 (total = 408 + 5 [`7F 65 82 01 98`] + 7 = 420 = `0x01A4`):

```
03 00 01 A4    TPKT len=420
02 F0 80       X.224 DT
7F 65 82 01 98 ...
```

### 1.7 Parsing gotchas

1. Outer tag is 2 bytes (`7F 65`/`7F 66`), never single-byte `30`.
2. Accept both short- and long-form lengths; RDP emits fixed `82 xx xx` even for small values.
3. Treat DomainParameters INTEGERs as **unsigned**; tolerate both `02 02 FF FF` and `02 03 00 FF FF` for 65535.
4. `upwardFlag` = TRUE (`FF`) in the client's Connect-Initial.
5. `userData` is a BER OCTET STRING whose *contents* switch to PER (T.124) — do not BER-parse inside it.

---

## 2. MCS Domain PDUs (PER)

After the BER Connect exchange, the remaining MCS PDUs use **PER (ALIGNED)**
per T.125. They are the "domain" PDUs of the `DomainMCSPDU` CHOICE. Each is
identified by a single **leading byte** = `(choice_index << 2)` (the PER CHOICE
tag for a small non-extensible choice, with the low bits acting as padding/flags
in the fixed RDP forms below). All ride inside TPKT + X.224 DT (`03 00 LL LL 02 F0 80`).

| PDU | Choice | Leading byte | Direction |
|---|---|---|---|
| Erect Domain Request | 1 | `04` | C→S |
| Attach User Request | 10 | `28` | C→S |
| Attach User Confirm | 11 | `2E` | S→C |
| Channel Join Request | 14 | `38` | C→S |
| Channel Join Confirm | 15 | `3E` | S→C |
| Send Data Request | 25 | `64` | C→S |
| Send Data Indication | 26 | `68` | S→C |
| Disconnect Provider Ultimatum | 8 | `20` | either |

### 2.1 Erect Domain Request — `04`

Fixed 5-byte body (subHeight/subInterval both 0):

```
04 01 00 01 00
│  │     │
│  └─ subHeight: len 1, value 0
│        └─ subInterval: len 1, value 0
└─ MCSPDU choice = erectDomainRequest (1)
```

Full packet: `03 00 00 0C 02 F0 80 04 01 00 01 00`.

### 2.2 Attach User Request — `28`

Single byte body:

```
28
```

Full packet: `03 00 00 08 02 F0 80 28`.

### 2.3 Attach User Confirm — `2E`

```
2E <result:PER-enum> <initiator:UserID>
```

- `result` — MCS Result ENUMERATED, packed. Success = high nibble following `2E`.
- `initiator` — the **User Channel ID** assigned to the client, encoded as
  `UserID ::= INTEGER(1001..65535)` → 16-bit value minus 1001.

Typical success form, initiator 1007 (`0x03EF`): `2E 00 00 06`
(result=0; initiator = 1007−1001 = 6 = `0x0006`). **Save this User Channel ID** —
it is the initiator for every subsequent Send Data Request and the channel the
client joins first.

### 2.4 Channel Join Request — `38`

```
38 <initiator:UserID> <channelId:u16>
```

- `initiator` = client's User Channel ID minus 1001 (from Attach User Confirm).
- `channelId` = target MCS channel, 16-bit big-endian (PER constrained INTEGER,
  full range so 2 raw octets).

The client joins, in order: its **own user channel**, the **I/O channel**
(from SC_NET, typically 1003 = `0x03EB`), and every **virtual channel** ID the
server returned in SC_NET.

Example — join own channel 1007, initiator 6: `38 00 06 03 EF`.

### 2.5 Channel Join Confirm — `3E`

```
3E <result> <initiator:UserID> <requested:u16> <channelId:u16>
```

- `result` — MCS Result (0 = success).
- `initiator` — echoes the client User Channel ID (minus 1001).
- `requested` — the channel the client asked for (16-bit).
- `channelId` — the granted channel (16-bit; equals `requested` on success).

Example: `3E 00 00 06 03 EF 03 EF` (success, initiator 6, channel 1007 granted).

### 2.6 Send Data Request (`64`) / Send Data Indication (`68`)

These wrap **all** post-connection RDP PDUs (Client Info, Demand/Confirm Active,
share data PDUs, etc.). Same layout, different leading byte by direction:

```
64|68  <initiator:UserID>  <channelId:u16>  <dataPriority+segmentation:1>  <userDataLength:PER-len>  <userData...>
```

| Field | Bytes | Meaning |
|---|---|---|
| MCSPDU | `64` (Req, C→S) / `68` (Ind, S→C) | choice 25 / 26 |
| initiator | 2 | sender's User Channel ID − 1001 |
| channelId | 2 | destination MCS channel (I/O channel 1003, or a VC id) |
| dataPriority + segmentation | 1 | top 2 bits = priority (`00`=high), plus segmentation flags; RDP uses `0x70` (high priority, complete single segment) |
| userDataLength | 1 or 2 | **PER length determinant** (see below) |
| userData | N | the RDP PDU (starts with a share/security header) |

**PER length determinant (userDataLength):**
- If `N ≤ 0x7F`: one byte, `N`.
- If `0x80 ≤ N ≤ 0x3FFF`: two bytes `0x80 | (N >> 8)`, `N & 0xFF` (i.e. top bit
  of the 14-bit big-endian value set → `81 xx` .. `BF xx`).

**How Send Data wraps an RDP PDU:** the `userData` payload begins with whatever
security header applies (Basic Security Header for Client Info / licensing under
standard RDP security; nothing extra under TLS/CredSSP), then the RDP
`TS_SHARECONTROLHEADER` (§5) or `TS_SHAREDATAHEADER` for share PDUs. The MCS
layer does not inspect this payload; it only carries `channelId` + length.

Example header for a 22-byte (`0x16`) share PDU to the I/O channel 1003, client
initiator 1007:

```
64 00 06 03 EB 70 16   <22 bytes of RDP PDU...>
│  └initiator 6  │  │  └ userDataLength = 0x16 (22)
│         channel 1003 └ priority/segmentation 0x70
└ Send Data Request
```

---

## 3. GCC ConferenceCreateRequest / ConferenceCreateResponse (T.124 PER)

The MCS `userData` OCTET STRING contents are PER-encoded per T.124: a
`ConnectData` wrapping a `ConnectGCCPDU` CHOICE selecting
`ConferenceCreateRequest` (client, §2.2.1.3.1) or `ConferenceCreateResponse`
(server, §2.2.1.4.1). This is the PER ALIGNED stream *inside* the BER OCTET
STRING; the outer TPKT / X.224 / BER-MCS framing is separate.

```
ConnectData ::= SEQUENCE { t124Identifier Key, connectPDU OCTET STRING }
Key ::= CHOICE { object OBJECT IDENTIFIER, h221NonStandard OCTET STRING(SIZE(4..255)) }
ConnectGCCPDU ::= CHOICE {
    conferenceCreateRequest  ConferenceCreateRequest,   -- index 0
    conferenceCreateResponse ConferenceCreateResponse,  -- index 1
    ... }                                                -- extensible
```

### 3.1 Invariant ConnectData prefix (identical client & server)

`t124Identifier` is the OID **{ itu-t(0) recommendation(0) t(20) 124 version(0) 1 }**
= `0.0.20.124.0.1`.

| Bytes | Field | Explanation |
|---|---|---|
| `00` | Key CHOICE index | 2 alternatives, not extensible → 1 bit, index 0 = `object`; octet-padded → `0x00` |
| `05` | OID length determinant | OID content is 5 octets |
| `00 14 7C 00 01` | OID content | 0·40+0 → `00`; 20 → `14`; 124 → `7C`; 0 → `00`; 1 → `01` |

**Invariant 7-byte prefix: `00 05 00 14 7C 00 01`** — appears verbatim at the
start of BOTH client CCR and server CCResp userData. Immediately after comes the
**`connectPDU` OCTET STRING length** (PER length determinant: 1 byte if ≤ 0x7F,
else `81 xx` two-byte form). This length = (whole ConnectGCCPDU that follows).

### 3.2 Client ConferenceCreateRequest (§2.2.1.3.1)

Well-known client prefix (representative length `0x2A`):

```
00 05 00 14 7C 00 01 81 2A 00 08 00 10 00 01 C0 00 44 75 63 61 81 <userDataLen>
```

| Bytes | Field | Explanation |
|---|---|---|
| `00 05 00 14 7C 00 01` | ConnectData Key = T.124 OID | as above |
| `81 2A` | connectPDU length | PER 2-byte form; value = userDataLen + 14 (varies with block count) |
| `00` | ConnectGCCPDU CHOICE index | 0 = conferenceCreateRequest (extensible: ext-bit 0 + index, octet-padded) |
| `08` | CCR SEQUENCE optional-field bitmap | only `userData` present |
| `00 10` | conferenceName (Numeric "1") | `00` len determinant; `10` = digit '1' packed 4-bit BCD |
| `00` | padding | 1 alignment octet after ConferenceName |
| `01` | userData count (SET OF) | 1 UserData set |
| `C0` | UserData preamble + Key CHOICE | value-present(1) + Key index 1 (h221NonStandard) → `1100 0000` |
| `00` | h221NonStandard length determinant | 4 − min(4) = 0 |
| `44 75 63 61` | H.221 key = **"Duca"** | client→server; D=44 u=75 c=63 a=61 |
| `81 <len>` | userData `value` OCTET STRING length | PER length of the concatenated client blocks |

Client blocks (each a little-endian TLV, §4) follow: clientCoreData (CS_CORE
0xC001), clientSecurityData (CS_SECURITY 0xC002), clientNetworkData (CS_NET
0xC003), clientClusterData (CS_CLUSTER 0xC004), ...

### 3.3 Server ConferenceCreateResponse (§2.2.1.4.1)

Well-known server prefix (representative length `0x2A`, nodeID 0x79F3):

```
00 05 00 14 7C 00 01 2A 14 76 0A 01 01 00 01 C0 00 4D 63 44 6E 81 <userDataLen>
```

| Bytes | Field | Explanation |
|---|---|---|
| `00 05 00 14 7C 00 01` | ConnectData Key = T.124 OID | identical to client |
| `2A` | connectPDU length | PER 1-byte form (≤ 0x7F); value = userDataLen + 14 |
| `14` | ConnectGCCPDU CHOICE index | 1 = conferenceCreateResponse (ext-bit 0 + index 1 → `0001 0100`) |
| `76 0A` | nodeID (UserID) | `INTEGER(1001..65535)` as 16-bit constrained: value − 1001. RDP nodeID 0x79F3 (31219); 31219 − 1001 = 30218 = `0x760A` |
| `01 01` | tag (INTEGER) | CCResp.tag = 1: `01` len, `01` value |
| `00` | result (ENUMERATED) | 0 = success |
| `01` | userData count (SET OF) | 1 |
| `C0` | UserData preamble + Key CHOICE | value-present + h221NonStandard |
| `00` | h221NonStandard length determinant | 0 |
| `4D 63 44 6E` | H.221 key = **"McDn"** | server→client; M=4D c=63 D=44 n=6E |
| `81 <len>` | userData `value` OCTET STRING length | PER length of concatenated server blocks |

Server blocks follow: serverCoreData (SC_CORE 0x0C01), serverNetworkData
(SC_NET 0x0C03), serverSecurityData (SC_SECURITY 0x0C02), ...

### 3.4 Key facts

- **Invariant Key prefix (both directions):** `00 05 00 14 7C 00 01`.
- **CHOICE selector after connectPDU length is the single best client/server
  discriminator:** `00` = CCR (client), `14` = CCResp (server).
- **H.221 keys:** client `44 75 63 61` "Duca"; server `4D 63 44 6E` "McDn".
- **UserData member preamble `C0`** identical both ways.
- **PER length determinants:** 1 byte if ≤ 0x7F, else 2 bytes with top bit of the
  big-endian value set (`81 xx`, `82 xx`, ...).
- The block payloads after the final `81 <len>` are **NOT PER** — they are RDP's
  little-endian TLVs (16-bit LE type, e.g. CS_CORE=0xC001, SC_CORE=0x0C01).
- Exact `connectPDU`/userData length bytes vary per session with block count; the
  `2A`/`81 2A` values are representative of a minimal block set.

---

## 4. RDP Data Blocks (TS_UD)

All multi-byte integers **little-endian**; "Unicode" = UTF-16LE. Every block
begins with a **TS_UD_HEADER** (§2.2.1.3.1 client / §2.2.1.4.1 server):
`type` (u16) + `length` (u16, total block length **including** the 4-byte header).
Offsets below are from the first header byte; payload starts at offset 4.

Block type constants: CS_CORE=0xC001, CS_SECURITY=0xC002, CS_NET=0xC003,
CS_CLUSTER=0xC004; SC_CORE=0x0C01, SC_SECURITY=0x0C02, SC_NET=0x0C03.

### 4.1 TS_UD_CS_CORE — §2.2.1.3.2, type 0xC001

Fixed portion runs to imeFileName; from postBeta2ColorDepth on, fields are
optional and MUST appear **in order** (a later optional requires all earlier ones).

| Off | Field | Size | Notes |
|---|---|---|---|
| 0 | header.type | 2 | 0xC001 → `01 C0` |
| 2 | header.length | 2 | total block length |
| 4 | version | 4 | see version constants |
| 8 | desktopWidth | 2 | pixels (≤ 4096) |
| 10 | desktopHeight | 2 | pixels (≤ 2048) |
| 12 | colorDepth | 2 | legacy; RNS_UD_COLOR_* |
| 14 | SASSequence | 2 | RNS_UD_SAS_DEL = 0xAA03 |
| 16 | keyboardLayout | 4 | KLID (e.g. 0x00000409 US) |
| 20 | clientBuild | 4 | build number |
| 24 | clientName | 32 | UTF-16LE, null-terminated, 15 chars + NUL max |
| 56 | keyboardType | 4 | 1..7 (4 = 101/102 enhanced, 7 = Japanese) |
| 60 | keyboardSubType | 4 | OEM-dependent |
| 64 | keyboardFunctionKey | 4 | function-key count (usually 12) |
| 68 | imeFileName | 64 | UTF-16LE null-terminated |
| 132 | postBeta2ColorDepth | 2 | OPTIONAL; RNS_UD_COLOR_* |
| 134 | clientProductId | 2 | OPTIONAL; SHOULD be 1 |
| 136 | serialNumber | 4 | OPTIONAL; SHOULD be 0 |
| 140 | highColorDepth | 2 | OPTIONAL; HIGH_COLOR_* |
| 142 | supportedColorDepths | 2 | OPTIONAL; RNS_UD_*BPP_SUPPORT bitmask |
| 144 | earlyCapabilityFlags | 2 | OPTIONAL; RNS_UD_CS_* bitmask |
| 146 | clientDigProductId | 64 | OPTIONAL; UTF-16LE |
| 210 | connectionType | 1 | OPTIONAL; valid only if RNS_UD_CS_VALID_CONNECTION_TYPE set |
| 211 | pad1octet | 1 | OPTIONAL |
| 212 | serverSelectedProtocol | 4 | OPTIONAL; echoes RDP_NEG selectedProtocol |
| 216 | desktopPhysicalWidth | 4 | OPTIONAL; mm (10–10000) |
| 220 | desktopPhysicalHeight | 4 | OPTIONAL; mm |
| 224 | desktopOrientation | 2 | OPTIONAL; 0/90/180/270 |
| 226 | desktopScaleFactor | 4 | OPTIONAL; 100–500 |
| 230 | deviceScaleFactor | 4 | OPTIONAL; 100/140/180 |

**version:** RDP4=0x00080001, RDP5..6.0=0x00080004, RDP6.1=0x00080005,
RDP7=0x00080006, RDP8=0x00080007, RDP8.1=0x00080008, RDP10.x=0x00080009+
(0x00080004 → bytes `04 00 08 00`).
**colorDepth / postBeta2ColorDepth (RNS_UD_COLOR_*):** 8BPP=0xCA01,
16BPP_555=0xCA02, 16BPP_565=0xCA03, 24BPP=0xCA04.
**highColorDepth (HIGH_COLOR_*):** 4BPP=0x0004, 8BPP=0x0008, 15BPP=0x000F,
16BPP=0x0010, 24BPP=0x0018.
**supportedColorDepths (bitmask):** 24BPP=0x0001, 16BPP=0x0002, 15BPP=0x0004, 32BPP=0x0008.
**earlyCapabilityFlags (RNS_UD_CS_*, u16):** SUPPORT_ERRINFO_PDU=0x0001,
WANT_32BPP_SESSION=0x0002, SUPPORT_STATUSINFO_PDU=0x0004,
STRONG_ASYMMETRIC_KEYS=0x0008, UNUSED=0x0010, VALID_CONNECTION_TYPE=0x0020,
SUPPORT_MONITOR_LAYOUT_PDU=0x0040, SUPPORT_NETCHAR_AUTODETECT=0x0080,
SUPPORT_DYNVC_GFX_PROTOCOL=0x0100, SUPPORT_DYNAMIC_TIME_ZONE=0x0200,
SUPPORT_HEARTBEAT_PDU=0x0400, SUPPORT_SKIP_CHANNELJOIN=0x0800.
**connectionType (CONNECTION_TYPE_*):** MODEM=0x01, BROADBAND_LOW=0x02,
SATELLITE=0x03, BROADBAND_HIGH=0x04, WAN=0x05, LAN=0x06, AUTODETECT=0x07.

Concrete CS_CORE prefix (RDP5, 1024×768, 8bpp, US kbd, build 2600):

```
01 C0 D8 00 04 00 08 00 00 04 00 03 01 CA 03 AA 09 04 00 00 28 0A 00 00 ...(clientName 32B UTF16LE)...
```

### 4.2 TS_UD_CS_SEC — §2.2.1.3.3, type 0xC002

| Off | Field | Size |
|---|---|---|
| 0 | header.type | 2 (0xC002 → `02 C0`) |
| 2 | header.length | 2 |
| 4 | encryptionMethods | 4 |
| 8 | extEncryptionMethods | 4 |

`extEncryptionMethods` is used only by French-locale clients (else 0). Under
enhanced security (TLS/CredSSP) `encryptionMethods` SHOULD be 0.
**encryptionMethods flags (u32):** 40BIT=0x00000001, 128BIT=0x00000002,
56BIT=0x00000008, FIPS=0x00000010 (0x04 unused).

Example (40+128 offered): `02 C0 0C 00 03 00 00 00 00 00 00 00`.

### 4.3 TS_UD_CS_NET — §2.2.1.3.4, type 0xC003

| Off | Field | Size |
|---|---|---|
| 0 | header.type | 2 (0xC003 → `03 C0`) |
| 2 | header.length | 2 |
| 4 | channelCount | 4 (max 31) |
| 8 | channelDefArray | channelCount × 12 |

**CHANNEL_DEF (§2.2.1.3.4.1), 12 bytes:** name (8 bytes, ANSI null-terminated,
≤ 7 chars + NUL, unused bytes zeroed) + options (u32).
**options flags:** INITIALIZED=0x80000000, ENCRYPT_RDP=0x40000000,
ENCRYPT_SC=0x20000000, ENCRYPT_CS=0x10000000, PRI_HIGH=0x08000000,
PRI_MED=0x04000000, PRI_LOW=0x02000000, COMPRESS_RDP=0x00800000,
COMPRESS=0x00400000, SHOW_PROTOCOL=0x00200000, REMOTE_CONTROL_PERSISTENT=0x00100000.

Example (1 channel "rdpdr"):
`03 C0 XX XX 01 00 00 00 72 64 70 64 72 00 00 00 <options u32>`.

### 4.4 TS_UD_CS_CLUSTER — §2.2.1.3.5, type 0xC004

| Off | Field | Size |
|---|---|---|
| 0 | header.type | 2 (0xC004 → `04 C0`) |
| 2 | header.length | 2 |
| 4 | Flags | 4 |
| 8 | RedirectedSessionID | 4 (valid only if REDIRECTED_SESSIONID_FIELD_VALID set) |

**Flags (u32):** REDIRECTION_SUPPORTED=0x00000001,
REDIRECTED_SESSIONID_FIELD_VALID=0x00000002,
ServerSessionRedirectionVersionMask=0x0000003C (bits 2–5, value = version<<2),
REDIRECTED_SMARTCARD=0x00000040.
**Redirection version (bits 2–5):** V1=0x00, V2=0x01, V3=0x02, V4=0x03, V5=0x04,
V6=0x05 (V4 → Flags |= 0x03<<2 = 0x0C).

Example (REDIR_SUPPORTED | SESSID_VALID | V4):
`04 C0 0C 00 0F 00 00 00 <sessid u32>` (Flags 0x0F = 0x01|0x02|0x0C).

### 4.5 TS_UD_SC_CORE — §2.2.1.4.2, type 0x0C01

| Off | Field | Size |
|---|---|---|
| 0 | header.type | 2 (0x0C01 → `01 0C`) |
| 2 | header.length | 2 |
| 4 | version | 4 (same encoding as CS_CORE) |
| 8 | clientRequestedProtocols | 4 (OPTIONAL; flags client sent in RDP_NEG_REQ) |
| 12 | earlyCapabilityFlags | 4 (OPTIONAL) |

**earlyCapabilityFlags (server, RNS_UD_SC_*, u32):**
EDGE_ACTIONS_SUPPORTED_V1=0x00000001, DYNAMIC_DST_SUPPORTED=0x00000002,
EDGE_ACTIONS_SUPPORTED_V2=0x00000004, SKIP_CHANNELJOIN_SUPPORTED=0x00000008.

Example: `01 0C 10 00 04 00 08 00 <clientRequestedProtocols u32> <earlyCapabilityFlags u32>`.

### 4.6 TS_UD_SC_NET — §2.2.1.4.4, type 0x0C03

| Off | Field | Size |
|---|---|---|
| 0 | header.type | 2 (0x0C03 → `03 0C`) |
| 2 | header.length | 2 |
| 4 | MCSChannelId | 2 (I/O channel MCS id, typically 0x03EB = 1003) |
| 6 | channelCount | 2 |
| 8 | channelIdArray | channelCount × 2 (u16 MCS ids, same order client listed) |
| 8+2N | Pad | 2 (OPTIONAL; present when channelCount is ODD, aligns to 4 bytes; ignored) |

Example (I/O 1003, 1 chan id 1004, pad because odd):
`03 0C 0C 00 EB 03 01 00 EC 03 00 00`.
**This block gives the client the I/O channel and virtual-channel IDs to join
in §2.4.**

### 4.7 TS_UD_SC_SEC1 — §2.2.1.4.3, type 0x0C02

| Off | Field | Size |
|---|---|---|
| 0 | header.type | 2 (0x0C02 → `02 0C`) |
| 2 | header.length | 2 |
| 4 | encryptionMethod | 4 |
| 8 | encryptionLevel | 4 |
| 12 | serverRandomLen | 4 (OPTIONAL) |
| 16 | serverCertLen | 4 (OPTIONAL) |
| 20 | serverRandom | serverRandomLen bytes (OPTIONAL; typically 32) |
| 20+rlen | serverCertificate | serverCertLen bytes (OPTIONAL; SERVER_CERTIFICATE §2.2.1.4.3.1) |

**Absence rule:** if encryptionMethod=0 AND encryptionLevel=ENCRYPTION_LEVEL_NONE(0),
then serverRandomLen, serverCertLen, serverRandom, serverCertificate are ALL
absent (block is just the two 4-byte fields) — the enhanced TLS/CredSSP case.
**encryptionMethod:** same flags as CS_SEC (40BIT=0x01, 128BIT=0x02, 56BIT=0x08,
FIPS=0x10) but exactly one bit set, or 0.
**encryptionLevel (u32, mutually exclusive):** NONE=0, LOW=1, CLIENT_COMPATIBLE=2,
HIGH=3, FIPS=4.
**serverCertificate:** dwVersion (u32): low 31 bits = CERT_CHAIN_VERSION_1
(0x00000001, proprietary RSA signed cert) or CERT_CHAIN_VERSION_2 (0x00000002,
X.509 chain); top bit 0x80000000 = temporary-cert flag. V1 body =
PROPRIETARYSERVERCERTIFICATE (RSA blob, magic "RSA1"=0x31415352, + signature);
V2 body = X.509 chain.

Example (TLS, no crypto): `02 0C 0C 00 00 00 00 00 00 00 00 00`.

---

## 5. Capability Exchange

All share PDUs ride inside an MCS Send Data Request (C→S) / Send Data Indication
(S→C), preceded by TPKT + X.224 DT. Multi-byte integers **little-endian**.

### 5.1 TS_SHARECONTROLHEADER (§2.2.8.1.1.1.1) — 6 bytes

| Off | Field | Size | Notes |
|---|---|---|---|
| 0 | totalLength | 2 | total bytes of the share-level PDU incl. this header (excl. TPKT/X.224/MCS/security wrappers) |
| 2 | pduType | 2 | bits 0-3 = PDU type; bits 4-15 = TS_PROTOCOL_VERSION (0x1). On-wire = type \| 0x0010 |
| 4 | PDUSource | 2 | MCS user channel ID (server user channel typically 0x03EA = 1002) |

**pduType on-wire values:** PDUTYPE_DEMANDACTIVEPDU=0x1 → `0x0011`;
PDUTYPE_CONFIRMACTIVEPDU=0x3 → `0x0013`; PDUTYPE_DEACTIVATEALLPDU=0x6 → `0x0016`;
PDUTYPE_DATAPDU=0x7 → `0x0017`; PDUTYPE_SERVER_REDIR_PKT=0xA → `0x001A`.

Example (Data PDU, totalLength=0x0016, source=0x03EA): `16 00 17 00 EA 03`.

### 5.2 TS_SHAREDATAHEADER (§2.2.8.1.1.1.2) — 18 bytes

| Off | Field | Size | Notes |
|---|---|---|---|
| 0 | shareControlHeader | 6 | pduType = DATAPDU → 0x0017 |
| 6 | shareId | 4 | |
| 10 | pad1 | 1 | |
| 11 | streamId | 1 | STREAM_UNDEFINED=0, STREAM_LOW=1, STREAM_MED=2, STREAM_HI=4 |
| 12 | uncompressedLength | 2 | |
| 14 | pduType2 | 1 | sub-type selector |
| 15 | compressedType | 1 | PACKET_COMPRESSED=0x20, PACKET_AT_FRONT=0x40, PACKET_FLUSHED=0x80; usually 0 |
| 16 | compressedLength | 2 | 0 when uncompressed |

**pduType2 constants:** PDUTYPE2_UPDATE=2, PDUTYPE2_CONTROL=20 (0x14),
PDUTYPE2_POINTER=27, PDUTYPE2_INPUT=28, PDUTYPE2_SYNCHRONIZE=31 (0x1F),
PDUTYPE2_REFRESH_RECT=33, PDUTYPE2_SUPPRESS_OUTPUT=35,
PDUTYPE2_SHUTDOWN_REQUEST=36, PDUTYPE2_SAVE_SESSION_INFO=38,
PDUTYPE2_FONTLIST=39 (0x27), PDUTYPE2_FONTMAP=40 (0x28),
PDUTYPE2_SET_ERROR_INFO_PDU=47, PDUTYPE2_MONITOR_LAYOUT_PDU=55.

### 5.3 Demand Active PDU (§2.2.1.13.1) — server→client

`TS_DEMAND_ACTIVE_PDU`:

- shareControlHeader (6; pduType → `0x0011`)
- shareId u32 — the share identifier the session will use
- lengthSourceDescriptor u16 — bytes of sourceDescriptor (commonly 4: "RDP\0")
- lengthCombinedCapabilities u16 — bytes of (numberCapabilities + pad2Octets + all capabilitySets)
- sourceDescriptor — lengthSourceDescriptor bytes (ANSI, e.g. "RDP\0")
- numberCapabilities u16 — count of TS_CAPS_SET
- pad2Octets u16
- capabilitySets — array of TS_CAPS_SET
- sessionId u32 — trailing field

### 5.4 Confirm Active PDU (§2.2.1.13.2) — client→server

`TS_CONFIRM_ACTIVE_PDU`:

- shareControlHeader (6; pduType → `0x0013`)
- shareId u32 — MUST echo the Demand Active shareId
- originatorId u16 — MUST be 0x03EA (server channel ID, 1002)
- lengthSourceDescriptor u16
- lengthCombinedCapabilities u16
- sourceDescriptor — e.g. "MSTSC\0"
- numberCapabilities u16
- pad2Octets u16
- capabilitySets — array of TS_CAPS_SET

(No trailing sessionId — that plus originatorId are the differences from Demand Active.)

### 5.5 TS_CAPS_SET header (§2.2.1.13.1.1.1)

- capabilitySetType u16
- lengthCapability u16 — total bytes of this cap set **including** the 4-byte header
- capabilityData — (lengthCapability − 4) bytes

**Capability set types (§2.2.7):** CAPSTYPE_GENERAL=0x0001, CAPSTYPE_BITMAP=0x0002,
CAPSTYPE_ORDER=0x0003, CAPSTYPE_BITMAPCACHE=0x0004, CAPSTYPE_CONTROL=0x0005,
CAPSTYPE_ACTIVATION=0x0007, CAPSTYPE_POINTER=0x0008, CAPSTYPE_SHARE=0x0009,
CAPSTYPE_COLORCACHE=0x000A, CAPSTYPE_SOUND=0x000C, CAPSTYPE_INPUT=0x000D (13),
CAPSTYPE_FONT=0x000E (14), CAPSTYPE_BRUSH=0x000F, CAPSTYPE_GLYPHCACHE=0x0010,
CAPSTYPE_OFFSCREENCACHE=0x0011, CAPSTYPE_BITMAPCACHE_HOSTSUPPORT=0x0012,
CAPSTYPE_BITMAPCACHE_REV2=0x0013, CAPSTYPE_VIRTUALCHANNEL=0x0014 (20),
CAPSTYPE_DRAWNINEGRIDCACHE=0x0015, CAPSTYPE_DRAWGDIPLUS=0x0016, CAPSTYPE_RAIL=0x0017,
CAPSTYPE_WINDOW=0x0018, CAPSETTYPE_COMPDESK=0x0019,
CAPSETTYPE_MULTIFRAGMENTUPDATE=0x001A, CAPSETTYPE_LARGE_POINTER=0x001B,
CAPSETTYPE_SURFACE_COMMANDS=0x001C, CAPSETTYPE_BITMAP_CODECS=0x001D,
CAPSSETTYPE_FRAME_ACKNOWLEDGE=0x001E.

#### General Capability Set (§2.2.7.1.1) — type 0x0001, lengthCapability 0x0018 (24)

- osMajorType u16 — UNSPECIFIED=0, WINDOWS=1, OS2=2, MACINTOSH=3, UNIX=4, IOS=5, OSX=6, ANDROID=7, CHROME_OS=8
- osMinorType u16 — e.g. WINDOWS_NT=3
- protocolVersion u16 = TS_CAPS_PROTOCOLVERSION = 0x0200 (MUST)
- pad2octetsA u16
- generalCompressionTypes u16 = 0 (MUST)
- extraFlags u16 — FASTPATH_OUTPUT_SUPPORTED=0x0001, LONG_CREDENTIALS_SUPPORTED=0x0004, AUTORECONNECT_SUPPORTED=0x0008, ENC_SALTED_CHECKSUM=0x0010, NO_BITMAP_COMPRESSION_HDR=0x0400
- updateCapabilityFlag u16 = 0 (MUST)
- remoteUnshareFlag u16 = 0 (MUST)
- generalCompressionLevel u16 = 0 (MUST)
- refreshRectSupport u8 — 0/1
- suppressOutputSupport u8 — 0/1

Header + first fields: `01 00 18 00 01 00 03 00 00 02 ...` (type, len, osMajor=1, osMinor=3, protocolVersion=0x0200).

#### Bitmap Capability Set (§2.2.7.1.2) — type 0x0002, lengthCapability 0x001C (28)

- preferredBitsPerPixel u16 — color depth (8/15/16/24/32)
- receive1BitPerPixel u16 — ignored, SHOULD be 1
- receive4BitsPerPixel u16 — ignored, SHOULD be 1
- receive8BitsPerPixel u16 — ignored, SHOULD be 1
- desktopWidth u16
- desktopHeight u16
- pad2octets u16
- desktopResizeFlag u16 — 0x0001 if resize supported
- bitmapCompressionFlag u16 = 0x0001 (MUST)
- highColorFlags u8 = 0 (ignored)
- drawingFlags u8 — DRAW_ALLOW_DYNAMIC_COLOR_FIDELITY=0x02, DRAW_ALLOW_COLOR_SUBSAMPLING=0x04, DRAW_ALLOW_SKIP_ALPHA=0x08, DRAW_UNUSED_FLAG=0x10
- multipleRectangleSupport u16 = 0x0001 (MUST)
- pad2octetsB u16

#### Order Capability Set (§2.2.7.1.3) — type 0x0003, lengthCapability 0x0058 (88)

terminalDescriptor (16), pad4octetsA (4), desktopSaveXGranularity u16,
desktopSaveYGranularity u16, pad2octetsA u16, maximumOrderLevel u16,
numberFonts u16, orderFlags u16, **orderSupport[32]** (per-primary-order enable
bytes), textFlags u16, orderSupportExFlags u16, pad4octetsB u32,
desktopSaveSize u32, pad2octetsC/D, textANSICodePage u16, pad2octetsE u16.

#### Pointer Capability Set (§2.2.7.1.5) — type 0x0008, lengthCapability 0x000A (10)

- colorPointerFlag u16
- colorPointerCacheSize u16
- pointerCacheSize u16

#### Input Capability Set (§2.2.7.1.6) — type 0x000D (13), lengthCapability 0x0058 (88)

- inputFlags u16 — INPUT_FLAG_SCANCODES=0x0001, INPUT_FLAG_MOUSEX=0x0004, INPUT_FLAG_FASTPATH_INPUT=0x0008, INPUT_FLAG_UNICODE=0x0010, INPUT_FLAG_FASTPATH_INPUT2=0x0020, INPUT_FLAG_UNUSED1=0x0040, INPUT_FLAG_MOUSE_RELATIVE=0x0080, TS_INPUT_FLAG_MOUSE_HWHEEL=0x0100, TS_INPUT_FLAG_QOE_TIMESTAMPS=0x0200
- pad2octetsA u16
- keyboardLayout u32 — active input locale (KLID), e.g. 0x00000409; ignored in server copy
- keyboardType u32 — e.g. 4 = IBM enhanced (101/102)
- keyboardSubType u32
- keyboardFunctionKey u32 — number of function keys (e.g. 12)
- imeFileName — 64 bytes UTF-16LE, null-padded

#### Share Capability Set (§2.2.7.2.4) — type 0x0009, lengthCapability 0x0008 (8)

- nodeId u16 (server sets 0x03EA; client sets 0)
- pad2octets u16

#### Font Capability Set (§2.2.7.2.5) — type 0x000E (14), lengthCapability 0x0008 (8)

- fontSupportFlags u16 (FONTSUPPORT_FONTLIST=0x0001)
- pad2octets u16

#### Virtual Channel Capability Set (§2.2.7.1.10) — type 0x0014 (20), lengthCapability 8 (or 12)

- flags u32 — VCCAPS_NO_COMPR=0x00000000, VCCAPS_COMPR_SC=0x00000001, VCCAPS_COMPR_CS_8K=0x00000002
- VCChunkSize u32 — OPTIONAL (max chunk size, e.g. 1600); present → lengthCapability 12

#### Color Table Cache Capability Set (§2.2.7.1.4) — type 0x000A, lengthCapability 0x0008 (8)

- colorTableCacheSize u16 (SHOULD be 6)
- pad2octets u16

### 5.6 Minimal viable client capability set

The smallest set most servers accept in Confirm Active (send in this order):

1. **General** (0x0001) — protocolVersion 0x0200, extraFlags FASTPATH_OUTPUT_SUPPORTED.
2. **Bitmap** (0x0002) — preferredBitsPerPixel = your color depth, desktopWidth/Height, bitmapCompressionFlag=1, multipleRectangleSupport=1.
3. **Order** (0x0003) — orderFlags with NEGOTIATEORDERSUPPORT=0x0002; orderSupport[] may be all-zero to force bitmap-only rendering (simplest first client).
4. **Pointer** (0x0008) — colorPointerFlag=1, cache sizes (e.g. 20/20).
5. **Input** (0x000D) — inputFlags INPUT_FLAG_SCANCODES | INPUT_FLAG_MOUSEX (add FASTPATH_INPUT2 if you implement fast-path input), keyboardLayout/Type.
6. **Share** (0x0009) — nodeId=0, pad.
7. **VirtualChannel** (0x0014) — flags=VCCAPS_NO_COMPR (only if you advertised channels in CS_NET).

Also commonly required by real servers: **Color Table Cache** (0x000A),
**Font** (0x000E), and **Bitmap Cache** (0x0004 or Rev2 0x0013) — a bitmap-only
client can send Bitmap Cache with all cache entries zeroed. A client that renders
only bitmaps (no drawing orders) can safely leave orderSupport[] zeroed and omit
glyph/brush/offscreen caches.

---

## 6. Client Info PDU + License + Finalization PDUs

Ordering (§1.3.1.1) after capability exchange: **client** sends Synchronize,
Control(Cooperate), Control(Request Control), Font List; **server** sends
Synchronize, Control(Cooperate), Control(Granted Control), Font Map. Receipt of
the server Font Map (pduType2 0x28) completes the connection sequence.

### 6.1 Client Info PDU (§2.2.1.11) — client→server

Framing: TPKT / X.224 Data / MCS SendDataRequest / **Basic Security Header**
(flags contains SEC_INFO_PKT=0x0040; under standard RDP security also
SEC_ENCRYPT=0x0008) / TS_INFO_PACKET. **Not** wrapped in a shareControlHeader —
it sits directly after the security header.

#### TS_INFO_PACKET (§2.2.1.11.1.1)

| Off | Field | Size | Notes |
|---|---|---|---|
| 0 | CodePage | 4 | ANSI code page if INFO_UNICODE unset, else active input locale (may be 0) |
| 4 | flags | 4 | see below |
| 8 | cbDomain | 2 | bytes of Domain, **excluding** null terminator (max 512) |
| 10 | cbUserName | 2 | bytes, excluding terminator (max 512) |
| 12 | cbPassword | 2 | bytes, excluding terminator (max 512) |
| 14 | cbAlternateShell | 2 | bytes, excluding terminator (max 512) |
| 16 | cbWorkingDir | 2 | bytes, excluding terminator (max 512) |
| 18 | Domain | cbDomain + terminator | Unicode text + 2-byte NUL (or 1+1 if ANSI); present even when zero-length |
| … | UserName | cbUserName + terminator | |
| … | Password | cbPassword + terminator | |
| … | AlternateShell | cbAlternateShell + terminator | |
| … | WorkingDir | cbWorkingDir + terminator | |
| … | extraInfo | TS_EXTENDED_INFO_PACKET | present for RDP 5.0+ (keyed off negotiated version, not a flag) |

**flags (u32):** INFO_MOUSE=0x00000001, INFO_DISABLECTRLALTDEL=0x00000002,
INFO_AUTOLOGON=0x00000008, INFO_UNICODE=0x00000010, INFO_MAXIMIZESHELL=0x00000020,
INFO_LOGONNOTIFY=0x00000040, INFO_COMPRESSION=0x00000080 (type in mask
CompressionTypeMask=0x00001E00), INFO_ENABLEWINDOWSKEY=0x00000100,
INFO_REMOTECONSOLEAUDIO=0x00002000, INFO_FORCE_ENCRYPTED_CS_PDU=0x00004000,
INFO_RAIL=0x00008000, INFO_LOGONERRORS=0x00010000, INFO_MOUSE_HAS_WHEEL=0x00020000,
INFO_PASSWORD_IS_SC_PIN=0x00040000, INFO_NOAUDIOPLAYBACK=0x00080000,
INFO_USING_SAVED_CREDS=0x00100000, INFO_AUDIOCAPTURE=0x00200000,
INFO_VIDEO_DISABLE=0x00400000, INFO_HIDEF_RAIL_SUPPORTED=0x02000000.

**KEY RULE:** the cb* fields in TS_INFO_PACKET measure the string **without** the
null terminator, but each string is still followed by its terminator on the wire
(2 bytes for Unicode). This **differs** from TS_EXTENDED_INFO_PACKET's cb*, which
**include** the terminator.

**Under NLA/CredSSP:** credentials arrive during CredSSP, so Password is empty —
cbPassword=0 with only the 2-byte NUL present (`00 00`). Domain/UserName may still
be populated (INFO_AUTOLOGON often set).

#### TS_EXTENDED_INFO_PACKET (§2.2.1.11.1.1.1)

- clientAddressFamily u16 — AF_INET=0x0002, AF_INET6=0x0017 (23)
- cbClientAddress u16 — bytes of clientAddress **including** terminator
- clientAddress — Unicode, cbClientAddress bytes
- cbClientDir u16 — bytes **including** terminator
- clientDir — Unicode, cbClientDir bytes
- clientTimeZone — TS_TIME_ZONE_INFORMATION (fixed 172 bytes)
- clientSessionId u32 — 0 on first connect
- performanceFlags u32 — PERF_DISABLE_WALLPAPER=0x01, PERF_DISABLE_FULLWINDOWDRAG=0x02, PERF_DISABLE_MENUANIMATIONS=0x04, PERF_DISABLE_THEMING=0x08, PERF_DISABLE_CURSOR_SHADOW=0x20, PERF_DISABLE_CURSORSETTINGS=0x40, PERF_ENABLE_FONT_SMOOTHING=0x80, PERF_ENABLE_DESKTOP_COMPOSITION=0x100
- cbAutoReconnectLen u16 — 0 if none
- autoReconnectCookie — ARC_CS_PRIVATE_PACKET (28 bytes) when present
- reserved1 u16, reserved2 u16 (RDP 6.1+)
- cbDynamicDSTTimeZoneKeyName u16, dynamicDSTTimeZoneKeyName (Unicode), dynamicDaylightTimeDisabled u16 (RDP 7.0+) — all version-gated/optional

#### TS_TIME_ZONE_INFORMATION (§2.2.1.11.1.1.1.1) — 172 bytes

Bias i32 (UTC = local + Bias), StandardName (64, Unicode 32 wchars),
StandardDate (16, TS_SYSTEMTIME), StandardBias i32, DaylightName (64),
DaylightDate (16), DaylightBias i32.
**TS_SYSTEMTIME (16 bytes):** wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute,
wSecond, wMilliseconds — all u16.

### 6.2 Server License Error PDU — Valid Client (§2.2.1.12)

Framing: TPKT / X.224 Data / MCS SendDataIndication / Security Header (flags
contains SEC_LICENSE_PKT=0x0080) / validClientLicenseData.

**LICENSE_VALID_CLIENT_DATA (§2.2.1.12.1):**

- **preamble (LICENSE_PREAMBLE, 4 bytes):**
  - bMsgType u8 = ERROR_ALERT = 0xFF
  - flags u8 — LicenseProtocolVersionMask=0x0F (version 3 = 0x03); EXTENDED_ERROR_MSG_SUPPORTED=0x80
  - wMsgSize u16 — total size incl. preamble (typically 0x0010 = 16)
- **validClientMessage (LICENSE_ERROR_MESSAGE §2.2.1.12.1.3):**
  - dwErrorCode u32 = STATUS_VALID_CLIENT = 0x00000007. (Others:
    ERR_INVALID_SERVER_CERTIFICATE=0x01, ERR_NO_LICENSE=0x02, ERR_INVALID_MAC=0x03,
    ERR_INVALID_SCOPE=0x04, ERR_NO_LICENSE_SERVER=0x06, STATUS_VALID_CLIENT=0x07,
    ERR_INVALID_CLIENT=0x08.)
  - dwStateTransition u32 = ST_NO_TRANSITION = 0x00000002. (ST_TOTAL_ABORT=0x01,
    ST_NO_TRANSITION=0x02, ST_RESET_PHASE_TO_START=0x03, ST_RESEND_LAST_MESSAGE=0x04.)
  - blob (LICENSE_BINARY_BLOB §2.2.1.12.1.2): wBlobType u16 = BB_ERROR_BLOB=0x0004
    (may be 0 and ignored here), wBlobLen u16 = 0x0000, no body follows.

The 0x00000007 message tells the client licensing succeeded (or none required)
and to proceed to capability exchange.

Body bytes: preamble `FF 03 10 00`; dwErrorCode `07 00 00 00`;
dwStateTransition `02 00 00 00`; blob `04 00 00 00`.

### 6.3 Finalization PDUs (all wrapped in TS_SHAREDATAHEADER)

#### TS_SYNCHRONIZE_PDU (§2.2.1.14.1) — pduType2 = PDUTYPE2_SYNCHRONIZE = 31 (0x1F)

- shareDataHeader (18)
- messageType u16 = SYNCMSGTYPE_SYNC = 0x0001
- targetUser u16 — MCS channel ID of the other party (client puts the server user channel here; server copy ignored)

Body: `01 00 <targetUser u16>` — e.g. `01 00 EA 03`.

#### TS_CONTROL_PDU (§2.2.1.15.1) — pduType2 = PDUTYPE2_CONTROL = 20 (0x14)

- shareDataHeader (18)
- action u16 — CTRLACTION_REQUEST_CONTROL=0x0001, CTRLACTION_GRANTED_CONTROL=0x0002, CTRLACTION_DETACH=0x0003, CTRLACTION_COOPERATE=0x0004
- grantId u16 — 0 for cooperate/request; in Granted Control = client's PDUSource/user channel
- controlId u32 — 0 for cooperate/request; in Granted Control = server's identifier

Cooperate full share-level bytes (shareId=0x000103EA, streamId=STREAM_LOW):
```
shareControlHeader  16 00 17 00 EA 03
shareId             EA 03 01 00
pad1                00
streamId            01
uncompressedLength  16 00
pduType2            14
compressedType      00
compressedLength    00 00
action              04 00
grantId             00 00
controlId           00 00 00 00
```

#### TS_FONTLIST_PDU (§2.2.1.18.1) — pduType2 = PDUTYPE2_FONTLIST = 39 (0x27)

- shareDataHeader (18)
- numberFonts u16 = 0 (SHOULD)
- totalNumFonts u16 = 0 (SHOULD)
- listFlags u16 = 0x0003 (FONTLIST_FIRST=0x0001 | FONTLIST_LAST=0x0002)
- entrySize u16 = 0x0032 (50)

#### TS_FONTMAP_PDU (§2.2.1.22.1) — pduType2 = PDUTYPE2_FONTMAP = 40 (0x28)

- shareDataHeader (18)
- numberEntries u16 = 0 (SHOULD)
- totalNumEntries u16 = 0 (SHOULD)
- mapFlags u16 = 0x0003 (FONTMAP_FIRST=0x0001 | FONTMAP_LAST=0x0002)
- entrySize u16 = 0x0004

Receipt of the server Font Map (0x28) completes the connection sequence; the
session then enters the data/graphics phase.

---

## 7. Open Questions / Low-Confidence

1. **MCS domain-PDU leading bytes (§2).** The CHOICE-index → leading-byte mapping
   (`04`, `28`, `2E`, `38`, `3E`, `64`, `68`) and the Erect Domain / Attach User
   fixed forms are widely reproduced by real clients and match `(index << 2)`, but
   the exact PER bit-packing of the low bits (padding vs. segmentation flags) was
   reconstructed from the wire forms, not derived field-by-field from T.125 PER
   here. Verify the Send Data `dataPriority + segmentation` byte (`0x70` used
   above) against the T.125 `DataPriority`/`Segmentation` encoding for your target
   servers — some stacks emit `0x40`.

2. **Connect-Initial worked byte counts (§1.6).** The 307-byte GCC blob and the
   resulting 408/420 totals are internally consistent but illustrative; real byte
   counts vary with the number of channels and optional CS_CORE fields. Do not
   hard-code these lengths — compute them.

3. **DomainParameters INTEGER sign encoding (§1.4).** Confirmed that stacks are
   inconsistent (`02 02 FF FF` vs `02 03 00 FF FF` for 65535). Emit the canonical
   `02 02 FF FF` target set for maximum interop; parse both. Server-chosen
   minimum/maximum values differ per implementation.

4. **GCC representative length bytes (§3).** `2A` / `81 2A` connectPDU lengths and
   the `81 <userDataLen>` fields are representative of a minimal block set; the
   `conferenceName` numeric encoding (`00 10` + pad) and the `08` optional-field
   bitmap are the values real clients emit but depend on which CCR optional fields
   you populate. Recompute lengths from actual block sizes.

5. **serverSelectedProtocol / clientRequestedProtocols echo (§4.1, §4.5).** The
   4-byte protocol flag values (RDP=0x0, SSL=0x1, HYBRID=0x2, HYBRID_EX=0x8) are
   from RDP_NEG; whether the server includes the optional SC_CORE fields depends
   on version and negotiated security — treat SC_CORE tail fields as optional and
   length-gated.

6. **Order capability set field layout (§5.5).** The 88-byte Order cap set fields
   after orderSupport[32] (textFlags, orderSupportExFlags, desktopSaveSize, code
   page) are listed to scale but exact offsets should be checked against
   §2.2.7.1.3 before you populate anything beyond orderSupport[] — a bitmap-only
   client zeroes orderSupport[] and can ignore the tail.

7. **Minimal capability set acceptance (§5.6).** Which cap sets a given server
   *requires* in Confirm Active varies (Windows vs FreeRDP vs xrdp). The list is a
   safe starting point; if Confirm Active is rejected, add Bitmap Cache (0x0004 /
   Rev2 0x0013), Color Cache (0x000A), Glyph Cache (0x0010), and Brush (0x000F)
   with conservative/zeroed contents.

8. **Client Info extraInfo presence (§6.1).** TS_EXTENDED_INFO_PACKET presence is
   keyed off the negotiated RDP version rather than a flag; confirm your target
   servers accept it for the version you advertise in CS_CORE.version.
