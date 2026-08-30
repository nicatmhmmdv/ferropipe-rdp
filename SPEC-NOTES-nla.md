# RDP NLA Implementation Reference: CredSSP + NTLMv2 (Native Rust)

A single, self-contained specification for implementing RDP Network Level Authentication. All numeric constants and hex vectors are drawn from [MS-NLMP] and [MS-CSSP] and preserved verbatim. Every multi-byte integer is **little-endian** unless stated otherwise.

---

## Part 1 — NTLM Message Wire Layout

### 1.1 Endianness rules

- Multi-byte integers (`MessageType`, `NegotiateFlags`, the 2-byte `Len`/`MaxLen`, the 4-byte `BufferOffset`, `SeqNum`, signature `Version`) are **little-endian**.
- The 8-byte `Signature` `"NTLMSSP\0"`, the raw 8-byte challenges, `NTProofStr`, and the 16-byte MIC are **byte strings**, not integers — no byte-swap.

### 1.2 Security-buffer / field descriptor (8 bytes)

Every variable payload (domain, user, workstation, target name, target info, LM/NT responses, session key) is referenced by an 8-byte descriptor in the fixed header; payload bytes are appended after the header.

| Off | Size | Field | Meaning |
|----|----|----|----|
| 0 | 2 | `Len` | Actual byte length of payload present |
| 2 | 2 | `MaxLen` | Reserved space; senders SHOULD set == `Len`; receivers MUST treat as `Len` |
| 4 | 4 | `BufferOffset` | Offset of payload **from start of whole message** (byte 0 = Signature) |

Rules: fixed header first, all payloads concatenated after it (order implementation-defined). `Len == 0` ⇒ field absent.

### 1.3 NEGOTIATE_MESSAGE (§2.2.1.1) — client → server

| Off | Size | Field | Value / notes |
|----|----|----|----|
| 0 | 8 | Signature | `4E 54 4C 4D 53 53 50 00` = `"NTLMSSP\0"` |
| 8 | 4 | MessageType | `01 00 00 00` (= 1) |
| 12 | 4 | NegotiateFlags | LE flag dword |
| 16 | 8 | DomainNameFields | descriptor (present iff `NEGOTIATE_OEM_DOMAIN_SUPPLIED`) |
| 24 | 8 | WorkstationFields | descriptor (present iff `NEGOTIATE_OEM_WORKSTATION_SUPPLIED`) |
| 32 | 8 | Version | present iff `NEGOTIATE_VERSION`; else omitted |
| 32/40 | var | Payload | domain/workstation bytes |

Fixed header = **32 bytes** without Version, **40 bytes** with Version.

### 1.4 CHALLENGE_MESSAGE (§2.2.1.2) — server → client

| Off | Size | Field | Value / notes |
|----|----|----|----|
| 0 | 8 | Signature | `"NTLMSSP\0"` |
| 8 | 4 | MessageType | `02 00 00 00` (= 2) |
| 12 | 8 | TargetNameFields | descriptor |
| 20 | 4 | NegotiateFlags | LE flag dword |
| 24 | 8 | ServerChallenge | 8-byte nonce (raw) |
| 32 | 8 | Reserved | MUST be 0 |
| 40 | 8 | TargetInfoFields | descriptor → AV_PAIR list |
| 48 | 8 | Version | present iff `NEGOTIATE_VERSION` |
| 48/56 | var | Payload | TargetName + TargetInfo |

Fixed header = **48 bytes** without Version, **56 bytes** with Version.

### 1.5 AUTHENTICATE_MESSAGE (§2.2.1.3) — client → server

| Off | Size | Field | Value / notes |
|----|----|----|----|
| 0 | 8 | Signature | `"NTLMSSP\0"` |
| 8 | 4 | MessageType | `03 00 00 00` (= 3) |
| 12 | 8 | LmChallengeResponseFields | descriptor |
| 20 | 8 | NtChallengeResponseFields | descriptor |
| 28 | 8 | DomainNameFields | descriptor |
| 36 | 8 | UserNameFields | descriptor |
| 44 | 8 | WorkstationFields | descriptor |
| 52 | 8 | EncryptedRandomSessionKeyFields | descriptor |
| 60 | 4 | NegotiateFlags | LE flag dword |
| 64 | 8 | Version | present iff `NEGOTIATE_VERSION` |
| 72 | 16 | MIC | present iff client emits a MIC |
| 72/88 | var | Payload | LM resp, NT resp, domain, user, workstation, enc session key |

Header sizes: **64** (no Version, no MIC); **72** (Version, no MIC); **88 bytes** when both Version and MIC present — the normal modern case. A client that writes a MIC always writes Version, so **MIC sits at fixed offset 72 (0x48)** and payloads start at **0x58 (88)**.

### 1.6 NegotiateFlags bit values (§2.2.2.5)

Diagrams number bits MSB-first (flag "A" = `0x00000001`). Values are stored LE on the wire.

| Name | Value |
|----|----|
| NTLMSSP_NEGOTIATE_UNICODE | 0x00000001 |
| NTLM_NEGOTIATE_OEM | 0x00000002 |
| NTLMSSP_REQUEST_TARGET | 0x00000004 |
| NTLMSSP_NEGOTIATE_SIGN | 0x00000010 |
| NTLMSSP_NEGOTIATE_SEAL | 0x00000020 |
| NTLMSSP_NEGOTIATE_DATAGRAM | 0x00000040 |
| NTLMSSP_NEGOTIATE_LM_KEY | 0x00000080 |
| NTLMSSP_NEGOTIATE_NTLM | 0x00000200 |
| NTLMSSP_NEGOTIATE_ANONYMOUS | 0x00000800 |
| NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED | 0x00001000 |
| NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED | 0x00002000 |
| NTLMSSP_NEGOTIATE_ALWAYS_SIGN | 0x00008000 |
| NTLMSSP_TARGET_TYPE_DOMAIN | 0x00010000 |
| NTLMSSP_TARGET_TYPE_SERVER | 0x00020000 |
| NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | 0x00080000 |
| NTLMSSP_NEGOTIATE_IDENTIFY | 0x00100000 |
| NTLMSSP_REQUEST_NON_NT_SESSION_KEY | 0x00400000 |
| NTLMSSP_NEGOTIATE_TARGET_INFO | 0x00800000 |
| NTLMSSP_NEGOTIATE_VERSION | 0x02000000 |
| NTLMSSP_NEGOTIATE_128 | 0x20000000 |
| NTLMSSP_NEGOTIATE_KEY_EXCH | 0x40000000 |
| NTLMSSP_NEGOTIATE_56 | 0x80000000 |

Reserved bits: r10=0x8, r9=0x100, r8=0x400, r7=0x4000, r6=0x40000, r5=0x200000, r4=0x1000000, r3=0x4000000, r2=0x8000000, r1=0x10000000.

**Typical CredSSP client flag set:** UNICODE(0x1) | NTLM(0x200) | EXTENDED_SESSIONSECURITY(0x80000) | ALWAYS_SIGN(0x8000) | KEY_EXCH(0x40000000) | SEAL(0x20) | SIGN(0x10) | TARGET_INFO(0x800000) | VERSION(0x2000000) | 128(0x20000000) | 56(0x80000000).

### 1.7 VERSION structure (§2.2.2.10) — 8 bytes

| Off | Size | Field | Notes |
|----|----|----|----|
| 0 | 1 | ProductMajorVersion | e.g. 6, 10 |
| 1 | 1 | ProductMinorVersion | e.g. 1 |
| 2 | 2 | ProductBuild | LE uint16 |
| 4 | 3 | Reserved | MUST be 0 |
| 7 | 1 | NTLMRevisionCurrent | `0x0F` = NTLMSSP_REVISION_W2K3; `0x00` = unknown |

Example (Windows 6.1 build 7601): `06 01 B1 1D 00 00 00 0F`.
Sample used in the §4.2 test vectors: `06 00 70 17 00 00 00 0F` (Major 6, Minor 0, Build 6000, revision 0x0F).

### 1.8 AV_PAIR structure and AvId values (§2.2.2.1)

Each AV_PAIR: `AvId` (LE u16) | `AvLen` (LE u16, byte length of Value) | `Value` (`AvLen` bytes). The list lives in TargetInfo (CHALLENGE) and inside the NTLMv2 `temp` blob (AUTHENTICATE). Terminated by an `MsvAvEOL` pair with `AvLen=0`.

| AvId | Value | Meaning |
|----|----|----|
| MsvAvEOL | 0x0000 | End of list; AvLen=0 |
| MsvAvNbComputerName | 0x0001 | Server NetBIOS computer name (Unicode) |
| MsvAvNbDomainName | 0x0002 | Server NetBIOS domain name (Unicode) |
| MsvAvDnsComputerName | 0x0003 | Server FQDN (Unicode) |
| MsvAvDnsDomainName | 0x0004 | DNS domain name (Unicode) |
| MsvAvDnsTreeName | 0x0005 | DNS forest/tree name (Unicode) |
| MsvAvFlags | 0x0006 | 32-bit flags; 0x1=auth constrained, **0x2 = MIC present**, 0x4=SPN untrusted |
| MsvAvTimestamp | 0x0007 | 8-byte FILETIME (LE) |
| MsvAvSingleHost | 0x0008 | Single_Host_Data restriction blob |
| MsvAvTargetName | 0x0009 | SPN of target server (Unicode) |
| MsvAvChannelBindings | 0x000A | 16-byte MD5 hash of gss_channel_bindings_struct |

### 1.9 MIC placement and computation (§2.2.1.3, §3.1.5.1.2, §3.2.2)

- 16-byte field at fixed offset **72 (0x48)** whenever Version (bytes 64–71) is present. No descriptor — inline, fixed-position. Position = `NegotiateFlags(60)+4 = 64`, `+8 Version = 72`.
- Client signals MIC presence by adding an **MsvAvFlags** AV_PAIR (`0x0006`) in the NtChallengeResponse AV_PAIR list with the **0x00000002** bit set.
- Computation:
  1. Build full AUTHENTICATE_MESSAGE with all payloads, MIC bytes at offset 72 set to **zero**.
  2. `MIC = HMAC_MD5(ExportedSessionKey, NEGOTIATE_MESSAGE ‖ CHALLENGE_MESSAGE ‖ AUTHENTICATE_MESSAGE)` — three complete messages in that order, AUTHENTICATE MIC region zeroed.
  3. Overwrite the 16 zero bytes at offset 72 with the digest.
- Server recomputes identically (zeroing received MIC) and compares; mismatch ⇒ `SEC_E_MESSAGE_ALTERED`.

---

## Part 2 — NTLMv2 Key Computation (Ordered Pseudo-code)

### Conventions

- `UNICODE(x)` = x as little-endian UTF-16, no BOM.
- `‖` = concatenation. `Z(n)` = n zero bytes. `HMAC_MD5(k, m)` = RFC 2104 HMAC-MD5. `MD4` = RFC 1320. `RC4K(k, d)` = RC4-encrypt d under fresh key k. `NIL` = empty.
- All multi-byte integers little-endian.

### Step 1 — NTOWFv2 / LMOWFv2 (§3.3.2)

```
NTOWFv2(Passwd, User, UserDom) =
    HMAC_MD5( MD4(UNICODE(Passwd)),
              UNICODE( Uppercase(User) ‖ UserDom ) )
LMOWFv2 = NTOWFv2      // identical in NTLMv2
ResponseKeyNT = ResponseKeyLM = NTOWFv2
```

**Gotcha:** only the username is uppercased; the domain is concatenated **as-is** (never case-folded).

### Step 2 — temp / blob (§3.3.2)

```
temp = Responserversion(0x01)      // 1 byte
     ‖ HiResponserversion(0x01)    // 1 byte
     ‖ Z(6)                        // 6 zero bytes  (NOT 8)
     ‖ Time                        // 8 bytes, FILETIME (100ns since 1601), LE
     ‖ ClientChallenge             // 8 bytes
     ‖ Z(4)
     ‖ ServerName                  // TargetInfo AV_PAIR list copied VERBATIM from CHALLENGE
     ‖ Z(4)                        // trailing 4 zero bytes (part of temp)
```

### Step 3 — NTProofStr and NtChallengeResponse (§3.3.2)

```
NTProofStr          = HMAC_MD5( ResponseKeyNT, ServerChallenge ‖ temp )
NtChallengeResponse = NTProofStr ‖ temp
```

### Step 4 — LmChallengeResponse (§3.3.2)

```
LmChallengeResponse = HMAC_MD5( ResponseKeyLM, ServerChallenge ‖ ClientChallenge )
                    ‖ ClientChallenge                       // 16 + 8 = 24 bytes
```

### Step 5 — SessionBaseKey (§3.3.2)

```
SessionBaseKey = HMAC_MD5( ResponseKeyNT, NTProofStr )     // keyed by NTOWFv2, message = NTProofStr only
```

### Step 6 — KeyExchangeKey (§3.4.5.1 KXKEY)

```
KeyExchangeKey = SessionBaseKey                             // unconditional for NTLMv2
```

### Step 7 — ExportedSessionKey & EncryptedRandomSessionKey (§3.4.5.2 / §3.1.5.1.2)

```
if NTLMSSP_NEGOTIATE_KEY_EXCH set:
    ExportedSessionKey        = NONCE(16)                   // fresh random 16 bytes
    EncryptedRandomSessionKey = RC4K( KeyExchangeKey, ExportedSessionKey )
else:
    ExportedSessionKey        = KeyExchangeKey
    EncryptedRandomSessionKey = NIL
```

`ExportedSessionKey` is the master key for SIGNKEY/SEALKEY derivation (Part 4).

### Step 8 — MIC (§3.1.5.1.2, §3.2.2)

```
// MIC field (offset 72, 16 bytes) zeroed inside AUTHENTICATE before hashing
MIC = HMAC_MD5( ExportedSessionKey,
                NEGOTIATE_MESSAGE ‖ CHALLENGE_MESSAGE ‖ AUTHENTICATE_MESSAGE )
// then write MIC back into the 16-byte field at offset 72
```

### Implementation gotchas

1. Uppercase the **user only**, never the domain.
2. `temp` header is `0x01 0x01` then **6** zero bytes (Time starts at temp offset 8).
3. Two 4-byte zero fields in temp: one before TargetInfo, one trailing. The trailing `Z(4)` is part of temp and of NtChallengeResponse.
4. TargetInfo is copied **verbatim** from the CHALLENGE (including its EOL `00 00 00 00`); do not regenerate.
5. SessionBaseKey message is `NTProofStr` (16 bytes), not the full NtChallengeResponse.
6. MIC hashes all three messages in order NEGOTIATE ‖ CHALLENGE ‖ AUTHENTICATE with its own field zeroed.

---

## Part 3 — TEST VECTORS ([MS-NLMP] §4.2.4, verbatim)

Shared inputs (§4.2.1):

| Item | Value |
|---|---|
| User | `"User"` |
| UserDom (Domain) | `"Domain"` |
| Passwd | `"Password"` |
| Workstation | `"COMPUTER"` |
| Server name | `"Server"` |
| ServerChallenge | `01 23 45 67 89 ab cd ef` |
| ClientChallenge | `aa aa aa aa aa aa aa aa` |
| Time (FILETIME) | `00 00 00 00 00 00 00 00` |
| RandomSessionKey | `55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55` |
| TargetInfo AV_PAIRs | NbDomainName="Domain", NbComputerName="Server", EOL |
| Version bytes (sample) | `06 00 70 17 00 00 00 0f` |

Intermediate & output values (all independently verified byte-for-byte):

| Quantity | Hex |
|---|---|
| `NTOWFv1("Password")` (§4.2.2.1) | `a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52` |
| `MD4(UNICODE("Password"))` | `a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52` |
| **NTOWFv2 = LMOWFv2** | `0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f` |
| TargetInfo (ServerName) | `02 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 00 01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00 00 00 00 00` |
| **temp** | `01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 aa aa aa aa aa aa aa aa 00 00 00 00 02 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 00 01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00 00 00 00 00 00 00 00 00` |
| **NTProofStr** | `68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c` |
| **NtChallengeResponse** (NTProofStr ‖ temp) | `68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c 01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 aa aa aa aa aa aa aa aa 00 00 00 00 02 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 00 01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00 00 00 00 00 00 00 00 00` |
| **LmChallengeResponse** | `86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa aa aa aa aa` |
| **SessionBaseKey** | `8d e4 0c ca db c1 4a 82 f1 5c b0 ad 0d e9 5c a3` |
| **KeyExchangeKey** (= SessionBaseKey) | `8d e4 0c ca db c1 4a 82 f1 5c b0 ad 0d e9 5c a3` |
| **EncryptedRandomSessionKey** = RC4K(KeyExchangeKey, 0x55×16) | `c5 da d2 54 4f c9 79 90 94 ce 1c e9 0b c9 d0 3e` |

Compact (unspaced) form for Rust `assert_eq!` literals:

```
NTOWFv2                   = 0c868a403bfd7a93a3001ef22ef02e3f
MD4(UNICODE("Password"))  = a4f49c406510bdcab6824ee7c30fd852
TargetInfo                = 02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000
temp                      = 01010000000000000000000000000000aaaaaaaaaaaaaaaa0000000002000c0044006f006d00610069006e0001000c005300650072007600650072000000000000000000
NTProofStr                = 68cd0ab851e51c96aabc927bebef6a1c
NtChallengeResponse       = 68cd0ab851e51c96aabc927bebef6a1c01010000000000000000000000000000aaaaaaaaaaaaaaaa0000000002000c0044006f006d00610069006e0001000c005300650072007600650072000000000000000000
LmChallengeResponse       = 86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa
SessionBaseKey            = 8de40ccadbc14a82f15cb0ad0de95ca3
KeyExchangeKey            = 8de40ccadbc14a82f15cb0ad0de95ca3
EncryptedRandomSessionKey = c5dad2544fc9799094ce1ce90bc9d03e
```

---

## Part 4 — SSPI SIGN / SEAL / MAC (Message Confidentiality & Integrity)

Section map (verified numbering):

| Section | Function |
|---|---|
| 2.2.2.9.1 | NTLMSSP_MESSAGE_SIGNATURE (Extended Session Security variant) |
| 3.4.2 | SIGN (integrity) |
| 3.4.3 | SEAL (confidentiality) |
| 3.4.4 / 3.4.4.2 | MAC (parent / With Extended Session Security) |
| 3.4.5.1 | KXKEY |
| 3.4.5.2 | SIGNKEY |
| 3.4.5.3 | SEALKEY |
| 3.4 | Session security details (RC4INIT, key/handle setup) |

CredSSP always negotiates `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY` + `NTLMSSP_NEGOTIATE_SEAL` (+ `NTLMSSP_NEGOTIATE_KEY_EXCH`).

### 4.1 SIGNKEY (§3.4.5.2)

Defined only when ESS is set; otherwise `SignKey = NIL`. Result is 128-bit. Each magic constant is a **null-terminated** ASCII string — append a trailing `0x00` before MD5.

```
SIGNKEY(NegFlg, ExportedSessionKey, Mode):
  if NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY in NegFlg:
     if Mode == "Client":
        SignKey = MD5( ExportedSessionKey ‖
                       "session key to client-to-server signing key magic constant\0" )
     else:
        SignKey = MD5( ExportedSessionKey ‖
                       "session key to server-to-client signing key magic constant\0" )
  else:
     SignKey = NIL
```

**Exact magic strings (append `0x00`):**
- Client signing: `session key to client-to-server signing key magic constant`
- Server signing: `session key to server-to-client signing key magic constant`

### 4.2 SEALKEY (§3.4.5.3)

For ESS, key material is truncated by entropy then MD5-mixed into a full 128-bit value.

```
SEALKEY(NegFlg, ExportedSessionKey, Mode):
  if NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY in NegFlg:
     if   NTLMSSP_NEGOTIATE_128 set: SealKey = ExportedSessionKey            // 16 bytes
     elif NTLMSSP_NEGOTIATE_56  set: SealKey = ExportedSessionKey[0..6]      // first 7 bytes (56-bit)
     else                          : SealKey = ExportedSessionKey[0..4]      // first 5 bytes (40-bit)
     if Mode == "Client":
        SealKey = MD5( SealKey ‖ "session key to client-to-server sealing key magic constant\0" )
     else:
        SealKey = MD5( SealKey ‖ "session key to server-to-client sealing key magic constant\0" )
  elif (NTLMSSP_NEGOTIATE_LM_KEY set) OR
       (NTLMSSP_NEGOTIATE_DATAGRAM set AND NTLMRevisionCurrent >= NTLMSSP_REVISION_W2K3):
     if NTLMSSP_NEGOTIATE_56 set: SealKey = ExportedSessionKey[0..6] ‖ 0xA0
     else                       : SealKey = ExportedSessionKey[0..4] ‖ 0xE5 0x38 0xB0
  else:
     SealKey = ExportedSessionKey
```

Index notation is inclusive: `[0..6]` = 7 bytes, `[0..4]` = 5 bytes.

**Exact magic strings (append `0x00`):**
- Client sealing: `session key to client-to-server sealing key magic constant`
- Server sealing: `session key to server-to-client sealing key magic constant`

For CredSSP (ESS + 128), the client sealing key is `MD5(ExportedSessionKey ‖ "session key to client-to-server sealing key magic constant\0")`.

### 4.3 Key/handle setup (§3.4)

```
ClientSigningKey = SIGNKEY(NegFlg, ExportedSessionKey, "Client")
ServerSigningKey = SIGNKEY(NegFlg, ExportedSessionKey, "Server")
ClientSealingKey = SEALKEY(NegFlg, ExportedSessionKey, "Client")
ServerSealingKey = SEALKEY(NegFlg, ExportedSessionKey, "Server")
RC4Init(ClientHandle, ClientSealingKey)     // client's RC4 stream state
RC4Init(ServerHandle, ServerSealingKey)     // server's RC4 stream state
```

A sender uses its own role's key/handle: the client seals/signs outbound with `ClientSigningKey`/`ClientHandle` and verifies inbound with `ServerSigningKey`/`ServerHandle`; the server is symmetric. The two RC4 handles are independent stream states.

`SeqNum`: connection-oriented mode (CredSSP) starts at `0`, incremented by one per message **sent**; receiver expects 0 then +1 each message; a mismatched `SeqNum` is rejected **without** incrementing.

### 4.4 NTLMSSP_MESSAGE_SIGNATURE, ESS variant (§2.2.2.9.1) — 16 bytes, LE

| Off | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | Version | `0x00000001` (`01 00 00 00`) |
| 4 | 8 | Checksum | first 8 bytes of `HMAC_MD5(SigningKey, SeqNum ‖ Message)`, RC4-encrypted if KEY_EXCH negotiated |
| 12 | 4 | SeqNum | 32-bit LE sequence number |

(The non-ESS §2.2.2.9 variant — Version(4) + RandomPad(4) + CRC32(4) + SeqNum(4) — is not used under CredSSP.)

### 4.5 MAC With Extended Session Security (§3.4.4.2)

Plain integrity (SIGN only, no key exchange):

```
MAC(Handle, SigningKey, SeqNum, Message):
  sig.Version  = 0x00000001
  sig.Checksum = HMAC_MD5(SigningKey, SeqNum ‖ Message)[0..7]
  sig.SeqNum   = SeqNum
  SeqNum += 1
```

With `NTLMSSP_NEGOTIATE_KEY_EXCH` (the CredSSP case), the 8 checksum bytes are additionally RC4-encrypted through the sender's sealing handle:

```
MAC(Handle, SigningKey, SeqNum, Message):
  sig.Version  = 0x00000001
  sig.Checksum = RC4(Handle, HMAC_MD5(SigningKey, SeqNum ‖ Message)[0..7])
  sig.SeqNum   = SeqNum
  SeqNum += 1
```

Key points:
- `SeqNum` is prepended to the HMAC input as a 4-byte LE value; HMAC keyed with `SigningKey`, computed over the **plaintext** `Message`.
- `[0..7]` = first 8 of the 16-byte HMAC-MD5 digest.
- The RC4 uses the **same `Handle`** as message sealing, continuing that keystream.

### 4.6 SEAL (§3.4.3)

```
SEAL(Handle, SigningKey, SeqNum, Message):
  SealedMessage = RC4(Handle, Message)                    // encrypt plaintext
  Signature     = MAC(Handle, SigningKey, SeqNum, Message) // HMAC over PLAINTEXT
```

Critical ordering (one continuous keystream on the sender's handle):
1. `RC4(Handle, Message)` consumes keystream bytes `[0 .. len(Message))`.
2. `MAC(...)` computes `HMAC_MD5(SigningKey, SeqNum ‖ Message)` over the **original plaintext**, takes first 8 bytes, and RC4-encrypts them with the **same Handle**, consuming keystream `[len(Message) .. len(Message)+8)`.

Encrypting checksum before message, or HMAC-ing ciphertext, breaks interop.

---

## Part 5 — CredSSP (MS-CSSP)

All CredSSP messages ride inside a TLS channel. EXPLICIT context tagging is used throughout, so every `[n]` is a **constructed** context-specific tag: `[n] = 0xA0 + n`.

### 5.1 TSRequest (§2.2.1)

```
TSRequest ::= SEQUENCE {
    version     [0] INTEGER,
    negoTokens  [1] NegoData     OPTIONAL,
    authInfo    [2] OCTET STRING OPTIONAL,
    pubKeyAuth  [3] OCTET STRING OPTIONAL,
    errorCode   [4] INTEGER      OPTIONAL,
    clientNonce [5] OCTET STRING OPTIONAL
}
```

| Field | Tag | DER id octet | Inner universal tag |
|---|---|---|---|
| (outer SEQUENCE) | — | `0x30` | — |
| version | [0] | `0xA0` | INTEGER `0x02` |
| negoTokens | [1] | `0xA1` | SEQUENCE `0x30` (NegoData) |
| authInfo | [2] | `0xA2` | OCTET STRING `0x04` |
| pubKeyAuth | [3] | `0xA3` | OCTET STRING `0x04` |
| errorCode | [4] | `0xA4` | INTEGER `0x02` |
| clientNonce | [5] | `0xA5` | OCTET STRING `0x04` |

- **version:** valid values 2, 3, 4, 5, 6. Negotiation: if the received version exceeds what you understand, treat the peer as compatible with your version (min of the two peers wins).
- **errorCode:** 32-bit ASN.1 INTEGER. For negotiated versions 3, 4, or 6, on server SPNEGO failure carries the NTSTATUS code; client MUST immediately fail with that status and cease processing.
- **clientNonce:** **32-byte** array of cryptographically random bytes; used only in **version 5 or higher**.

### 5.2 NegoData (§2.2.1.1)

```
NegoData ::= SEQUENCE OF SEQUENCE {
    negoToken [0] OCTET STRING
}
```

DER tags: outer `SEQUENCE OF` = `0x30`; each inner `SEQUENCE` = `0x30`; `negoToken [0]` = `0xA0` (wraps OCTET STRING `0x04`). Carries SPNEGO/Kerberos/NTLM messages.

### 5.3 TSCredentials (§2.2.1.2)

```
TSCredentials ::= SEQUENCE {
    credType    [0] INTEGER,
    credentials [1] OCTET STRING
}
```

DER tags: SEQUENCE `0x30`; credType `[0]` = `0xA0` (INTEGER `0x02`); credentials `[1]` = `0xA1` (OCTET STRING `0x04`).

| credType | Meaning |
|---|---|
| 1 | credentials = DER(TSPasswordCreds) (§2.2.1.2.1) |
| 2 | credentials = DER(TSSmartCardCreds) (§2.2.1.2.2) |
| 6 | credentials = DER(TSRemoteGuardCreds) (§2.2.1.2.3) |

`credentials` is an OCTET STRING whose bytes are the **DER encoding** of the selected inner structure.

### 5.4 TSPasswordCreds (§2.2.1.2.1)

```
TSPasswordCreds ::= SEQUENCE {
    domainName [0] OCTET STRING,
    userName   [1] OCTET STRING,
    password   [2] OCTET STRING
}
```

DER tags: SEQUENCE `0x30`; domainName `[0]` = `0xA0`; userName `[1]` = `0xA1`; password `[2]` = `0xA2` — each wrapping OCTET STRING `0x04`. Each OCTET STRING contains the string in **UTF-16LE** (no BOM, no internal NUL terminator).

### 5.5 Message sequence (§3.1.5)

1. **TLS handshake** (RFC 2246). Server does **not** request client cert (client stays anonymous); server cert may be CA-signed or self-signed; TLS session resumption is not supported.
2. **SPNEGO/Kerberos/NTLM** in `negoTokens`, repeated as needed. `authInfo` omitted during this phase; `pubKeyAuth` omitted UNLESS the client sends its **last** nego token — that final TSRequest carries BOTH `negoTokens` and `pubKeyAuth`. Concretely:
   - (1) client `negoTokens` = NTLM NEGOTIATE
   - (2) server `negoTokens` = NTLM CHALLENGE
   - (3) client `negoTokens` = NTLM AUTHENTICATE **+ pubKeyAuth** (+ `clientNonce` for v5+)
3. **Client pubKeyAuth** (version-dependent, §5.6).
4. **Server pubKeyAuth** response (version-dependent, §5.6). Only `pubKeyAuth` present. If the server doesn't support the requested version it SHOULD set `errorCode = STATUS_NOT_SUPPORTED`.
5. **Client authInfo** = `SEAL(DER(TSCredentials))` via `GSS_WrapEx`; `pubKeyAuth`/`negoTokens` omitted. TSCredentials MUST NOT contain more than one credential structure.

### 5.6 pubKeyAuth computation (§3.1.5)

**"SubjectPublicKey"** = the ASN.1-encoded `SubjectPublicKey` **sub-field** of `SubjectPublicKeyInfo` from the server's X.509 cert (RFC 3280 §4.1). NOT the whole `SubjectPublicKeyInfo` wrapper — a common pitfall. Encryption ("SEAL") = `GSS_WrapEx()` of the negotiated mechanism (the NTLM SEAL of Part 4 in the CredSSP/NTLM case), producing `signature ‖ encrypted-payload`.

#### Version 5 or 6 (post-CVE-2018-0886 hash binding)

Client (step 3) generates a fresh 32-byte random nonce → `TSRequest.clientNonce`, then:

```
ClientServerHashMagic = "CredSSP Client-To-Server Binding Hash"
ClientServerHash      = SHA256( ClientServerHashMagic ‖ 0x00 ‖ Nonce ‖ SubjectPublicKey )
TSRequest.pubKeyAuth  = Encrypt(ClientServerHash)
```

Server (step 4) recomputes the client hash from received Nonce + its own TLS public key; if it matches, replies:

```
ServerClientHashMagic = "CredSSP Server-To-Client Binding Hash"
ServerClientHash      = SHA256( ServerClientHashMagic ‖ 0x00 ‖ Nonce ‖ SubjectPublicKey )
TSRequest.pubKeyAuth  = Encrypt(ServerClientHash)
```

Client (step 5) regenerates the server hash and compares.

**Exact magic strings (both include a trailing NUL `0x00` in the SHA256 input):**
- Client→Server: `CredSSP Client-To-Server Binding Hash`
- Server→Client: `CredSSP Server-To-Client Binding Hash`

SHA256 input byte order (normative pseudocode; FreeRDP-compatible): `magic-string ‖ 0x00 ‖ clientNonce(32) ‖ SubjectPublicKey`. Nonce size = **32 bytes**. Output = 32 bytes.

Magic-string hex:
- Client→Server (37 chars + NUL): `43 72 65 64 53 53 50 20 43 6C 69 65 6E 74 2D 54 6F 2D 53 65 72 76 65 72 20 42 69 6E 64 69 6E 67 20 48 61 73 68 00`
- Server→Client (+ NUL): `43 72 65 64 53 53 50 20 53 65 72 76 65 72 2D 54 6F 2D 43 6C 69 65 6E 74 20 42 69 6E 64 69 6E 67 20 48 61 73 68 00`

#### Version 2, 3, 4 (legacy raw-key + 1)

- Client (step 3): SEAL the raw `SubjectPublicKey` bytes directly (no nonce, no hash) into `pubKeyAuth`.
- Server (step 4): verifies it matches the key from its TLS handshake, then **adds 1 to the first byte** of the public key and encrypts the binary result (the +1 may make it invalid ASN.1; it prevents replay of the client's pubKeyAuth back at the client).
- Client (step 5): binary-compares the decrypted server response against (its sent public key with the first byte incremented).

#### Summary of difference

- **v≥5:** client SEALs `SHA256(magic ‖ 0x00 ‖ nonce32 ‖ SubjectPublicKey)`; nonce provides entropy; server returns the SEALed server-direction hash over the same key+nonce. Fixes CVE-2018-0886 (encrypt-oracle / MITM weakness).
- **v<5:** client SEALs raw `SubjectPublicKey`; server returns SEAL(key with first byte +1). No nonce, no hash.

### 5.7 authInfo

`authInfo` = `SEAL(DER(TSCredentials))` via `GSS_WrapEx` under the SPNEGO-negotiated key; carries the message signature then the encrypted data. Sent only in step 5, after server authenticity is confirmed.

---

## Part 6 — Open Questions / Low-Confidence Items

1. **No published SEAL/MAC test vectors.** [MS-NLMP] §3.4 provides key-setup values (§4.2.1) but no full sealed-message vector. The 16-byte signature layout `01 00 00 00 ‖ checksum(8) ‖ SeqNum(4)` and the SIGNKEY/SEALKEY derivations must be validated against a live Windows RDP server or FreeRDP, not against a spec vector. The `0x0100000000000000<SeqNum>` shape sometimes cited is not reproduced here as authoritative.

2. **No CredSSP byte-level test vectors.** [MS-CSSP] publishes no input→output vectors. Only the deterministic magic-string constants and DER context tags are recoverable. The full v5+ `SHA256(magic‖0x00‖nonce‖key)` path and the GSS_WrapEx of pubKeyAuth need interop testing against a real server.

3. **v5+ SHA256 operand order ambiguity.** The [MS-CSSP] normative pseudocode orders operands `magic ‖ nonce ‖ SubjectPublicKey`, but the surrounding prose lists them differently ("SubjectPublicKey concatenated with the well-known string and the nonce"). This doc follows the pseudocode order (FreeRDP-compatible). Confirm against the target server if interop fails.

4. **SubjectPublicKey vs SubjectPublicKeyInfo.** The spec says the inner `SubjectPublicKey` sub-field, but some implementations historically hashed/sealed the whole `SubjectPublicKeyInfo`. Verify which the target RDP server expects.

5. **errorCode version coverage.** The NTSTATUS-in-errorCode behavior is specified for negotiated versions 3, 4, 6 — behavior for version 5 specifically is not explicitly enumerated in the fetched text; treat as needing confirmation.

6. **MsvAvTimestamp / MIC interaction.** When the CHALLENGE TargetInfo contains an `MsvAvTimestamp` (0x0007), Windows clients set the MsvAvFlags MIC bit and add `MsvAvChannelBindings`/`MsvAvTargetName` per SPN/channel-binding policy. The precise conditions under which the MIC becomes mandatory (vs optional) were not exhaustively confirmed from the fetched sections.

7. **RC4 keystream continuity across the handshake→data boundary.** Whether the same RC4 handle used for pubKeyAuth sealing continues (keystream not reset) into the authInfo SEAL and subsequent data messages is asserted here from the connection-oriented `SeqNum` model, but should be validated — a reset handle vs a continuous stream is a common interop failure.

8. **56-bit vs 128-bit SEALKEY selection under CredSSP.** CredSSP is assumed to negotiate ESS+128, making the `[0..6]`/`[0..4]` truncation branches dead in practice. If a server negotiates 56-bit only, the truncation-then-MD5 path must be exercised — untested here.

Verification note: NTLMv2 intermediates in Part 3 were independently recomputed via manual MD4 + HMAC-MD5 + RC4 (`scratchpad/md4.py`) and matched the [MS-NLMP] §4.2.4 published values byte-for-byte.