# Phase 4 (Graphics) & Phase 5 (Input) — Native Rust RDP Client Implementation Reference

Scope: MS-RDPBCGR fast-path framing, fast-path output/input PDUs and events, bitmap update PDUs, interleaved RLE decompression, the RDP 6.0 planar codec, and pointer/cursor updates. All multi-byte scalars are **little-endian unless explicitly noted**. Confidence per section is stated inline; open questions are collected at the end.

---

## 0. Header-Byte Bit Ordering (read this first)

Confidence: **high.**

The MS bitmask diagrams draw fields left-to-right, but the **leftmost field occupies the LOW-order bits** of the byte (bit 0 = LSB). This matches every real RDP stack (FreeRDP `fastpath.c`). So for a packed header byte `h`:

| Header | Field extraction |
|--------|------------------|
| `fpOutputHeader` | `action = h & 0x03`; `flags = (h >> 6) & 0x03` |
| `fpInputHeader`  | `action = h & 0x03`; `numEvents = (h >> 2) & 0x0F`; `flags = (h >> 6) & 0x03` |
| `updateHeader`   | `updateCode = h & 0x0F`; `fragmentation = (h >> 4) & 0x03`; `compression = (h >> 6) & 0x03` |
| `eventHeader`    | `eventFlags = h & 0x1F`; `eventCode = (h >> 5) & 0x07` |

---

## 1. Fast-Path PDU Framing

Confidence: **high** (verified against live MS-RDPBCGR).

### 1.1 Length encoding (`length1`/`length2`) — identical for output and input PDUs

```
b1 = read_u8()                          # length1
if (b1 & 0x80) == 0:                    # high bit clear
    pduLength = b1                      # 1..127, length2 absent
else:                                   # high bit set
    b2 = read_u8()                      # length2
    pduLength = ((b1 & 0x7F) << 8) | b2 # 14-bit big-endian, low bits in length2
```

- `pduLength` is the **overall** PDU length in bytes, counting `fpOutputHeader`/`fpInputHeader` **and** the length field(s) themselves.
- SHOULD be `<= 16,383` (0x3FFF).
- **Encoder rule:** emit 1 byte if total `< 0x80`, else emit a big-endian u16 with `0x8000` OR'd in (`val | 0x8000`).

Note this is the one **big-endian** field in an otherwise little-endian protocol.

### 1.2 TS_FP_UPDATE_PDU — server→client (§2.2.9.1.2)

```
Offset  Field              Size   Notes
0       fpOutputHeader     1      bit-packed
1       length1            1      length encoding (§1.1)
[2]     length2            1      present only if length1 & 0x80
[..]    fipsInformation    4      only if ENCRYPTION_METHOD_FIPS (0x10) negotiated
[..]    dataSignature      8      only if FASTPATH_OUTPUT_ENCRYPTED (flags bit 0x2) set
[..]    fpOutputUpdates    var    array of TS_FP_UPDATE (§2.2.9.1.2.1)
```

**fpOutputHeader** — diagram `action(2) | reserved(4) | flags(2)`:
- `action` = `hdr & 0x03`:
  - `FASTPATH_OUTPUT_ACTION_FASTPATH = 0x0`
  - `FASTPATH_OUTPUT_ACTION_X224 = 0x3` (slow-path; whole first byte then reads as `0x03`)
- `reserved` = bits 2-5, MUST be 0
- `flags` = `(hdr >> 6) & 0x03`:
  - `FASTPATH_OUTPUT_SECURE_CHECKSUM = 0x1` (salted MAC) → contributes `0x40`
  - `FASTPATH_OUTPUT_ENCRYPTED = 0x2` (dataSignature present + payload encrypted) → contributes `0x80`

**Example header bytes:**
- `0x00` = fast-path, no encryption, no checksum (the common TLS-wrapped case — outer TLS carries all security, so these bits stay 0).
- `0x40` = SECURE_CHECKSUM only; `0x80` = ENCRYPTED only; `0xC0` = both.
- `0x03` = slow-path (X.224) marker.
- Minimal unencrypted example: `00 08 <6 bytes of updates>` = fast-path action, total length 8, no length2/fips/signature.

### 1.3 TS_FP_INPUT_PDU — client→server (§2.2.8.1.2)

```
Offset  Field              Size   Notes
0       fpInputHeader      1      bit-packed
1       length1            1      length encoding (§1.1)
[2]     length2            1      present only if length1 & 0x80
[..]    fipsInformation    4      only if ENCRYPTION_METHOD_FIPS
[..]    dataSignature      8      only if FASTPATH_INPUT_ENCRYPTED (flags 0x2)
[..]    numEvents          1      present ONLY if header numEvents field == 0 (>15 events); allows up to 255
[..]    fpInputEvents      var    array of TS_FP_INPUT_EVENT (§2.2.8.1.2.2)
```

**fpInputHeader** — diagram `action(2) | numEvents(4) | flags(2)`:
- `action` = `hdr & 0x03`: `FASTPATH_INPUT_ACTION_FASTPATH = 0x0`, `FASTPATH_INPUT_ACTION_X224 = 0x3`
- `numEvents` = `(hdr >> 2) & 0x0F` — event count 1..15; if 0, real count is in the separate `numEvents` byte (up to 255)
- `flags` = `(hdr >> 6) & 0x03`: `FASTPATH_INPUT_SECURE_CHECKSUM = 0x1`, `FASTPATH_INPUT_ENCRYPTED = 0x2`

**Example header bytes:**
- `0x04` = fast-path, 1 event (`1<<2`), no crypto flags.
- `0x08` = fast-path, 2 events (`2<<2`).
- `0x00` = fast-path, header numEvents 0 → separate numEvents byte present (for >15 events).
- Minimal 1-key example (unencrypted): `04 08 00 1E` → `fpInputHeader=0x04` (fast-path + 1 event), `length1=0x08`... **note:** the minimal example is illustrative; recompute `length1` as the true total byte count of the assembled PDU. The event `00 1E` = eventHeader `0x00` (scancode, key-down) + keyCode `0x1E` ('A').

---

## 2. Fast-Path Output Updates

Confidence: **high.**

### 2.1 TS_FP_UPDATE — one update (§2.2.9.1.2.1)

```
Offset  Field              Size   Notes
0       updateHeader       1      bit-packed
[1]     compressionFlags   1      present only if compression bits == FASTPATH_OUTPUT_COMPRESSION_USED (0x2)
[..]    size               2      u16 LE — byte count of updateData
[..]    updateData         var    (== size) update-type-specific payload
```

**updateHeader** — diagram `updateCode(4) | fragmentation(2) | compression(2)`:
- `updateCode` = `hdr & 0x0F`
- `fragmentation` = `(hdr >> 4) & 0x03`
- `compression` = `(hdr >> 6) & 0x03`

**`updateCode` values:**

| Value | Name |
|-------|------|
| 0x0 | FASTPATH_UPDATETYPE_ORDERS |
| 0x1 | FASTPATH_UPDATETYPE_BITMAP |
| 0x2 | FASTPATH_UPDATETYPE_PALETTE |
| 0x3 | FASTPATH_UPDATETYPE_SYNCHRONIZE |
| 0x4 | FASTPATH_UPDATETYPE_SURFCMDS |
| 0x5 | FASTPATH_UPDATETYPE_PTR_NULL (system pointer hidden) |
| 0x6 | FASTPATH_UPDATETYPE_PTR_DEFAULT |
| 0x8 | FASTPATH_UPDATETYPE_PTR_POSITION |
| 0x9 | FASTPATH_UPDATETYPE_COLOR (color pointer) |
| 0xA | FASTPATH_UPDATETYPE_CACHED |
| 0xB | FASTPATH_UPDATETYPE_POINTER (new pointer) |
| 0xC | FASTPATH_UPDATETYPE_LARGE_POINTER |

(0x7 is unused; the spec skips 0x6→0x8.)

**`fragmentation` values:** `FASTPATH_FRAGMENT_SINGLE=0x0`, `LAST=0x1`, `FIRST=0x2`, `NEXT=0x3`.

**`compression` values:** `FASTPATH_OUTPUT_COMPRESSION_USED=0x2` (only defined value). When set, the `compressionFlags` byte is present and uses the same flags as `compressedType` in the Share Data Header (§2.2.8.1.1.1.2).

**Example header bytes:**
- `0x01` = BITMAP, single fragment, no compression → next is `size(2 LE)` then bitmap data.
- `0x03` = SYNCHRONIZE (size will be 0).
- `0x2B` = updateCode 0xB (POINTER), fragmentation 0x2 (FIRST): `0xB | (0x2<<4) = 0x2B`.
- `0x84` = updateCode 0x4 (SURFCMDS), compression used: `0x4 | (0x2<<6) = 0x84` → `compressionFlags` byte follows.

---

## 3. Fast-Path Input Events

Confidence: **high.**

### 3.1 eventHeader (§2.2.8.1.2.2) — shared by all fast-path input events

Diagram `eventFlags(5) | eventCode(3)`:
- `eventFlags` = `hdr & 0x1F`
- `eventCode` = `(hdr >> 5) & 0x07`

**`eventCode` values:**

| Value | Name |
|-------|------|
| 0 | FASTPATH_INPUT_EVENT_SCANCODE (keyboard) |
| 1 | FASTPATH_INPUT_EVENT_MOUSE |
| 2 | FASTPATH_INPUT_EVENT_MOUSEX (extended mouse) |
| 3 | FASTPATH_INPUT_EVENT_SYNC |
| 4 | FASTPATH_INPUT_EVENT_UNICODE |
| 6 | FASTPATH_INPUT_EVENT_QOE_TIMESTAMP |

### 3.2 TS_FP_KEYBOARD_EVENT (§2.2.8.1.2.2.1)

```
Offset  Field         Size
0       eventHeader   1     eventCode=0 (SCANCODE), eventFlags = kbd flags
1       keyCode       1     u8 scancode
```

`eventFlags` (5 bits):
- `FASTPATH_INPUT_KBDFLAGS_RELEASE = 0x01` (set = key-up, clear = key-down)
- `FASTPATH_INPUT_KBDFLAGS_EXTENDED = 0x02` (E0 extended scancode)
- `FASTPATH_INPUT_KBDFLAGS_EXTENDED1 = 0x04` (E1, PAUSE key only)

Examples: key-down 'A' (scancode 0x1E) → `00 1E`; key-up 'A' → `01 1E`; Right-Ctrl down (extended) → `02 1D`.

### 3.3 TS_FP_POINTER_EVENT — mouse (§2.2.8.1.2.2.3)

```
Offset  Field         Size   Notes
0       eventHeader   1      eventCode=1 (MOUSE), eventFlags MUST be 0 → byte = 0x20
1       pointerFlags  2      u16 LE
3       xPos          2      u16 LE, x relative to top-left of desktop
5       yPos          2      u16 LE
```

- eventHeader is always `0x20` (`1<<5`) for a mouse event.
- `pointerFlags` (same as slow-path TS_POINTER_EVENT):
  - `PTRFLAGS_MOVE=0x0800`
  - `PTRFLAGS_DOWN=0x8000`
  - `PTRFLAGS_BUTTON1` (left) `=0x1000`
  - `PTRFLAGS_BUTTON2` (right) `=0x2000`
  - `PTRFLAGS_BUTTON3` (middle) `=0x4000`
  - `PTRFLAGS_WHEEL=0x0200`
  - `PTRFLAGS_HWHEEL=0x0400`
  - wheel rotation in low byte as signed `WheelRotationMask = 0x01FF`; when WHEEL/HWHEEL set, xPos/yPos are ignored.
- Example: left-button press at (100,200): eventHeader `20`, pointerFlags `0x9000` (DOWN|BUTTON1) → `00 90`, xPos 100 → `64 00`, yPos 200 → `C8 00`. Full event: `20 00 90 64 00 C8 00`. Pure move → pointerFlags `0x0800` → `20 00 08 <x LE> <y LE>`.

(§2.2.8.1.2.2.2 TS_FP_POINTERX_EVENT, eventCode=2, has the identical pointerFlags/xPos/yPos layout but carries the extended XBUTTON1/XBUTTON2 flags.)

---

## 4. Bitmap Update PDU, TS_BITMAP_DATA, Compression Header, Pixel Formats

Confidence: **high** for field layouts; the fast-path `updateType` presence is flagged in Open Questions.

### 4.1 Slow-path Bitmap Update Data — TS_UPDATE_BITMAP_DATA (§2.2.9.1.1.3.1.2.1)

| off | field | size | notes |
|-----|-------|------|-------|
| 0 | updateType | u16 | MUST be `UPDATETYPE_BITMAP = 0x0001` |
| 2 | numberRectangles | u16 | count of TS_BITMAP_DATA entries |
| 4 | rectangles | var | array of `numberRectangles` × TS_BITMAP_DATA |

So slow path = `01 00` `NN NN` then the rectangle array. The wrapper TS_UPDATE_BITMAP (§2.2.9.1.1.3.1.2) contains a shareDataHeader followed by this bitmapData.

### 4.2 Fast-path TS_FP_UPDATE_BITMAP (§2.2.9.1.2.1.1.1.2)

| off | field | size | notes |
|-----|-------|------|-------|
| 0 | updateHeader | u8 | updateCode (low 4 bits) MUST = `FASTPATH_UPDATETYPE_BITMAP` (1) |
| 1 | compressionFlags | u8 (optional) | present only if compression-used flag set |
| +1/+2 | size | u16 | byte length of bitmapUpdateData |
| … | bitmapUpdateData | var | a full TS_UPDATE_BITMAP_DATA (§2.2.9.1.1.3.1.2.1) |

Spec text: *"Both slow-path and fast-path utilize the same data format, a Bitmap Update Data structure."* Per the letter of the spec, the fast-path payload **still begins with `updateType = 0x0001`**, then numberRectangles, then rectangles. Fast-path only replaces the 18-byte slow-path shareDataHeader with the compact updateHeader/size. **See Open Questions** — some implementations (FreeRDP) treat the payload as starting at numberRectangles; verify against a live capture.

### 4.3 TS_BITMAP_DATA (§2.2.9.1.1.3.1.2.2) — one rectangle

| off | field | size | notes |
|-----|-------|------|-------|
| 0 | destLeft | u16 | left bound |
| 2 | destTop | u16 | top bound |
| 4 | destRight | u16 | **inclusive** right bound |
| 6 | destBottom | u16 | **inclusive** bottom bound |
| 8 | width | u16 | width in pixels |
| 10 | height | u16 | height in pixels |
| 12 | bitsPerPixel | u16 | color depth |
| 14 | flags | u16 | see below |
| 16 | bitmapLength | u16 | size in bytes of (bitmapComprHdr + bitmapDataStream) |
| 18 | bitmapComprHdr | 8 bytes, optional | TS_CD_HEADER; present ONLY if BITMAP_COMPRESSION set AND NO_BITMAP_COMPRESSION_HDR NOT set |
| 18 or 26 | bitmapDataStream | var | pixel data (compressed or raw) |

Fixed header = 18 bytes before the optional compression header.

**flags:**
- `BITMAP_COMPRESSION = 0x0001` — bitmapDataStream is compressed.
- `NO_BITMAP_COMPRESSION_HDR = 0x0400` — bitmapComprHdr is omitted (saves 8 bytes).

**8-byte bitmapComprHdr presence logic:**
- BITMAP_COMPRESSION clear → no header, raw pixels.
- BITMAP_COMPRESSION set + NO_BITMAP_COMPRESSION_HDR clear → header **present** (8 bytes).
- BITMAP_COMPRESSION set + NO_BITMAP_COMPRESSION_HDR set → header **absent**.

**bitmapLength scope:** = length of bitmapComprHdr + bitmapDataStream combined. Header present → compressed pixel bytes = `bitmapLength − 8`; header absent → pixel bytes = `bitmapLength`.

**Inclusiveness & dimensions:** destRight/destBottom are **inclusive** pixel coordinates:
- `width  = destRight  − destLeft + 1`
- `height = destBottom − destTop  + 1`

destLeft/Top/Right/Bottom define the inclusive bounding box on the framebuffer; width/height are the decoded bitmap dimensions and are what you use to size/decode the pixel buffer. The RLE/raster rule can pad decoded width up (see cbScanWidth below).

### 4.4 Raw (uncompressed) pixel layout

Uncompressed bitmapDataStream is a **bottom-up, left-to-right** series of pixels:
- Row order **bottom-up** (last scanline first, like a Windows DIB).
- Within a row, left→right.
- Each pixel = whole number of bytes (`ceil(bpp/8)`).
- Each row padded to a multiple of 4 bytes (up to 3 padding bytes).
- Row stride = `align4(width × bytesPerPixel)`.

### 4.5 Pixel formats by bitsPerPixel (values stored little-endian)

- **15 bpp — RGB555**: one u16 LE. MSB→LSB: `0 RRRRR GGGGG BBBBB` (bit15 unused/0, R 14–10, G 9–5, B 4–0), 5 bits each.
- **16 bpp — RGB565**: one u16 LE. MSB→LSB: `RRRRR GGGGGG BBBBB` (R 15–11 = 5 bits, G 10–5 = 6 bits, B 4–0 = 5 bits).
- **24 bpp — BGR**: 3 bytes in memory order **B, G, R**. No alpha. Rows padded to 4-byte multiple.
- **32 bpp — XRGB/BGRX (a.k.a. BGRA)**: 4 bytes in memory order **B, G, R, X** (4th byte unused/alpha, ignored for opaque). Equivalent to LE u32 `0x00RRGGBB`. When BITMAP_COMPRESSION is set at 32 bpp, the stream is **NOT** interleaved RLE — it is RDP 6.0 Bitmap Compression (RDP6_BITMAP_STREAM, [MS-RDPEGDI] §2.2.2.5.1); 32bpp raw is BGRX.

**Extraction (LE u16 for 15/16 bpp):**
- RGB565: `R = (px >> 11) & 0x1F; G = (px >> 5) & 0x3F; B = px & 0x1F`. Scale to 8-bit: `R8 = (R<<3)|(R>>2), G8 = (G<<2)|(G>>4), B8 = (B<<3)|(B>>2)`.
- RGB555: `R = (px >> 10) & 0x1F; G = (px >> 5) & 0x1F; B = px & 0x1F`.

### 4.6 TS_CD_HEADER — Compressed Data Header (§2.2.9.1.1.3.1.2.3), 8 bytes

| off | field | size | value/meaning |
|-----|-------|------|---------------|
| 0 | cbCompFirstRowSize | u16 | MUST be `0x0000` |
| 2 | cbCompMainBodySize | u16 | size in bytes of the compressed bitmap data following this header |
| 4 | cbScanWidth | u16 | bitmap width in pixels; MUST be divisible by 4 |
| 6 | cbUncompressedSize | u16 | size in bytes of the bitmap data after decompression |

When present, use `cbCompMainBodySize` (not bitmapLength) as the authoritative compressed-body length; `bitmapLength − 8` should equal it. `cbScanWidth` forced to a multiple of 4 is why decoded width can exceed `(destRight − destLeft + 1)`.

### 4.7 Compression codec selection

- Compressed, **bpp ≠ 32**: **Interleaved RLE** (§5 below), wrapped in RLE Compressed Bitmap Stream (§2.2.9.1.1.3.1.2.4).
- Compressed, **bpp = 32**: **RDP 6.0 Bitmap Compression** (planar codec, §6), RDP6_BITMAP_STREAM ([MS-RDPEGDI] §2.2.2.5.1).

---

## 5. Interleaved RLE Bitmap Decompression (complete algorithm)

Confidence: **high.** Decode pseudo-code lives in [MS-RDPBCGR] §2.2.9.1.1.3.1.2.4 (`RleDecompress`); [MS-RDPEGDI] §2.2.2.5.1 / §3.1.9 cross-reference it.

### 5.1 Two numbering systems (do not confuse)

1. **Raw header byte prefix** — what is on the wire (FreeRDP/rdesktop constant names). Regular orders = top 3 bits + 5-bit length; lite orders = top 4 bits + 4-bit length; MEGA/special = a whole dedicated byte.
2. **"code ID"** returned by `ExtractCodeId()` — normalized: regular = `header>>5` (0x0–0x4); lite = `header>>4` (0xC–0xE); mega/special = the full byte (0xF0–0xFE). The pseudo-code switches on this code ID.

### 5.2 Opcode / prefix table

`x` = length bits. Raw prefix = on-the-wire byte; Code ID = what `ExtractCodeId` returns.

| Order | Raw prefix (binary) | Raw byte range | Code ID | MEGA_MEGA byte | Length bits |
|---|---|---|---|---|---|
| Background Run | `000x xxxx` | 0x00–0x1F | 0x0 | **0xF0** | regular 5-bit |
| Foreground Run | `001x xxxx` | 0x20–0x3F | 0x1 | **0xF1** | regular 5-bit |
| Foreground/Background Image | `010x xxxx` | 0x40–0x5F | 0x2 | **0xF2** | regular 5-bit (×8) |
| Color Run | `011x xxxx` | 0x60–0x7F | 0x3 | **0xF3** | regular 5-bit |
| Color Image | `100x xxxx` | 0x80–0x9F | 0x4 | **0xF4** | regular 5-bit |
| Set-Foreground Run (lite) | `1100 xxxx` | 0xC0–0xCF | 0xC | **0xF6** | lite 4-bit |
| Set-FG FGBG Image (lite) | `1101 xxxx` | 0xD0–0xDF | 0xD | **0xF7** | lite 4-bit (×8) |
| Dithered Run (lite) | `1110 xxxx` | 0xE0–0xEF | 0xE | **0xF8** | lite 4-bit |
| SPECIAL_FGBG_1 | `1111 1001` | 0xF9 | 0xF9 | — | none (fixed 8 px) |
| SPECIAL_FGBG_2 | `1111 1010` | 0xFA | 0xFA | — | none (fixed 8 px) |
| WHITE | `1111 1101` | 0xFD | 0xFD | — | none (1 px) |
| BLACK | `1111 1110` | 0xFE | 0xFE | — | none (1 px) |

There is **no "regular" dithered run and no "regular" set-foreground order** — those exist only in lite (0xC0/0xD0/0xE0) and MEGA (0xF6/0xF7/0xF8). Prefixes 0xA0–0xBF, 0xF5, 0xFB, 0xFC, 0xFF are unused/reserved.

```
ExtractCodeId(hdr):
    if   (hdr & 0xC0) != 0xC0:  return hdr >> 5   // regular:  0x0..0x4
    elif (hdr & 0xF0) == 0xF0:  return hdr         // mega/special: 0xF0..0xFE
    else:                       return hdr >> 4    // lite: 0xC,0xD,0xE
```

### 5.3 Run-length encoding — the three forms

**Regular run orders** (BG/FG/COLOR_RUN/COLOR_IMAGE), mask `0x1F`:
- `len = hdr & 0x1F`. If `len != 0` → length 1..31, header **1 byte**.
- If `len == 0` → *extended regular*: `len = next_byte + 32` (32..287), header **2 bytes**.

**Lite run orders** (SET_FG_RUN 0xC0, DITHERED 0xE0), mask `0x0F`:
- `len = hdr & 0x0F`. If `len != 0` → length 1..15, **1 byte**.
- If `len == 0` → `len = next_byte + 16` (16..271), **2 bytes**.

**FGBG image orders** encode a *pixel* count that is a multiple of 8 in the compact form:
- Regular FGBG (0x40): `g = hdr & 0x1F`; if `g != 0` → `len = g * 8`; if `g == 0` → `len = next_byte + 1`.
- Lite FGBG (0xD0): `g = hdr & 0x0F`; if `g != 0` → `len = g * 8`; if `g == 0` → `len = next_byte + 1`.

**MEGA_MEGA orders** (0xF0–0xF4, 0xF6–0xF8): header byte followed by a **16-bit little-endian** length: `len = hdr[1] | (hdr[2] << 8)`. Header **3 bytes**.

`AdvanceOverOrderHeader` skips: 1 byte (compact), 2 bytes (extended regular/lite, or FGBG with `g==0`), or 3 bytes (MEGA). SET-FG/Dithered/Color runs read their operand pixel(s) *after* the header.

### 5.4 Per-order decode semantics

Setup: `fgPel` = **white** (0xFF / 0x7FFF / 0xFFFF / 0xFFFFFF by depth), `fInsertFgPel = FALSE`, `fFirstLine = TRUE`. `rowDelta` = bytes per scanline (= `width × pixelSize`). Decode is **bottom-up**: the first scanline written is the bottom row, so "the pixel above" is `*(pbDest - rowDelta)`. Once `pbDest` has advanced ≥ `rowDelta` bytes, clear `fFirstLine` (and `fInsertFgPel`).

- **Background Run**: copy `len` pixels from the previous scanline (`ReadPixel(pbDest - rowDelta)`); on first line write black. **fInsertFgPel quirk**: if `fInsertFgPel` is set (previous order was also a background run), the **first** pixel is written as `above XOR fgPel` (first line: `fgPel`), consuming one from `len`. After any background run, `fInsertFgPel = TRUE`. **Every other order sets `fInsertFgPel = FALSE`.**
- **Foreground Run** (and lite/MEGA Set-FG Run): if SET variant, first `fgPel = ReadPixel(pbSrc)` (advance one pixel). Then write `len` pixels of `above XOR fgPel` (first line: just `fgPel`).
- **Dithered Run** (lite 0xE0 / MEGA 0xF8): read two literal pixels `pixelA`, `pixelB`; write the pair `pixelA,pixelB` **`len` times** → 2·len pixels. No XOR.
- **Color Run** (0x60 / 0xF3): read one literal pixel; write it `len` times. No XOR.
- **Color Image** (0x80 / 0xF4): raw copy of `len` pixels straight from source to dest (`len * pixelSize` bytes). No XOR. (Spec text writes `byteCount = runLength * GetColorDepth()`, understood as `runLength * pixelSizeInBytes`.)
- **FGBG Image** (0x40 / 0xD0 set / 0xF2 / 0xF7): if SET variant, read `fgPel` first. Then consume the run in groups of 8 pixels, each group governed by **one bitmask byte** read from the stream; a trailing partial group (`len % 8`) uses the low bits of the final mask byte.
- **SPECIAL_FGBG_1** (0xF9): one FGBG group of 8 pixels using fixed bitmask `g_MaskSpecialFgBg1 = 0x03`. No mask byte or length read from stream.
- **SPECIAL_FGBG_2** (0xFA): one FGBG group of 8 pixels using fixed bitmask `g_MaskSpecialFgBg2 = 0x05`.
- **WHITE** (0xFD): write one white pixel. **BLACK** (0xFE): write one black pixel.

**FGBG bitmask rule** (WriteFgBgImage / WriteFirstLineFgBgImage): for each of the up-to-8 pixels, bit *i* of the mask byte governs pixel *i*, **LSB first** (bit0 → leftmost pixel):
- bit = 1 (foreground): `pixel = above XOR fgPel` (first line: `pixel = fgPel`).
- bit = 0 (background): `pixel = above` (first line: `pixel = black`).

where `above = ReadPixel(pbDest - rowDelta)`.

### 5.5 Bytes-per-pixel (pixelSize = 1, 2, 3)

- **1 bpp** (8-bit palettized): PIXEL = 1 byte. White = 0xFF, black = 0x00.
- **2 bpp** (15-bit RGB555 or 16-bit RGB565): PIXEL = 16-bit LE. White = 0x7FFF (15-bit) / 0xFFFF (16-bit); black = 0x0000. Literal operands are 2 bytes each.
- **3 bpp** (24-bit RGB): PIXEL = 3 bytes LE. White = 0xFFFFFF, black = 0x000000. Literal operands are 3 bytes each.

Only the pixel width changes; order/opcode logic and XOR/bitmask handling are identical across depths.

### 5.6 Reference decode routine

```
// Code IDs from ExtractCodeId (NOT the raw byte for regular/lite):
REGULAR_BG_RUN        = 0x0    MEGA_MEGA_BG_RUN         = 0xF0
REGULAR_FG_RUN        = 0x1    MEGA_MEGA_FG_RUN         = 0xF1
REGULAR_FGBG_IMAGE    = 0x2    MEGA_MEGA_FGBG_IMAGE     = 0xF2
REGULAR_COLOR_RUN     = 0x3    MEGA_MEGA_COLOR_RUN      = 0xF3
REGULAR_COLOR_IMAGE   = 0x4    MEGA_MEGA_COLOR_IMAGE    = 0xF4
LITE_SET_FG_FG_RUN    = 0xC    MEGA_MEGA_SET_FG_RUN     = 0xF6
LITE_SET_FG_FGBG_IMAGE= 0xD    MEGA_MEGA_SET_FGBG_IMAGE = 0xF7
LITE_DITHERED_RUN     = 0xE    MEGA_MEGA_DITHERED_RUN   = 0xF8
SPECIAL_FGBG_1 = 0xF9   SPECIAL_FGBG_2 = 0xFA   WHITE = 0xFD   BLACK = 0xFE
g_MaskRegularRunLength=0x1F  g_MaskLiteRunLength=0x0F
g_MaskSpecialFgBg1=0x03      g_MaskSpecialFgBg2=0x05
// FreeRDP/rdesktop name constants by RAW header byte:
//  BG=0x00 FG=0x20 FGBG=0x40 COLOR_RUN=0x60 COLOR_IMG=0x80
//  LITE_SET_FG=0xC0 LITE_SET_FGBG=0xD0 DITHERED=0xE0

// PS = GetPixelSize(): 1 for 8bpp, 2 for 15/16bpp, 3 for 24bpp.
// ReadPixel/WritePixel handle PS bytes little-endian. NextPixel(p)=p+PS.

ExtractRunLength(code, hdr):
    if code == REGULAR_FGBG_IMAGE:              // raw 0x40
        r = hdr[0] & 0x1F;  return (r != 0) ? r*8 : hdr[1]+1
    elif code == LITE_SET_FG_FGBG_IMAGE:        // raw 0xD0
        r = hdr[0] & 0x0F;  return (r != 0) ? r*8 : hdr[1]+1
    elif IsRegularCode(code):                   // BG/FG/COLOR_RUN/COLOR_IMAGE regular
        r = hdr[0] & 0x1F;  return (r != 0) ? r : hdr[1]+32
    elif IsLiteCode(code):                      // SET_FG_RUN / DITHERED lite
        r = hdr[0] & 0x0F;  return (r != 0) ? r : hdr[1]+16
    elif IsMegaMegaCode(code):
        return hdr[1] | (hdr[2] << 8)           // 16-bit LE

WriteFgBgImage(pbDest, rowDelta, bitmask, fgPel, cBits):     // non-first line
    for i in 0..cBits-1:                                     // LSB-first
        above = ReadPixel(pbDest - rowDelta)
        WritePixel(pbDest, (bitmask & (1<<i)) ? above ^ fgPel : above)
        pbDest = NextPixel(pbDest)
    return pbDest

WriteFirstLineFgBgImage(pbDest, bitmask, fgPel, cBits):      // first line: no "above"
    for i in 0..cBits-1:
        WritePixel(pbDest, (bitmask & (1<<i)) ? fgPel : BLACK)
        pbDest = NextPixel(pbDest)
    return pbDest

RleDecompress(pbSrc, cbSrc, pbDest, rowDelta):
    pbEnd = pbSrc + cbSrc
    fgPel = WHITE_PIXEL          // 0xFF / 0x7FFF|0xFFFF / 0xFFFFFF
    fInsertFgPel = FALSE
    fFirstLine   = TRUE

    while pbSrc < pbEnd:
        if fFirstLine and (pbDest - pbDestBuffer) >= rowDelta:
            fFirstLine = FALSE;  fInsertFgPel = FALSE     // finished bottom row

        code = ExtractCodeId(*pbSrc)

        // ---- Background Run ----
        if code == REGULAR_BG_RUN or code == MEGA_MEGA_BG_RUN:
            len = ExtractRunLength(code, pbSrc); pbSrc = AdvanceOverOrderHeader(code, pbSrc)
            if fFirstLine:
                if fInsertFgPel: WritePixel(pbDest, fgPel); pbDest=NextPixel(pbDest); len--
                while len-- > 0: WritePixel(pbDest, BLACK); pbDest=NextPixel(pbDest)
            else:
                if fInsertFgPel:
                    WritePixel(pbDest, ReadPixel(pbDest-rowDelta) ^ fgPel); pbDest=NextPixel(pbDest); len--
                while len-- > 0:
                    WritePixel(pbDest, ReadPixel(pbDest-rowDelta)); pbDest=NextPixel(pbDest)
            fInsertFgPel = TRUE                    // <-- only BG runs set this
            continue

        fInsertFgPel = FALSE                       // every non-BG order clears it

        // ---- Foreground Run / lite+mega Set-FG Run ----
        if code in {REGULAR_FG_RUN, MEGA_MEGA_FG_RUN, LITE_SET_FG_FG_RUN, MEGA_MEGA_SET_FG_RUN}:
            len = ExtractRunLength(code, pbSrc); pbSrc = AdvanceOverOrderHeader(code, pbSrc)
            if code in {LITE_SET_FG_FG_RUN, MEGA_MEGA_SET_FG_RUN}:
                fgPel = ReadPixel(pbSrc); pbSrc = NextPixel(pbSrc)
            while len-- > 0:
                if fFirstLine: WritePixel(pbDest, fgPel)
                else:          WritePixel(pbDest, ReadPixel(pbDest-rowDelta) ^ fgPel)
                pbDest = NextPixel(pbDest)
            continue

        // ---- Dithered Run (2*len pixels A,B,A,B...) ----
        if code == LITE_DITHERED_RUN or code == MEGA_MEGA_DITHERED_RUN:
            len = ExtractRunLength(code, pbSrc); pbSrc = AdvanceOverOrderHeader(code, pbSrc)
            pixelA = ReadPixel(pbSrc); pbSrc = NextPixel(pbSrc)
            pixelB = ReadPixel(pbSrc); pbSrc = NextPixel(pbSrc)
            while len-- > 0:
                WritePixel(pbDest, pixelA); pbDest=NextPixel(pbDest)
                WritePixel(pbDest, pixelB); pbDest=NextPixel(pbDest)
            continue

        // ---- Color Run ----
        if code == REGULAR_COLOR_RUN or code == MEGA_MEGA_COLOR_RUN:
            len = ExtractRunLength(code, pbSrc); pbSrc = AdvanceOverOrderHeader(code, pbSrc)
            pixelA = ReadPixel(pbSrc); pbSrc = NextPixel(pbSrc)
            while len-- > 0: WritePixel(pbDest, pixelA); pbDest=NextPixel(pbDest)
            continue

        // ---- Foreground/Background Image (+ lite/mega Set-FG variants) ----
        if code in {REGULAR_FGBG_IMAGE, MEGA_MEGA_FGBG_IMAGE, LITE_SET_FG_FGBG_IMAGE, MEGA_MEGA_SET_FGBG_IMAGE}:
            len = ExtractRunLength(code, pbSrc); pbSrc = AdvanceOverOrderHeader(code, pbSrc)
            if code in {LITE_SET_FG_FGBG_IMAGE, MEGA_MEGA_SET_FGBG_IMAGE}:
                fgPel = ReadPixel(pbSrc); pbSrc = NextPixel(pbSrc)
            while len > 8:                          // full 8-pixel groups
                bitmask = *pbSrc++
                pbDest = fFirstLine ? WriteFirstLineFgBgImage(pbDest, bitmask, fgPel, 8)
                                    : WriteFgBgImage(pbDest, rowDelta, bitmask, fgPel, 8)
                len -= 8
            if len > 0:                             // trailing partial group
                bitmask = *pbSrc++
                pbDest = fFirstLine ? WriteFirstLineFgBgImage(pbDest, bitmask, fgPel, len)
                                    : WriteFgBgImage(pbDest, rowDelta, bitmask, fgPel, len)
            continue

        // ---- Color Image (raw copy) ----
        if code == REGULAR_COLOR_IMAGE or code == MEGA_MEGA_COLOR_IMAGE:
            len = ExtractRunLength(code, pbSrc); pbSrc = AdvanceOverOrderHeader(code, pbSrc)
            byteCount = len * PS
            while byteCount-- > 0: *pbDest++ = *pbSrc++
            continue

        // ---- Special FGBG (fixed 8-pixel mask, no mask byte in stream) ----
        if code == SPECIAL_FGBG_1:
            pbSrc += 1
            pbDest = fFirstLine ? WriteFirstLineFgBgImage(pbDest, 0x03, fgPel, 8)
                                : WriteFgBgImage(pbDest, rowDelta, 0x03, fgPel, 8)
            continue
        if code == SPECIAL_FGBG_2:
            pbSrc += 1
            pbDest = fFirstLine ? WriteFirstLineFgBgImage(pbDest, 0x05, fgPel, 8)
                                : WriteFgBgImage(pbDest, rowDelta, 0x05, fgPel, 8)
            continue

        // ---- Single WHITE / BLACK pixel ----
        if code == WHITE: pbSrc+=1; WritePixel(pbDest, WHITE_PIXEL); pbDest=NextPixel(pbDest); continue
        if code == BLACK: pbSrc+=1; WritePixel(pbDest, BLACK);       pbDest=NextPixel(pbDest); continue
```

---

## 6. RDP 6.0 Planar Codec Decode (RDP6_BITMAP_STREAM)

Confidence: **high.** Spec: [MS-RDPEGDI] §2.2.2.5.1 / §3.1.9. Reference: FreeRDP `libfreerdp/codec/planar.c`. Used for compressed 32bpp bitmaps.

### 6.1 FormatHeader byte (first byte of the stream)

| Bits | Field | Meaning |
|------|-------|---------|
| 0..2 | **CLL** (Color Loss Level) | 0 = lossless; 1..7 = chroma right-shifted by CLL bits before send (lossy) |
| 3 | **CS** (Chroma Subsampling) | 1 = two chroma planes are 2×2 subsampled (`ceil(W/2)×ceil(H/2)`); luma/alpha stay full-res |
| 4 | **RLE** | 1 = each color plane is RDP6-RLE compressed; 0 = planes raw |
| 5 | **NA** (No-Alpha) | 1 = alpha plane omitted (decoder fills A = 0xFF); 0 = alpha present |
| 6..7 | reserved | 0 |

Constants (FreeRDP `planar.c`): `PLANAR_FORMAT_HEADER_CLL_MASK=0x07`, `_CS=0x08`, `_RLE=0x10`, `_NA=0x20`.

**Color space selection:** if `CLL == 0 && CS == 0` → planes are **ARGB** (absolute R,G,B). Otherwise (CLL != 0 or CS == 1) → **AYCoCg** (alpha + luma Y + orange-chroma Co + green-chroma Cg); run the YCoCg→RGB inverse transform.

### 6.2 Plane layout / order

Planes concatenated in fixed order **A, R, G, B** (or **A, Y, Co, Cg**). When **NA=1** the alpha plane is absent → 3 planes. Each plane decoded independently (RAW or RLE per the RLE flag). With CS=1 only the two chroma planes are subsampled, pixel-doubled back to full resolution after decode.

Fully-uncompressed shortcut: FormatHeader `0x00` (all flags clear) followed by verbatim 32bpp data with a trailing `0x00` alignment pad.

### 6.3 Decode

```
decode(src, width, height):
  fh   = src[0]; p = src + 1
  cll  =  fh & 0x07
  cs   = (fh & 0x08) != 0
  rle  = (fh & 0x10) != 0
  na   = (fh & 0x20) != 0
  hasAlpha   = !na
  colorSpace = (cll == 0 && cs == 0) ? ARGB : AYCoCg

  planes = hasAlpha ? [A,c1,c2,c3] : [c1,c2,c3]
  for each plane:
      // plane dims: full WxH, EXCEPT cs=1 -> the two chroma planes are
      // ceil(W/2) x ceil(H/2); luma & alpha stay full.
      if rle:  decodePlaneRLE(p, plane)   // delta-encoded
      else:    decodePlaneRAW(p, plane)   // absolute bytes, W*H, no delta

  // RAW plane: copy (planeW*planeH) bytes verbatim, row-major, top-down.

  decodePlaneRLE(p, plane):
    for y in 0..planeH-1:
      x = 0
      while x < planeW:
        control    = *p++
        nRunLength = control & 0x0F         // low nibble
        cRawBytes  = (control >> 4) & 0x0F  // high nibble
        if   nRunLength == 1: nRunLength = 16 + cRawBytes; cRawBytes = 0
        elif nRunLength == 2: nRunLength = 32 + cRawBytes; cRawBytes = 0
        for i in 0..cRawBytes-1:            // literal segment
            rowbuf[x++] = *p++
        runByte = (cRawBytes>0) ? rowbuf[x-1] : 0x00   // run segment
        for i in 0..nRunLength-1:
            rowbuf[x++] = runByte
      // de-delta the scanline in place:
      for x in 0..planeW-1:
        if y == 0:
            plane[0][x] = rowbuf[x]              // absolute
        else:
            d = rowbuf[x]                        // sign-encoded delta byte
            if (d & 1): delta = -(((d >> 1) + 1))// odd  => negative
            else:       delta =  (d >> 1)        // even => positive
            plane[y][x] = (UINT8)(plane[y-1][x] + delta)  // wraps mod 256

  // Reassemble:
  //  if cs=1: upsample chroma planes (pixel-double) to full res.
  //  if AYCoCg: per-pixel YCoCg->RGB:
  //     R = Y + Co - Cg ; G = Y + Cg ; B = Y - Co - Cg
  //     (chroma stored reduced by CLL bits; restore by shifting by cll)
  //  Emit ARGB32 = (A<<24)|(R<<16)|(G<<8)|B
```

Key rules:
- **RAW plane** = absolute values, no delta.
- **RLE plane**: scanline 0 bytes are **absolute**; every later scanline's bytes are **signed deltas vs the pixel directly above** (same column, previous scanline). Delta byte is sign-and-magnitude, **sign in the LSB**: even `d` → `+(d>>1)`, odd `d` → `-((d>>1)+1)`. Reconstruct `plane[y][x] = (uint8)(plane[y-1][x] + delta)` mod 256.
- Extended-run escape: `nRunLength==1` → `16 + cRawBytes`; `nRunLength==2` → `32 + cRawBytes` (max run 47).

---

## 7. Pointer / Cursor Updates

Confidence: **high** for structures; the AND=1 & XOR≠0 inversion and 32bpp-alpha combination are flagged in Open Questions. Slow-path: [MS-RDPBCGR] §2.2.9.1.1.4; fast-path: §2.2.9.1.2.1.

### 7.1 Structures

**TS_POINT16** (§2.2.9.1.1.4.1): two UINT16 LE — `xPos`, `yPos`.

**TS_POINTERPOSATTRIBUTE** (§2.2.9.1.1.4.2): a single `TS_POINT16 position` — moves cursor without changing shape.

**TS_COLORPOINTERATTRIBUTE** (§2.2.9.1.1.4.4) — wire order (all LE):

| Field | Size | Notes |
|-------|------|-------|
| cacheIndex | UINT16 | slot in pointer cache |
| hotSpot | TS_POINT16 | (x,y) click point within the image |
| width | UINT16 | typically 32 (≤96 without large-pointer cap) |
| height | UINT16 | typically 32 |
| lengthAndMask | UINT16 | byte length of andMaskData |
| lengthXorMask | UINT16 | byte length of xorMaskData |
| xorMaskData | var | color (XOR) bitmap, 24bpp here |
| andMaskData | var | 1bpp AND/transparency bitmap |
| pad | 1 byte (optional) | present in slow-path so total is even |

**TS_POINTERATTRIBUTE** ("New Pointer", §2.2.9.1.1.4.5): `xorBpp` (UINT16: 1/8/15/16/24/**32**) followed by an embedded TS_COLORPOINTERATTRIBUTE. Used for non-24bpp cursors (esp. 32bpp with real alpha).

**TS_CACHEDPOINTERATTRIBUTE** (§2.2.9.1.1.4.3): just `cacheIndex` (UINT16) — re-selects a cached shape.

**TS_SYSTEMPOINTERATTRIBUTE** (§2.2.9.1.1.4.6): `systemPointerType` UINT32 — `SYSPTR_NULL = 0x00000000` (hidden) or `SYSPTR_DEFAULT = 0x00007F00` (OS default arrow).

Slow-path wrapper **TS_POINTER_PDU** (§2.2.9.1.1.4) `messageType` UINT16: `TS_PTRMSGTYPE_SYSTEM=0x0001`, `POSITION=0x0003`, `COLOR=0x0006`, `CACHED=0x0007`, `POINTER=0x0008`.

### 7.2 AND / XOR mask format → RGBA

Both masks stored **bottom-up** (last scanline first), each scanline padded to a **2-byte (WORD) boundary**:
- **AND mask** = 1 bit per pixel. `andStride = ((width + 15) / 16) * 2` bytes/scanline. Bit = transparency select.
- **XOR mask** = color, `xorBpp` bits/pixel (24 default → 3 bytes BGR per pixel). `xorStride = ((width * xorBpp + 15) / 16) * 2` bytes/scanline.

Per-pixel semantics (classic Windows AND/XOR): `screen = (screen AND andbit) XOR xorcolor`:

| AND bit | XOR color | Result → RGBA alpha |
|---------|-----------|---------------------|
| 0 | color C | opaque pixel C, alpha = 255 |
| 1 | 0 (black) | fully transparent, alpha = 0 |
| 1 | non-zero (typ. white) | inverted screen; RGBA can't invert — approximate (render as opaque black/white or leave transparent) |

**Build an RGBA cursor:**
1. For each output row `y` (top-down), read source scanline `srcY = height - 1 - y` from both masks (they're bottom-up).
2. For each `x`: AND bit `a = (andRow[x>>3] >> (7 - (x&7))) & 1`; read the XOR pixel (3 bytes BGR at `xorRow + x*3`, or 4 bytes if `xorBpp==32`).
3. Emit RGBA: `A = a ? 0 : 255` (opaque where AND=0), else handle the AND=1 & XOR≠0 inversion case; `R,G,B` from the XOR pixel.
4. **32bpp special case** (via TS_POINTERATTRIBUTE): XOR data carries per-pixel alpha — use it directly and treat the AND mask as a secondary/legacy hint (many clients OR the two: transparent if alpha==0 or AND bit set).

### 7.3 Fast-path pointer update codes

The fast-path fragment header (§2.2.9.1.2.1) carries a 4-bit `updateCode` in `updateHeader` (bits 0..3):

| Code | Value | Structure / meaning |
|------|-------|---------------------|
| FASTPATH_UPDATETYPE_PTR_NULL | **0x5** | TS_FP_SYSTEMPOINTERHIDDENATTRIBUTE (§2.2.9.1.2.1.5) — hide cursor (no payload) |
| FASTPATH_UPDATETYPE_PTR_DEFAULT | **0x6** | TS_FP_SYSTEMPOINTERDEFAULTATTRIBUTE (§2.2.9.1.2.1.6) — OS default arrow (no payload) |
| FASTPATH_UPDATETYPE_PTR_POSITION | **0x8** | TS_FP_POINTERPOSATTRIBUTE (§2.2.9.1.2.1.4) — TS_POINT16 move |
| FASTPATH_UPDATETYPE_COLOR | **0x9** | TS_FP_COLORPOINTERATTRIBUTE (§2.2.9.1.2.1.7) — same body as slow-path TS_COLORPOINTERATTRIBUTE |
| FASTPATH_UPDATETYPE_CACHED | **0xA** | TS_FP_CACHEDPOINTERATTRIBUTE (§2.2.9.1.2.1.9) — cacheIndex select |
| FASTPATH_UPDATETYPE_POINTER | **0xB** | TS_FP_POINTERATTRIBUTE (§2.2.9.1.2.1.8) — New Pointer with xorBpp |
| FASTPATH_UPDATETYPE_LARGE_POINTER | **0xC** | TS_FP_LARGEPOINTERATTRIBUTE (§2.2.9.1.2.1.11) — negotiated via Large Pointer Capability Set (§2.2.7.2.7); width/height are UINT16 up to 384×384 |

Notes: default/null (system) pointers carry no shape payload — just the code. COLOR vs POINTER differ only by the leading `xorBpp` field (POINTER adds it; COLOR is fixed 24bpp). CACHED is cheapest. Large-pointer must be enabled by capability exchange before the server may send >96×96 or the LARGE_POINTER fast-path code.

---

## 8. Open Questions / Low-Confidence Items

These are the points where the spec text, reference implementations, or wire captures may diverge — verify each against a real session before shipping.

1. **Fast-path bitmap `updateType` presence (medium).** Per the letter of MS-RDPBCGR §2.2.9.1.2.1.1.1.2, the fast-path bitmap payload embeds the *full* TS_UPDATE_BITMAP_DATA and **still begins with `updateType = 0x0001`**, then numberRectangles. But FreeRDP's fast-path bitmap handler assumes the payload starts directly at `numberRectangles`. **Action:** decode a live capture and check whether the first 2 bytes after `size` are `01 00` (spec) or the rectangle count (FreeRDP). Handle both defensively — if the first u16 == 0x0001 and a second u16 plausibly reads as a rectangle count, consume updateType; otherwise treat the first u16 as numberRectangles.

2. **Color Image `byteCount` (low).** Spec pseudo-code literally writes `byteCount = runLength * GetColorDepth()`; every real implementation uses `runLength * pixelSizeInBytes` (PS). Treated here as PS bytes. Confirmed by FreeRDP/rdesktop but worth an assertion in code.

3. **`fInsertFgPel` first-line semantics (low-medium).** The interaction of the inserted foreground pel with `fFirstLine` (first inserted pel written as `fgPel` rather than `above XOR fgPel`) is transcribed from the spec routine but is subtle. Validate against known-good RLE test vectors (e.g. FreeRDP `TestFreeRDPCodecInterleaved`).

4. **`fFirstLine` clear condition (low).** The exact trigger for clearing `fFirstLine`/`fInsertFgPel` ("once `pbDest` has advanced ≥ `rowDelta` from the buffer start") is expressed as a running offset check. Implementations differ slightly in whether the check happens at the top of the loop or after each write; verify the boundary pixel of row 0→1 renders correctly.

5. **Planar CLL chroma scaling direction & rounding (medium).** The chroma-precision restoration for `CLL != 0` (shift chroma left/right by `cll` bits) and the exact rounding in the YCoCg→RGB step (`R=Y+Co−Cg; G=Y+Cg; B=Y−Co−Cg`) are not pinned to bit-exact behavior here. Cross-check against FreeRDP `planar.c` `planar_decompress` and its `YCoCg` conversion for the exact shifts and clamps.

6. **Planar RLE run byte when `cRawBytes == 0` at scanline start (low).** The rule "run byte = 0x00 when no literal preceded it" is inferred; confirm the very first control byte of a scanline that starts with a pure run reproduces correctly.

7. **Cursor AND=1 & XOR≠0 inversion (medium).** True Windows semantics invert the screen pixel, which a static RGBA cursor cannot represent. The approximation (render opaque black/white, or transparent) is a rendering choice, not spec-defined. Decide per-renderer; most modern clients render such pixels as opaque and accept minor visual drift.

8. **32bpp cursor alpha vs AND mask combination (medium).** For `xorBpp == 32`, whether to use the XOR alpha alone, the AND mask alone, or OR the two is implementation-defined. Recommendation here (OR: transparent if `alpha==0 || andBit`) matches common client behavior but is unverified against Windows RDP server output.

9. **`compressionFlags` byte semantics (low).** When fast-path `compression == FASTPATH_OUTPUT_COMPRESSION_USED (0x2)`, the extra `compressionFlags` byte reuses the Share Data Header `compressedType` flags (§2.2.8.1.1.1.2). Bulk decompression (MPPC) is out of scope for Phases 4/5 but the flag byte must still be consumed. Confirm which bits appear in TLS-wrapped sessions (usually none — bulk compression is typically off under TLS).

10. **Length-field endianness caveat (low, but easy to get wrong).** The fast-path `length1/length2` field is the sole **big-endian** 14-bit quantity in an otherwise little-endian protocol. Double-check the encoder ORs `0x8000` into a big-endian u16, not little-endian.

11. **Slow-path color pointer trailing `pad` (low).** The optional 1-byte pad on slow-path TS_COLORPOINTERATTRIBUTE (to make the total even) is present in slow-path but the exact presence rule vs the fast-path variant should be confirmed from a capture; over-reading it corrupts the next PDU.

---

Sources (all verified against live Microsoft Open Specifications):
- MS-RDPBCGR §2.2.8.1.2 / §2.2.8.1.2.2.x (fast-path input), §2.2.9.1.2 / §2.2.9.1.2.1 (fast-path output), §2.2.9.1.1.3.1.2.x (bitmap update, TS_BITMAP_DATA, TS_CD_HEADER, Interleaved RLE), §2.2.9.1.1.4.x & §2.2.9.1.2.1.x (pointer updates).
- MS-RDPEGDI §2.2.2.5.1 (RDP6_BITMAP_STREAM planar codec), §3.1.9 (color-plane RLE + delta scanline, YCoCg color-space conversion).
- Reference implementations: FreeRDP `libfreerdp/codec/interleaved.c`, `planar.c`, `fastpath.c`; rdesktop `bitmap.c`.