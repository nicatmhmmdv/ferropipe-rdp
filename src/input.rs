//! Fast-path client input ([MS-RDPBCGR] 2.2.8.1.2): keyboard and mouse events
//! the client sends to the server. A compact header, a length, then a sequence of
//! events. Under TLS there is no per-PDU signature.

use bytes::{BufMut, BytesMut};

/// Fast-path input event codes (eventHeader bits 5-7).
const EVENT_SCANCODE: u8 = 0;
const EVENT_MOUSE: u8 = 1;
const EVENT_MOUSEX: u8 = 2;
const EVENT_UNICODE: u8 = 4;

/// Keyboard event flags (eventHeader bits 0-4).
pub const KBDFLAGS_RELEASE: u8 = 0x01;
pub const KBDFLAGS_EXTENDED: u8 = 0x02;

/// Mouse pointerFlags ([MS-RDPBCGR] 2.2.8.1.2.2.3).
pub const PTRFLAGS_WHEEL: u16 = 0x0200;
pub const PTRFLAGS_HWHEEL: u16 = 0x0400;
pub const PTRFLAGS_WHEEL_NEGATIVE: u16 = 0x0100;
/// The wheel rotation amount lives in the low 9 bits: bit 8 is
/// `PTRFLAGS_WHEEL_NEGATIVE`, bits 0-7 the amount (two's complement when negative).
pub const WHEEL_ROTATION_MASK: u16 = 0x01FF;
/// Rotation units per wheel notch (Windows' `WHEEL_DELTA`).
pub const WHEEL_NOTCH: u16 = 0x78;
pub const PTRFLAGS_MOVE: u16 = 0x0800;
pub const PTRFLAGS_DOWN: u16 = 0x8000;
pub const PTRFLAGS_BUTTON1: u16 = 0x1000; // left
pub const PTRFLAGS_BUTTON2: u16 = 0x2000; // right
pub const PTRFLAGS_BUTTON3: u16 = 0x4000; // middle

fn event_header(event_code: u8, event_flags: u8) -> u8 {
    (event_code << 5) | (event_flags & 0x1f)
}

/// A scancode keyboard event.
pub fn scancode_event(key_code: u8, pressed: bool, extended: bool) -> Vec<u8> {
    let mut flags = 0u8;
    if !pressed {
        flags |= KBDFLAGS_RELEASE;
    }
    if extended {
        flags |= KBDFLAGS_EXTENDED;
    }
    vec![event_header(EVENT_SCANCODE, flags), key_code]
}

/// A Unicode keyboard event (sends a character directly).
pub fn unicode_event(code: u16, pressed: bool) -> Vec<u8> {
    let flags = if pressed { 0 } else { KBDFLAGS_RELEASE };
    let mut v = vec![event_header(EVENT_UNICODE, flags)];
    v.extend_from_slice(&code.to_le_bytes());
    v
}

/// A mouse event: pointer flags + absolute position.
pub fn mouse_event(pointer_flags: u16, x: u16, y: u16) -> Vec<u8> {
    let mut b = BytesMut::new();
    b.put_u8(event_header(EVENT_MOUSE, 0));
    b.put_u16_le(pointer_flags);
    b.put_u16_le(x);
    b.put_u16_le(y);
    b.to_vec()
}

/// One notch of mouse-wheel rotation at the pointer position. `vertical` picks
/// `PTRFLAGS_WHEEL` (positive = away from the user) over `PTRFLAGS_HWHEEL`
/// (positive = to the right). `notches` is clamped to ±1: a rotation field only
/// holds one `WHEEL_NOTCH` cleanly, so callers emit one event per notch.
pub fn wheel_event(vertical: bool, notches: i32, x: u16, y: u16) -> Vec<u8> {
    let axis = if vertical {
        PTRFLAGS_WHEEL
    } else {
        PTRFLAGS_HWHEEL
    };
    // ±0x78 as a 9-bit two's complement field: -0x78 → 0x188, whose bit 8 is
    // exactly PTRFLAGS_WHEEL_NEGATIVE.
    let rotation = (notches.clamp(-1, 1) * i32::from(WHEEL_NOTCH)) as i16;
    mouse_event(axis | (rotation as u16 & WHEEL_ROTATION_MASK), x, y)
}

/// An extended mouse event (buttons 4/5).
pub fn mouse_x_event(pointer_flags: u16, x: u16, y: u16) -> Vec<u8> {
    let mut b = BytesMut::new();
    b.put_u8(event_header(EVENT_MOUSEX, 0));
    b.put_u16_le(pointer_flags);
    b.put_u16_le(x);
    b.put_u16_le(y);
    b.to_vec()
}

/// Assemble a fast-path input PDU from the given events.
pub fn input_pdu(events: &[Vec<u8>]) -> Vec<u8> {
    let num = events.len();
    // fpInputHeader: action=0 (bits 0-1), numberEvents (bits 2-5) if ≤ 15.
    let header = if num <= 15 { (num as u8) << 2 } else { 0 };

    let mut body = Vec::new();
    if num > 15 {
        body.push(num as u8); // separate numberEvents byte
    }
    for e in events {
        body.extend_from_slice(e);
    }

    // length counts the whole PDU (header + length bytes + body).
    let base = 1 + body.len();
    let mut out = Vec::new();
    out.push(header);
    if base + 1 < 0x80 {
        out.push((base + 1) as u8);
    } else {
        let total = base + 2;
        out.push(0x80 | (total >> 8) as u8);
        out.push((total & 0xff) as u8);
    }
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scancode_press_and_release() {
        let press = scancode_event(0x1E, true, false); // 'A' make
        assert_eq!(press, vec![0x00, 0x1E]);
        let release = scancode_event(0x1E, false, false); // 'A' break
        assert_eq!(release, vec![KBDFLAGS_RELEASE, 0x1E]);
    }

    #[test]
    fn scancode_extended_press_and_release_set_extended_flag() {
        let press = scancode_event(0x53, true, true); // Delete (E0 53) make
        assert_eq!(press, vec![KBDFLAGS_EXTENDED, 0x53]);
        let release = scancode_event(0x53, false, true); // Delete break
        assert_eq!(release, vec![KBDFLAGS_RELEASE | KBDFLAGS_EXTENDED, 0x53]);
    }

    #[test]
    fn mouse_move_event_layout() {
        let ev = mouse_event(PTRFLAGS_MOVE, 100, 200);
        assert_eq!(ev[0], 0x20); // eventCode MOUSE = 1 → 1<<5
        assert_eq!(u16::from_le_bytes([ev[1], ev[2]]), PTRFLAGS_MOVE);
        assert_eq!(u16::from_le_bytes([ev[3], ev[4]]), 100);
        assert_eq!(u16::from_le_bytes([ev[5], ev[6]]), 200);
    }

    #[test]
    fn input_pdu_wraps_events_with_count() {
        let events = vec![
            scancode_event(0x1E, true, false),
            mouse_event(PTRFLAGS_MOVE, 1, 2),
        ];
        let pdu = input_pdu(&events);
        assert_eq!(pdu[0] >> 2 & 0x0f, 2); // numberEvents = 2
        assert_eq!(pdu[0] & 0x03, 0); // action = fastpath
                                      // length byte then the two events
        assert_eq!(pdu[1] as usize, pdu.len());
    }

    #[test]
    fn wheel_event_one_notch_up_is_wheel_plus_0x78() {
        // Arrange / Act: +1 vertical notch at (10, 20).
        let ev = wheel_event(true, 1, 10, 20);
        // Assert: eventCode MOUSE, pointerFlags = PTRFLAGS_WHEEL | 0x0078 (LE), then x, y.
        assert_eq!(ev, vec![0x20, 0x78, 0x02, 0x0A, 0x00, 0x14, 0x00]);
    }

    #[test]
    fn wheel_event_one_notch_down_sets_negative_and_twos_complement() {
        // Arrange / Act: -1 vertical notch.
        let ev = wheel_event(true, -1, 10, 20);
        // Assert: PTRFLAGS_WHEEL | PTRFLAGS_WHEEL_NEGATIVE | 0x0088 (= 0x100 - 0x78).
        assert_eq!(ev, vec![0x20, 0x88, 0x03, 0x0A, 0x00, 0x14, 0x00]);
    }

    #[test]
    fn wheel_event_horizontal_notch_uses_hwheel_flag() {
        // Arrange / Act: +1 horizontal notch (to the right).
        let ev = wheel_event(false, 1, 10, 20);
        // Assert: PTRFLAGS_HWHEEL | 0x0078.
        assert_eq!(ev, vec![0x20, 0x78, 0x04, 0x0A, 0x00, 0x14, 0x00]);
    }

    #[test]
    fn wheel_event_clamps_to_one_notch_per_event() {
        // Arrange / Act / Assert: callers emit one event per notch.
        assert_eq!(wheel_event(true, 5, 1, 2), wheel_event(true, 1, 1, 2));
        assert_eq!(wheel_event(false, -3, 1, 2), wheel_event(false, -1, 1, 2));
    }

    #[test]
    fn left_click_is_down_plus_button1() {
        let down = mouse_event(PTRFLAGS_DOWN | PTRFLAGS_BUTTON1, 5, 6);
        let flags = u16::from_le_bytes([down[1], down[2]]);
        assert!(flags & PTRFLAGS_DOWN != 0 && flags & PTRFLAGS_BUTTON1 != 0);
    }
}
