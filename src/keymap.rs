//! Physical-key → PC/AT scan code set 1 keymap for [MS-RDPBCGR] keyboard events.
//!
//! RDP keyboard events carry *scan code set 1 make codes*, i.e. the byte a PC/AT
//! keyboard emits for a physical key position, independent of the OS keyboard
//! layout. Keys that a real keyboard prefixes with `0xE0` (right Ctrl/Alt, the
//! navigation cluster, numpad Enter/`/`, Windows and Menu keys) are sent with the
//! *extended* flag instead of the prefix byte.
//!
//! [`KeyCode`] names keys by their **US-QWERTY position**, so a consuming app must
//! map from the platform's *physical* key code (e.g. `egui::Key`, `winit
//! KeyCode`, X11 keycode, Windows scan code) — never from the typed character.
//! That keeps the mapping correct on non-US layouts: the server applies its own
//! layout to the position we send.
//!
//! Not covered: `Pause`/`Break` (0xE1-prefixed, needs KBDFLAGS_EXTENDED1, which
//! the fast-path encoder does not carry) and the ISO/JIS-only extra keys.

use crate::input::{scancode_event, KBDFLAGS_EXTENDED, KBDFLAGS_RELEASE};

#[cfg(feature = "egui")]
pub mod egui;

/// A physical key, platform-neutral (named after the US-QWERTY position).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyCode {
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
    I,
    J,
    K,
    L,
    M,
    N,
    O,
    P,
    Q,
    R,
    S,
    T,
    U,
    V,
    W,
    X,
    Y,
    Z,
    Digit0,
    Digit1,
    Digit2,
    Digit3,
    Digit4,
    Digit5,
    Digit6,
    Digit7,
    Digit8,
    Digit9,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    Escape,
    Backquote,
    Minus,
    Equal,
    Backspace,
    Tab,
    BracketLeft,
    BracketRight,
    Backslash,
    CapsLock,
    Semicolon,
    Quote,
    Enter,
    ShiftLeft,
    Comma,
    Period,
    Slash,
    ShiftRight,
    ControlLeft,
    AltLeft,
    Space,
    AltRight,
    ControlRight,
    SuperLeft,
    SuperRight,
    ContextMenu,
    Insert,
    Delete,
    Home,
    End,
    PageUp,
    PageDown,
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
    NumLock,
    ScrollLock,
    PrintScreen,
    Numpad0,
    Numpad1,
    Numpad2,
    Numpad3,
    Numpad4,
    Numpad5,
    Numpad6,
    Numpad7,
    Numpad8,
    Numpad9,
    NumpadAdd,
    NumpadSubtract,
    NumpadMultiply,
    NumpadDivide,
    NumpadDecimal,
    NumpadEnter,
}

/// Scan code set 1 make code plus whether it needs the extended (0xE0) flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scancode {
    pub code: u8,
    pub extended: bool,
}

/// A fast-path keyboard event ready for the wire: the eventHeader flag bits
/// (`KBDFLAGS_RELEASE` / `KBDFLAGS_EXTENDED`) plus the make code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyEvent {
    pub code: u8,
    pub flags: u8,
}

impl KeyCode {
    /// Every key this keymap knows, for building lookup tables.
    pub const ALL: &'static [KeyCode] = &[
        KeyCode::A,
        KeyCode::B,
        KeyCode::C,
        KeyCode::D,
        KeyCode::E,
        KeyCode::F,
        KeyCode::G,
        KeyCode::H,
        KeyCode::I,
        KeyCode::J,
        KeyCode::K,
        KeyCode::L,
        KeyCode::M,
        KeyCode::N,
        KeyCode::O,
        KeyCode::P,
        KeyCode::Q,
        KeyCode::R,
        KeyCode::S,
        KeyCode::T,
        KeyCode::U,
        KeyCode::V,
        KeyCode::W,
        KeyCode::X,
        KeyCode::Y,
        KeyCode::Z,
        KeyCode::Digit0,
        KeyCode::Digit1,
        KeyCode::Digit2,
        KeyCode::Digit3,
        KeyCode::Digit4,
        KeyCode::Digit5,
        KeyCode::Digit6,
        KeyCode::Digit7,
        KeyCode::Digit8,
        KeyCode::Digit9,
        KeyCode::F1,
        KeyCode::F2,
        KeyCode::F3,
        KeyCode::F4,
        KeyCode::F5,
        KeyCode::F6,
        KeyCode::F7,
        KeyCode::F8,
        KeyCode::F9,
        KeyCode::F10,
        KeyCode::F11,
        KeyCode::F12,
        KeyCode::Escape,
        KeyCode::Backquote,
        KeyCode::Minus,
        KeyCode::Equal,
        KeyCode::Backspace,
        KeyCode::Tab,
        KeyCode::BracketLeft,
        KeyCode::BracketRight,
        KeyCode::Backslash,
        KeyCode::CapsLock,
        KeyCode::Semicolon,
        KeyCode::Quote,
        KeyCode::Enter,
        KeyCode::ShiftLeft,
        KeyCode::Comma,
        KeyCode::Period,
        KeyCode::Slash,
        KeyCode::ShiftRight,
        KeyCode::ControlLeft,
        KeyCode::AltLeft,
        KeyCode::Space,
        KeyCode::AltRight,
        KeyCode::ControlRight,
        KeyCode::SuperLeft,
        KeyCode::SuperRight,
        KeyCode::ContextMenu,
        KeyCode::Insert,
        KeyCode::Delete,
        KeyCode::Home,
        KeyCode::End,
        KeyCode::PageUp,
        KeyCode::PageDown,
        KeyCode::ArrowUp,
        KeyCode::ArrowDown,
        KeyCode::ArrowLeft,
        KeyCode::ArrowRight,
        KeyCode::NumLock,
        KeyCode::ScrollLock,
        KeyCode::PrintScreen,
        KeyCode::Numpad0,
        KeyCode::Numpad1,
        KeyCode::Numpad2,
        KeyCode::Numpad3,
        KeyCode::Numpad4,
        KeyCode::Numpad5,
        KeyCode::Numpad6,
        KeyCode::Numpad7,
        KeyCode::Numpad8,
        KeyCode::Numpad9,
        KeyCode::NumpadAdd,
        KeyCode::NumpadSubtract,
        KeyCode::NumpadMultiply,
        KeyCode::NumpadDivide,
        KeyCode::NumpadDecimal,
        KeyCode::NumpadEnter,
    ];

    /// The set 1 make code for this key and whether it is 0xE0-extended.
    ///
    /// This is the standard PC/AT scan code set 1 table, laid out by keyboard row.
    /// It is deliberately one exhaustive `match` (no wildcard) so adding a
    /// `KeyCode` variant without a scancode is a compile error.
    pub fn scancode(self) -> Scancode {
        use KeyCode::*;
        match self {
            // Row 0: Escape + function keys.
            Escape => plain(0x01),
            F1 => plain(0x3B),
            F2 => plain(0x3C),
            F3 => plain(0x3D),
            F4 => plain(0x3E),
            F5 => plain(0x3F),
            F6 => plain(0x40),
            F7 => plain(0x41),
            F8 => plain(0x42),
            F9 => plain(0x43),
            F10 => plain(0x44),
            F11 => plain(0x57),
            F12 => plain(0x58),
            PrintScreen => ext(0x37),
            ScrollLock => plain(0x46),
            // Row 1: digits.
            Backquote => plain(0x29),
            Digit1 => plain(0x02),
            Digit2 => plain(0x03),
            Digit3 => plain(0x04),
            Digit4 => plain(0x05),
            Digit5 => plain(0x06),
            Digit6 => plain(0x07),
            Digit7 => plain(0x08),
            Digit8 => plain(0x09),
            Digit9 => plain(0x0A),
            Digit0 => plain(0x0B),
            Minus => plain(0x0C),
            Equal => plain(0x0D),
            Backspace => plain(0x0E),
            // Row 2: QWERTY.
            Tab => plain(0x0F),
            Q => plain(0x10),
            W => plain(0x11),
            E => plain(0x12),
            R => plain(0x13),
            T => plain(0x14),
            Y => plain(0x15),
            U => plain(0x16),
            I => plain(0x17),
            O => plain(0x18),
            P => plain(0x19),
            BracketLeft => plain(0x1A),
            BracketRight => plain(0x1B),
            Backslash => plain(0x2B),
            // Row 3: home row.
            CapsLock => plain(0x3A),
            A => plain(0x1E),
            S => plain(0x1F),
            D => plain(0x20),
            F => plain(0x21),
            G => plain(0x22),
            H => plain(0x23),
            J => plain(0x24),
            K => plain(0x25),
            L => plain(0x26),
            Semicolon => plain(0x27),
            Quote => plain(0x28),
            Enter => plain(0x1C),
            // Row 4: shift row.
            ShiftLeft => plain(0x2A),
            Z => plain(0x2C),
            X => plain(0x2D),
            C => plain(0x2E),
            V => plain(0x2F),
            B => plain(0x30),
            N => plain(0x31),
            M => plain(0x32),
            Comma => plain(0x33),
            Period => plain(0x34),
            Slash => plain(0x35),
            ShiftRight => plain(0x36),
            // Row 5: modifiers + space.
            ControlLeft => plain(0x1D),
            SuperLeft => ext(0x5B),
            AltLeft => plain(0x38),
            Space => plain(0x39),
            AltRight => ext(0x38),
            SuperRight => ext(0x5C),
            ContextMenu => ext(0x5D),
            ControlRight => ext(0x1D),
            // Navigation cluster (all 0xE0-prefixed).
            Insert => ext(0x52),
            Delete => ext(0x53),
            Home => ext(0x47),
            End => ext(0x4F),
            PageUp => ext(0x49),
            PageDown => ext(0x51),
            ArrowUp => ext(0x48),
            ArrowDown => ext(0x50),
            ArrowLeft => ext(0x4B),
            ArrowRight => ext(0x4D),
            // Numpad: the digits share codes with the navigation keys minus the prefix.
            NumLock => plain(0x45),
            NumpadDivide => ext(0x35),
            NumpadMultiply => plain(0x37),
            NumpadSubtract => plain(0x4A),
            Numpad7 => plain(0x47),
            Numpad8 => plain(0x48),
            Numpad9 => plain(0x49),
            NumpadAdd => plain(0x4E),
            Numpad4 => plain(0x4B),
            Numpad5 => plain(0x4C),
            Numpad6 => plain(0x4D),
            Numpad1 => plain(0x4F),
            Numpad2 => plain(0x50),
            Numpad3 => plain(0x51),
            Numpad0 => plain(0x52),
            NumpadDecimal => plain(0x53),
            NumpadEnter => ext(0x1C),
        }
    }

    /// True for the eight modifier keys (Shift/Ctrl/Alt/Super, left and right).
    pub fn is_modifier(self) -> bool {
        use KeyCode::*;
        matches!(
            self,
            ShiftLeft
                | ShiftRight
                | ControlLeft
                | ControlRight
                | AltLeft
                | AltRight
                | SuperLeft
                | SuperRight
        )
    }
}

const fn plain(code: u8) -> Scancode {
    Scancode {
        code,
        extended: false,
    }
}

const fn ext(code: u8) -> Scancode {
    Scancode {
        code,
        extended: true,
    }
}

impl KeyEvent {
    /// Whether this is a key-up (break) event.
    pub fn is_release(self) -> bool {
        self.flags & KBDFLAGS_RELEASE != 0
    }

    /// Whether the key carries the extended (0xE0) flag.
    pub fn is_extended(self) -> bool {
        self.flags & KBDFLAGS_EXTENDED != 0
    }

    /// Encode as a fast-path scancode input event (see [`scancode_event`]).
    pub fn encode(self) -> Vec<u8> {
        scancode_event(self.code, !self.is_release(), self.is_extended())
    }
}

/// The flags/code pair for pressing (`pressed == true`) or releasing a key.
pub fn key_event(key: KeyCode, pressed: bool) -> KeyEvent {
    let Scancode { code, extended } = key.scancode();
    let release = if pressed { 0 } else { KBDFLAGS_RELEASE };
    let extended = if extended { KBDFLAGS_EXTENDED } else { 0 };
    KeyEvent {
        code,
        flags: release | extended,
    }
}

/// Ctrl+Alt+Del: press ControlLeft, AltLeft, Delete, then release in reverse.
pub fn secure_attention_sequence() -> Vec<KeyEvent> {
    const KEYS: [KeyCode; 3] = [KeyCode::ControlLeft, KeyCode::AltLeft, KeyCode::Delete];
    let presses = KEYS.iter().map(|&k| key_event(k, true));
    let releases = KEYS.iter().rev().map(|&k| key_event(k, false));
    presses.chain(releases).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// The 18 keys a PC/AT keyboard prefixes with 0xE0.
    const EXTENDED_KEYS: [KeyCode; 18] = [
        KeyCode::NumpadEnter,
        KeyCode::ControlRight,
        KeyCode::NumpadDivide,
        KeyCode::PrintScreen,
        KeyCode::AltRight,
        KeyCode::Home,
        KeyCode::ArrowUp,
        KeyCode::PageUp,
        KeyCode::ArrowLeft,
        KeyCode::ArrowRight,
        KeyCode::End,
        KeyCode::ArrowDown,
        KeyCode::PageDown,
        KeyCode::Insert,
        KeyCode::Delete,
        KeyCode::SuperLeft,
        KeyCode::SuperRight,
        KeyCode::ContextMenu,
    ];

    const MODIFIER_KEYS: [KeyCode; 8] = [
        KeyCode::ShiftLeft,
        KeyCode::ShiftRight,
        KeyCode::ControlLeft,
        KeyCode::ControlRight,
        KeyCode::AltLeft,
        KeyCode::AltRight,
        KeyCode::SuperLeft,
        KeyCode::SuperRight,
    ];

    fn assert_codes(expected: &[(KeyCode, u8)], extended: bool) {
        for &(key, code) in expected {
            // Act
            let sc = key.scancode();
            // Assert
            assert_eq!(sc, Scancode { code, extended }, "{key:?}");
        }
    }

    #[test]
    fn escape_and_digit_row_use_expected_set1_codes() {
        // Arrange
        let expected = [
            (KeyCode::Escape, 0x01),
            (KeyCode::Digit1, 0x02),
            (KeyCode::Digit9, 0x0A),
            (KeyCode::Digit0, 0x0B),
            (KeyCode::Minus, 0x0C),
            (KeyCode::Equal, 0x0D),
            (KeyCode::Backspace, 0x0E),
            (KeyCode::Tab, 0x0F),
        ];
        // Act + Assert
        assert_codes(&expected, false);
    }

    #[test]
    fn qwerty_rows_use_expected_set1_codes() {
        // Arrange
        let expected = [
            (KeyCode::Q, 0x10),
            (KeyCode::P, 0x19),
            (KeyCode::BracketLeft, 0x1A),
            (KeyCode::BracketRight, 0x1B),
            (KeyCode::Enter, 0x1C),
            (KeyCode::ControlLeft, 0x1D),
            (KeyCode::A, 0x1E),
            (KeyCode::L, 0x26),
            (KeyCode::Semicolon, 0x27),
            (KeyCode::Quote, 0x28),
            (KeyCode::Backquote, 0x29),
            (KeyCode::ShiftLeft, 0x2A),
            (KeyCode::Backslash, 0x2B),
            (KeyCode::Z, 0x2C),
            (KeyCode::M, 0x32),
            (KeyCode::Comma, 0x33),
            (KeyCode::Period, 0x34),
            (KeyCode::Slash, 0x35),
            (KeyCode::ShiftRight, 0x36),
            (KeyCode::AltLeft, 0x38),
            (KeyCode::Space, 0x39),
            (KeyCode::CapsLock, 0x3A),
        ];
        // Act + Assert
        assert_codes(&expected, false);
    }

    #[test]
    fn function_and_lock_keys_use_expected_set1_codes() {
        // Arrange
        let expected = [
            (KeyCode::F1, 0x3B),
            (KeyCode::F10, 0x44),
            (KeyCode::NumLock, 0x45),
            (KeyCode::ScrollLock, 0x46),
            (KeyCode::F11, 0x57),
            (KeyCode::F12, 0x58),
        ];
        // Act + Assert
        assert_codes(&expected, false);
    }

    #[test]
    fn numpad_keys_use_expected_set1_codes() {
        // Arrange
        let expected = [
            (KeyCode::NumpadMultiply, 0x37),
            (KeyCode::Numpad7, 0x47),
            (KeyCode::NumpadSubtract, 0x4A),
            (KeyCode::NumpadAdd, 0x4E),
            (KeyCode::Numpad0, 0x52),
            (KeyCode::NumpadDecimal, 0x53),
        ];
        // Act + Assert
        assert_codes(&expected, false);
    }

    #[test]
    fn extended_keys_use_e0_prefixed_set1_codes() {
        // Arrange
        let expected = [
            (KeyCode::NumpadEnter, 0x1C),
            (KeyCode::ControlRight, 0x1D),
            (KeyCode::NumpadDivide, 0x35),
            (KeyCode::PrintScreen, 0x37),
            (KeyCode::AltRight, 0x38),
            (KeyCode::Home, 0x47),
            (KeyCode::ArrowUp, 0x48),
            (KeyCode::PageUp, 0x49),
            (KeyCode::ArrowLeft, 0x4B),
            (KeyCode::ArrowRight, 0x4D),
            (KeyCode::End, 0x4F),
            (KeyCode::ArrowDown, 0x50),
            (KeyCode::PageDown, 0x51),
            (KeyCode::Insert, 0x52),
            (KeyCode::Delete, 0x53),
            (KeyCode::SuperLeft, 0x5B),
            (KeyCode::SuperRight, 0x5C),
            (KeyCode::ContextMenu, 0x5D),
        ];
        // Act + Assert
        assert_codes(&expected, true);
    }

    #[test]
    fn only_the_e0_prefixed_keys_are_flagged_extended() {
        // Arrange
        let extended: HashSet<KeyCode> = EXTENDED_KEYS.into_iter().collect();
        for &key in KeyCode::ALL {
            // Act
            let is_extended = key.scancode().extended;
            // Assert
            assert_eq!(is_extended, extended.contains(&key), "{key:?}");
        }
    }

    #[test]
    fn all_keys_table_lists_every_key_exactly_once() {
        // Arrange
        let unique: HashSet<KeyCode> = KeyCode::ALL.iter().copied().collect();
        // Assert: 26 letters + 10 digits + 12 F + 21 main + 2 locks + 14 numpad + 18 extended
        assert_eq!(KeyCode::ALL.len(), 103);
        assert_eq!(unique.len(), KeyCode::ALL.len());
    }

    #[test]
    fn non_extended_make_codes_are_unique() {
        // Arrange
        let codes: Vec<u8> = KeyCode::ALL
            .iter()
            .map(|k| k.scancode())
            .filter(|sc| !sc.extended)
            .map(|sc| sc.code)
            .collect();
        // Act
        let unique: HashSet<u8> = codes.iter().copied().collect();
        // Assert
        assert_eq!(unique.len(), codes.len());
        assert_eq!(codes.len(), 85);
    }

    #[test]
    fn extended_make_codes_are_unique() {
        // Arrange
        let codes: Vec<u8> = KeyCode::ALL
            .iter()
            .map(|k| k.scancode())
            .filter(|sc| sc.extended)
            .map(|sc| sc.code)
            .collect();
        // Act
        let unique: HashSet<u8> = codes.iter().copied().collect();
        // Assert
        assert_eq!(unique.len(), codes.len());
        assert_eq!(codes.len(), EXTENDED_KEYS.len());
    }

    #[test]
    fn is_modifier_is_true_for_exactly_the_eight_modifier_keys() {
        // Arrange
        let modifiers: HashSet<KeyCode> = MODIFIER_KEYS.into_iter().collect();
        // Act
        let flagged: Vec<KeyCode> = KeyCode::ALL
            .iter()
            .copied()
            .filter(|k| k.is_modifier())
            .collect();
        // Assert
        assert_eq!(flagged.len(), 8);
        for key in flagged {
            assert!(modifiers.contains(&key), "{key:?} is not a modifier");
        }
    }

    #[test]
    fn key_event_sets_release_flag_only_on_release() {
        // Arrange
        let key = KeyCode::A;
        // Act
        let press = key_event(key, true);
        let release = key_event(key, false);
        // Assert
        assert_eq!(press.flags & KBDFLAGS_RELEASE, 0);
        assert_eq!(release.flags & KBDFLAGS_RELEASE, KBDFLAGS_RELEASE);
        assert!(!press.is_release());
        assert!(release.is_release());
        assert_eq!(press.code, 0x1E);
        assert_eq!(release.code, 0x1E);
    }

    #[test]
    fn key_event_sets_extended_flag_exactly_for_extended_keys() {
        for &key in KeyCode::ALL {
            // Arrange
            let expected = key.scancode().extended;
            // Act
            let press = key_event(key, true);
            let release = key_event(key, false);
            // Assert
            assert_eq!(press.is_extended(), expected, "{key:?} press");
            assert_eq!(release.is_extended(), expected, "{key:?} release");
            assert_eq!(
                press.flags & !(KBDFLAGS_RELEASE | KBDFLAGS_EXTENDED),
                0,
                "{key:?}"
            );
        }
    }

    #[test]
    fn key_event_encodes_extended_press_to_exact_bytes() {
        // Arrange
        let press = key_event(KeyCode::Delete, true);
        let release = key_event(KeyCode::Delete, false);
        // Act
        let press_bytes = press.encode();
        let release_bytes = release.encode();
        // Assert: eventCode SCANCODE (0) << 5 | flags, then the make code
        assert_eq!(press_bytes, vec![KBDFLAGS_EXTENDED, 0x53]);
        assert_eq!(
            release_bytes,
            vec![KBDFLAGS_RELEASE | KBDFLAGS_EXTENDED, 0x53]
        );
        assert_eq!(press_bytes, scancode_event(0x53, true, true));
    }

    #[test]
    fn secure_attention_sequence_presses_ctrl_alt_del_then_releases_in_reverse() {
        // Act
        let seq = secure_attention_sequence();
        // Assert
        let expected = vec![
            key_event(KeyCode::ControlLeft, true),
            key_event(KeyCode::AltLeft, true),
            key_event(KeyCode::Delete, true),
            key_event(KeyCode::Delete, false),
            key_event(KeyCode::AltLeft, false),
            key_event(KeyCode::ControlLeft, false),
        ];
        assert_eq!(seq.len(), 6);
        assert_eq!(seq, expected);
    }
}
