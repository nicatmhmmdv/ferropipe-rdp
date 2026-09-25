//! egui → [`KeyCode`] bridge (Cargo feature `egui`).
//!
//! egui 0.36 reports keyboard input three ways, and an RDP client has to
//! reconcile them into *one* stream of scan codes:
//!
//! - `Event::Key { key, physical_key, .. }` — a key press/release.
//!   `physical_key` is the position on the keyboard (what RDP wants); `key` is
//!   the logical key after the OS keymap. Since egui 0.36 the modifier keys
//!   themselves also arrive here (`Key::ShiftLeft`, `Key::AltRight`, …) on
//!   native targets.
//! - `Modifiers` (on every event, and via `Event::ModifiersChanged`) — the
//!   collapsed "some Shift/Ctrl/Alt is down" state. It is the only modifier
//!   signal on the web, and the only one when the window gains focus with a
//!   modifier already held.
//! - `Event::Text` — the characters the platform composed from the key press.
//!
//! [`key_code`], [`key_events`] and [`modifier_transitions`] are the pure
//! translations. [`KeyboardBridge`] is the small state machine that applies
//! them so a modifier reaches the server exactly once whichever signal carried
//! it, and that tells the app which `Text` events are redundant.

use super::{key_event, KeyCode, KeyEvent};
use egui::{Key, Modifiers};

/// The [`KeyCode`] at the US-QWERTY position of an egui key.
///
/// `None` for keys that are commands rather than positions (`Copy`, `Cut`,
/// `Paste`, `BrowserBack`), for function keys beyond F12, and for the ISO
/// `IntlBackslash` key (scan code 0x56, which [`KeyCode`] does not carry).
///
/// Shifted punctuation that egui reports as a key of its own (`Colon`, `Plus`,
/// `Pipe`, `Questionmark`, `Exclamationmark`, the curly brackets) maps to the
/// unshifted key at the same position; the server applies Shift itself.
/// `Num0`–`Num9` map to the main digit row because egui does not distinguish
/// the numpad.
///
/// One exhaustive `match` (no wildcard) so a new egui key is a compile error.
pub fn key_code(key: Key) -> Option<KeyCode> {
    use KeyCode as K;
    Some(match key {
        // Commands, not positions.
        Key::Copy | Key::Cut | Key::Paste | Key::BrowserBack => return None,
        // Navigation and editing.
        Key::ArrowDown => K::ArrowDown,
        Key::ArrowLeft => K::ArrowLeft,
        Key::ArrowRight => K::ArrowRight,
        Key::ArrowUp => K::ArrowUp,
        Key::Escape => K::Escape,
        Key::Tab => K::Tab,
        Key::Backspace => K::Backspace,
        Key::Enter => K::Enter,
        Key::Space => K::Space,
        Key::Insert => K::Insert,
        Key::Delete => K::Delete,
        Key::Home => K::Home,
        Key::End => K::End,
        Key::PageUp => K::PageUp,
        Key::PageDown => K::PageDown,
        // Punctuation by US-QWERTY position; shifted variants share the key.
        Key::Backtick => K::Backquote,
        Key::Minus => K::Minus,
        Key::Plus | Key::Equals => K::Equal,
        Key::OpenBracket | Key::OpenCurlyBracket => K::BracketLeft,
        Key::CloseBracket | Key::CloseCurlyBracket => K::BracketRight,
        Key::Backslash | Key::Pipe => K::Backslash,
        Key::Semicolon | Key::Colon => K::Semicolon,
        Key::Quote => K::Quote,
        Key::Comma => K::Comma,
        Key::Period => K::Period,
        Key::Slash | Key::Questionmark => K::Slash,
        Key::Exclamationmark => K::Digit1,
        // Digits: main row (egui has no numpad variants).
        Key::Num0 => K::Digit0,
        Key::Num1 => K::Digit1,
        Key::Num2 => K::Digit2,
        Key::Num3 => K::Digit3,
        Key::Num4 => K::Digit4,
        Key::Num5 => K::Digit5,
        Key::Num6 => K::Digit6,
        Key::Num7 => K::Digit7,
        Key::Num8 => K::Digit8,
        Key::Num9 => K::Digit9,
        // Letters.
        Key::A => K::A,
        Key::B => K::B,
        Key::C => K::C,
        Key::D => K::D,
        Key::E => K::E,
        Key::F => K::F,
        Key::G => K::G,
        Key::H => K::H,
        Key::I => K::I,
        Key::J => K::J,
        Key::K => K::K,
        Key::L => K::L,
        Key::M => K::M,
        Key::N => K::N,
        Key::O => K::O,
        Key::P => K::P,
        Key::Q => K::Q,
        Key::R => K::R,
        Key::S => K::S,
        Key::T => K::T,
        Key::U => K::U,
        Key::V => K::V,
        Key::W => K::W,
        Key::X => K::X,
        Key::Y => K::Y,
        Key::Z => K::Z,
        // Function keys: `KeyCode` carries F1–F12 only.
        Key::F1 => K::F1,
        Key::F2 => K::F2,
        Key::F3 => K::F3,
        Key::F4 => K::F4,
        Key::F5 => K::F5,
        Key::F6 => K::F6,
        Key::F7 => K::F7,
        Key::F8 => K::F8,
        Key::F9 => K::F9,
        Key::F10 => K::F10,
        Key::F11 => K::F11,
        Key::F12 => K::F12,
        Key::F13
        | Key::F14
        | Key::F15
        | Key::F16
        | Key::F17
        | Key::F18
        | Key::F19
        | Key::F20
        | Key::F21
        | Key::F22
        | Key::F23
        | Key::F24
        | Key::F25
        | Key::F26
        | Key::F27
        | Key::F28
        | Key::F29
        | Key::F30
        | Key::F31
        | Key::F32
        | Key::F33
        | Key::F34
        | Key::F35 => return None,
        // Modifier keys, both sides.
        Key::ShiftLeft => K::ShiftLeft,
        Key::ShiftRight => K::ShiftRight,
        Key::ControlLeft => K::ControlLeft,
        Key::ControlRight => K::ControlRight,
        Key::AltLeft => K::AltLeft,
        Key::AltRight => K::AltRight,
        Key::SuperLeft => K::SuperLeft,
        Key::SuperRight => K::SuperRight,
        // ISO 102nd key (0x56): not in `KeyCode`, see the `keymap` module docs.
        Key::IntlBackslash => return None,
    })
}

/// The wire event for an egui `Event::Key`, or nothing if the key has no position.
///
/// `physical` (egui's `physical_key`) wins over the logical `key`: RDP carries
/// positions and the server applies its own layout, so mapping the logical key
/// would type the wrong character on any non-US layout. The logical key is used
/// only when the integration cannot report the physical one (the web). An
/// unmapped physical key is *not* rescued by the logical key, since the logical
/// key's US position would be a different key; the app should let the
/// `Event::Text` through instead (see [`KeyboardBridge::text_wanted`]).
///
/// A key `repeat` is forwarded as one more press, i.e. a typematic make code.
/// The host has no keyboard of its own to repeat with — an RDP server only
/// repeats what the client sends — so dropping repeats would stop held keys
/// from repeating at all, while a make code for a key already down is harmless.
pub fn key_events(key: Key, physical: Option<Key>, pressed: bool, _repeat: bool) -> Vec<KeyEvent> {
    key_code(physical.unwrap_or(key))
        .map(|code| key_event(code, pressed))
        .into_iter()
        .collect()
}

/// Press/release events for the Shift/Ctrl/Alt changes between two modifier states.
///
/// The left-hand key stands for each modifier, since `Modifiers` collapses both
/// sides. Ctrl counts as held when `ctrl` is set, or when `command` is set
/// without `mac_cmd`: egui defines `command == ctrl` on Windows/Linux, while on
/// macOS `command` mirrors `mac_cmd` (the ⌘ key), which is not a Ctrl and is
/// left alone here — native macOS also delivers ⌘ as a physical
/// `Key::SuperLeft`/`SuperRight` event, which [`key_events`] forwards as the
/// Windows key. Presses come before releases so a chord never momentarily has
/// no modifier down.
pub fn modifier_transitions(prev: Modifiers, next: Modifiers) -> Vec<KeyEvent> {
    let changes: Vec<(KeyCode, bool)> = MODIFIER_SIDES
        .iter()
        .filter(|(held, _)| held(prev) != held(next))
        .map(|&(held, key)| (key, held(next)))
        .collect();
    let presses = changes.iter().filter(|&&(_, pressed)| pressed);
    let releases = changes.iter().filter(|&&(_, pressed)| !pressed);
    presses
        .chain(releases)
        .map(|&(key, pressed)| key_event(key, pressed))
        .collect()
}

/// A collapsed modifier: how to read it off `Modifiers`, and the key that stands for it.
type ModifierSide = (fn(Modifiers) -> bool, KeyCode);

const MODIFIER_SIDES: [ModifierSide; 3] = [
    (is_shift_held, KeyCode::ShiftLeft),
    (is_ctrl_held, KeyCode::ControlLeft),
    (is_alt_held, KeyCode::AltLeft),
];

fn is_shift_held(modifiers: Modifiers) -> bool {
    modifiers.shift
}

fn is_ctrl_held(modifiers: Modifiers) -> bool {
    modifiers.ctrl || (modifiers.command && !modifiers.mac_cmd)
}

fn is_alt_held(modifiers: Modifiers) -> bool {
    modifiers.alt
}

/// The physical modifier keys [`KeyboardBridge`] tracks, one bit each.
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
const SHIFT_BITS: u8 = 0b0000_0011;
const CTRL_BITS: u8 = 0b0000_1100;
const ALT_BITS: u8 = 0b0011_0000;

fn modifier_bit(code: KeyCode) -> Option<u8> {
    MODIFIER_KEYS
        .iter()
        .position(|&key| key == code)
        .map(|index| 1 << index)
}

/// Turns egui keyboard events into scan code events while tracking which
/// modifier keys the server currently has down.
///
/// Two signals can carry a modifier, and the bridge makes sure each reaches
/// the server once:
///
/// - A *physical* modifier `Event::Key` (`Key::ShiftLeft`, `Key::AltRight`, …)
///   is forwarded as-is and remembered per side. This is what keeps AltGr
///   working on non-US layouts: egui never reports AltGr in `Modifiers`.
/// - A modifier egui reports held in `Modifiers` with no physical key backing
///   it is *synthesized* (left-hand key) and released once egui drops it. On
///   native, egui-winit sends `ModifiersChanged` just before the physical key
///   event, so a physical left key silently takes over the scan code the
///   synthesized press already put down instead of doubling it.
///
/// Feed every keyboard event in order: [`key`](Self::key) for `Event::Key`,
/// [`modifiers_changed`](Self::modifiers_changed) for
/// `Event::ModifiersChanged`, [`text_wanted`](Self::text_wanted) for
/// `Event::Text`, and [`release_all`](Self::release_all) when the window loses
/// focus so nothing stays stuck down on the server.
#[derive(Clone, Debug, Default)]
pub struct KeyboardBridge {
    /// Physical modifier keys currently down, one bit per `MODIFIER_KEYS` entry.
    physical: u8,
    /// Modifiers pressed on `Modifiers`' say-so alone (left-hand keys).
    synthetic: Modifiers,
    /// Whether the latest key press reached the server as a scan code, so the
    /// `Event::Text` it produced must not be sent again as Unicode.
    last_press_mapped: bool,
}

impl KeyboardBridge {
    pub fn new() -> Self {
        Self::default()
    }

    /// Events for an `Event::Key`: synthesized modifier changes first, then the
    /// key itself (nothing for an unmapped key).
    pub fn key(
        &mut self,
        key: Key,
        physical: Option<Key>,
        pressed: bool,
        repeat: bool,
        modifiers: Modifiers,
    ) -> Vec<KeyEvent> {
        let code = key_code(physical.unwrap_or(key));
        if let Some((code, bit)) = code.and_then(|code| Some((code, modifier_bit(code)?))) {
            return self.physical_modifier(code, bit, pressed);
        }
        let mut events = self.reconcile(modifiers);
        let key = key_events(key, physical, pressed, repeat);
        if pressed {
            self.last_press_mapped = !key.is_empty();
        }
        events.extend(key);
        events
    }

    /// Events for an `Event::ModifiersChanged`.
    pub fn modifiers_changed(&mut self, modifiers: Modifiers) -> Vec<KeyEvent> {
        self.reconcile(modifiers)
    }

    /// Whether an `Event::Text` must be sent as a Unicode event. Call once per
    /// text event, in order. The answer is `false` when the latest key press
    /// already carried the text as a scan code, or while Ctrl/Alt is held (text
    /// under those is a shortcut side effect, not typing).
    pub fn text_wanted(&mut self, modifiers: Modifiers) -> bool {
        let redundant = std::mem::replace(&mut self.last_press_mapped, false);
        !redundant && !(modifiers.ctrl || modifiers.alt)
    }

    /// Release every modifier the server has down — physical keys first, then
    /// synthesized ones — and forget them. For when the window loses focus.
    pub fn release_all(&mut self) -> Vec<KeyEvent> {
        let physical = MODIFIER_KEYS
            .iter()
            .enumerate()
            .filter(|&(index, _)| self.physical & (1 << index) != 0)
            .map(|(_, &key)| key_event(key, false));
        let synthetic = modifier_transitions(self.synthetic, Modifiers::NONE);
        let events = physical.chain(synthetic).collect();
        *self = Self::default();
        events
    }

    /// Synthesize or release modifiers so the server matches `modifiers`,
    /// ignoring those a physical key already accounts for.
    fn reconcile(&mut self, modifiers: Modifiers) -> Vec<KeyEvent> {
        let wanted = self.unbacked(modifiers);
        let events = modifier_transitions(self.synthetic, wanted);
        self.synthetic = wanted;
        events
    }

    /// The modifiers egui reports held that no physical key is backing.
    fn unbacked(&self, modifiers: Modifiers) -> Modifiers {
        let backed = |bits: u8| self.physical & bits != 0;
        Modifiers {
            shift: is_shift_held(modifiers) && !backed(SHIFT_BITS),
            ctrl: is_ctrl_held(modifiers) && !backed(CTRL_BITS),
            alt: is_alt_held(modifiers) && !backed(ALT_BITS),
            mac_cmd: false,
            command: false,
        }
    }

    fn physical_modifier(&mut self, code: KeyCode, bit: u8, pressed: bool) -> Vec<KeyEvent> {
        if pressed {
            self.physical |= bit;
            self.last_press_mapped = true;
            if self.take_over_synthesized(code) {
                return Vec::new();
            }
        } else {
            self.physical &= !bit;
        }
        vec![key_event(code, pressed)]
    }

    /// If `code` is the left-hand key of a modifier that was synthesized, the
    /// physical key takes ownership of the scan code already down: nothing to send.
    fn take_over_synthesized(&mut self, code: KeyCode) -> bool {
        let flag = match code {
            KeyCode::ShiftLeft => &mut self.synthetic.shift,
            KeyCode::ControlLeft => &mut self.synthetic.ctrl,
            KeyCode::AltLeft => &mut self.synthetic.alt,
            _ => return false,
        };
        std::mem::replace(flag, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::KBDFLAGS_RELEASE;
    use std::collections::HashSet;

    /// egui keys with no PC/AT position in `KeyCode`: commands, F13+, and keys
    /// that only exist on non-US keyboards.
    const UNMAPPED: &[Key] = &[
        Key::Copy,
        Key::Cut,
        Key::Paste,
        Key::BrowserBack,
        Key::IntlBackslash,
        Key::F13,
        Key::F14,
        Key::F15,
        Key::F16,
        Key::F17,
        Key::F18,
        Key::F19,
        Key::F20,
        Key::F21,
        Key::F22,
        Key::F23,
        Key::F24,
        Key::F25,
        Key::F26,
        Key::F27,
        Key::F28,
        Key::F29,
        Key::F30,
        Key::F31,
        Key::F32,
        Key::F33,
        Key::F34,
        Key::F35,
    ];

    fn press(key: KeyCode) -> KeyEvent {
        key_event(key, true)
    }

    fn release(key: KeyCode) -> KeyEvent {
        key_event(key, false)
    }

    /// Modifiers the way a Windows/Linux integration reports them (`command == ctrl`).
    fn mods(shift: bool, ctrl: bool, alt: bool) -> Modifiers {
        Modifiers {
            shift,
            ctrl,
            alt,
            command: ctrl,
            mac_cmd: false,
        }
    }

    fn assert_maps(expected: &[(Key, KeyCode)]) {
        for &(key, code) in expected {
            // Act
            let mapped = key_code(key);
            // Assert
            assert_eq!(mapped, Some(code), "{key:?}");
        }
    }

    // ----- key_code -----

    #[test]
    fn every_egui_key_maps_or_is_explicitly_unmapped() {
        // Arrange
        let unmapped: HashSet<Key> = UNMAPPED.iter().copied().collect();
        for &key in Key::ALL {
            // Act
            let mapped = key_code(key);
            // Assert
            assert_eq!(
                mapped.is_none(),
                unmapped.contains(&key),
                "{key:?} -> {mapped:?}"
            );
        }
    }

    #[test]
    fn letters_map_to_the_same_named_key_codes() {
        // Arrange
        let expected = [
            (Key::A, KeyCode::A),
            (Key::B, KeyCode::B),
            (Key::C, KeyCode::C),
            (Key::D, KeyCode::D),
            (Key::E, KeyCode::E),
            (Key::F, KeyCode::F),
            (Key::G, KeyCode::G),
            (Key::H, KeyCode::H),
            (Key::I, KeyCode::I),
            (Key::J, KeyCode::J),
            (Key::K, KeyCode::K),
            (Key::L, KeyCode::L),
            (Key::M, KeyCode::M),
            (Key::N, KeyCode::N),
            (Key::O, KeyCode::O),
            (Key::P, KeyCode::P),
            (Key::Q, KeyCode::Q),
            (Key::R, KeyCode::R),
            (Key::S, KeyCode::S),
            (Key::T, KeyCode::T),
            (Key::U, KeyCode::U),
            (Key::V, KeyCode::V),
            (Key::W, KeyCode::W),
            (Key::X, KeyCode::X),
            (Key::Y, KeyCode::Y),
            (Key::Z, KeyCode::Z),
        ];
        // Act + Assert
        assert_maps(&expected);
    }

    #[test]
    fn digits_map_to_the_main_row_digit_keys() {
        // Arrange: egui does not distinguish the numpad, so Num* is the main row.
        let expected = [
            (Key::Num0, KeyCode::Digit0),
            (Key::Num1, KeyCode::Digit1),
            (Key::Num2, KeyCode::Digit2),
            (Key::Num3, KeyCode::Digit3),
            (Key::Num4, KeyCode::Digit4),
            (Key::Num5, KeyCode::Digit5),
            (Key::Num6, KeyCode::Digit6),
            (Key::Num7, KeyCode::Digit7),
            (Key::Num8, KeyCode::Digit8),
            (Key::Num9, KeyCode::Digit9),
        ];
        // Act + Assert
        assert_maps(&expected);
    }

    #[test]
    fn function_keys_map_to_f1_through_f12_only() {
        // Arrange
        let expected = [
            (Key::F1, KeyCode::F1),
            (Key::F2, KeyCode::F2),
            (Key::F3, KeyCode::F3),
            (Key::F4, KeyCode::F4),
            (Key::F5, KeyCode::F5),
            (Key::F6, KeyCode::F6),
            (Key::F7, KeyCode::F7),
            (Key::F8, KeyCode::F8),
            (Key::F9, KeyCode::F9),
            (Key::F10, KeyCode::F10),
            (Key::F11, KeyCode::F11),
            (Key::F12, KeyCode::F12),
        ];
        // Act + Assert
        assert_maps(&expected);
        assert_eq!(key_code(Key::F13), None);
        assert_eq!(key_code(Key::F35), None);
    }

    #[test]
    fn shifted_punctuation_maps_to_its_us_qwerty_physical_position() {
        // Arrange
        let expected = [
            (Key::Plus, KeyCode::Equal),
            (Key::Equals, KeyCode::Equal),
            (Key::Backtick, KeyCode::Backquote),
            (Key::Colon, KeyCode::Semicolon),
            (Key::Semicolon, KeyCode::Semicolon),
            (Key::Pipe, KeyCode::Backslash),
            (Key::Backslash, KeyCode::Backslash),
            (Key::Questionmark, KeyCode::Slash),
            (Key::Slash, KeyCode::Slash),
            (Key::Exclamationmark, KeyCode::Digit1),
            (Key::OpenBracket, KeyCode::BracketLeft),
            (Key::OpenCurlyBracket, KeyCode::BracketLeft),
            (Key::CloseBracket, KeyCode::BracketRight),
            (Key::CloseCurlyBracket, KeyCode::BracketRight),
            (Key::Minus, KeyCode::Minus),
            (Key::Comma, KeyCode::Comma),
            (Key::Period, KeyCode::Period),
            (Key::Quote, KeyCode::Quote),
        ];
        // Act + Assert
        assert_maps(&expected);
    }

    #[test]
    fn editing_and_navigation_keys_map_to_the_same_named_key_codes() {
        // Arrange
        let expected = [
            (Key::ArrowDown, KeyCode::ArrowDown),
            (Key::ArrowLeft, KeyCode::ArrowLeft),
            (Key::ArrowRight, KeyCode::ArrowRight),
            (Key::ArrowUp, KeyCode::ArrowUp),
            (Key::Escape, KeyCode::Escape),
            (Key::Tab, KeyCode::Tab),
            (Key::Backspace, KeyCode::Backspace),
            (Key::Enter, KeyCode::Enter),
            (Key::Space, KeyCode::Space),
            (Key::Insert, KeyCode::Insert),
            (Key::Delete, KeyCode::Delete),
            (Key::Home, KeyCode::Home),
            (Key::End, KeyCode::End),
            (Key::PageUp, KeyCode::PageUp),
            (Key::PageDown, KeyCode::PageDown),
        ];
        // Act + Assert
        assert_maps(&expected);
    }

    #[test]
    fn physical_modifier_keys_map_to_both_sides() {
        // Arrange
        let expected = [
            (Key::ShiftLeft, KeyCode::ShiftLeft),
            (Key::ShiftRight, KeyCode::ShiftRight),
            (Key::ControlLeft, KeyCode::ControlLeft),
            (Key::ControlRight, KeyCode::ControlRight),
            (Key::AltLeft, KeyCode::AltLeft),
            (Key::AltRight, KeyCode::AltRight),
            (Key::SuperLeft, KeyCode::SuperLeft),
            (Key::SuperRight, KeyCode::SuperRight),
        ];
        // Act + Assert
        assert_maps(&expected);
    }

    // ----- modifier_transitions -----

    #[test]
    fn no_modifier_change_yields_no_events() {
        // Arrange
        let held = mods(true, true, false);
        // Act
        let events = modifier_transitions(held, held);
        // Assert
        assert!(events.is_empty());
        assert!(modifier_transitions(Modifiers::NONE, Modifiers::NONE).is_empty());
    }

    #[test]
    fn ctrl_newly_held_presses_control_left() {
        // Act
        let events = modifier_transitions(Modifiers::NONE, Modifiers::CTRL);
        // Assert
        assert_eq!(events, vec![press(KeyCode::ControlLeft)]);
    }

    #[test]
    fn shift_released_yields_a_single_release_event() {
        // Act
        let events = modifier_transitions(Modifiers::SHIFT, Modifiers::NONE);
        // Assert
        assert_eq!(events, vec![release(KeyCode::ShiftLeft)]);
        assert!(events[0].is_release());
        assert_eq!(events[0].flags & KBDFLAGS_RELEASE, KBDFLAGS_RELEASE);
    }

    #[test]
    fn multiple_changes_emit_presses_before_releases() {
        // Arrange: Shift+Alt held, then Ctrl alone.
        let prev = mods(true, false, true);
        let next = mods(false, true, false);
        // Act
        let events = modifier_transitions(prev, next);
        // Assert
        assert_eq!(
            events,
            vec![
                press(KeyCode::ControlLeft),
                release(KeyCode::ShiftLeft),
                release(KeyCode::AltLeft),
            ]
        );
    }

    #[test]
    fn command_without_mac_cmd_counts_as_ctrl() {
        // Act
        let events = modifier_transitions(Modifiers::NONE, Modifiers::COMMAND);
        // Assert
        assert_eq!(events, vec![press(KeyCode::ControlLeft)]);
    }

    #[test]
    fn mac_cmd_is_not_treated_as_ctrl() {
        // Arrange: the ⌘ key as a macOS integration reports it.
        let cmd = Modifiers::MAC_CMD.plus(Modifiers::COMMAND);
        // Act + Assert
        assert!(modifier_transitions(Modifiers::NONE, cmd).is_empty());
        assert!(modifier_transitions(cmd, Modifiers::NONE).is_empty());
    }

    // ----- key_events -----

    #[test]
    fn physical_key_takes_precedence_over_logical_key() {
        // Arrange: on AZERTY the key at the US "A" position types "q".
        // Act
        let events = key_events(Key::Q, Some(Key::A), true, false);
        // Assert
        assert_eq!(events, vec![press(KeyCode::A)]);
    }

    #[test]
    fn logical_key_is_used_when_physical_key_is_unknown() {
        // Act
        let events = key_events(Key::Q, None, true, false);
        // Assert
        assert_eq!(events, vec![press(KeyCode::Q)]);
    }

    #[test]
    fn unmapped_physical_key_is_not_rescued_by_the_logical_key() {
        // Arrange: the UK ISO key types "\" but sits at 0x56, which KeyCode cannot express;
        // sending the US Backslash position would type "#" on the server.
        // Act
        let events = key_events(Key::Backslash, Some(Key::IntlBackslash), true, false);
        // Assert
        assert!(events.is_empty());
    }

    #[test]
    fn unmapped_key_yields_no_events() {
        // Act + Assert
        assert!(key_events(Key::Copy, None, true, false).is_empty());
        assert!(key_events(Key::F13, Some(Key::F13), false, false).is_empty());
    }

    #[test]
    fn release_sets_the_release_flag() {
        // Act
        let events = key_events(Key::Delete, Some(Key::Delete), false, false);
        // Assert
        assert_eq!(events, vec![release(KeyCode::Delete)]);
        assert!(events[0].is_release());
        assert!(events[0].is_extended());
    }

    #[test]
    fn repeat_yields_a_single_press() {
        // Act
        let repeat = key_events(Key::A, Some(Key::A), true, true);
        // Assert
        assert_eq!(repeat, vec![press(KeyCode::A)]);
        assert_eq!(repeat, key_events(Key::A, Some(Key::A), true, false));
    }

    // ----- KeyboardBridge -----

    /// A native-style `Event::Key` where the physical key is known and equals the logical one.
    fn key(
        bridge: &mut KeyboardBridge,
        key: Key,
        pressed: bool,
        modifiers: Modifiers,
    ) -> Vec<KeyEvent> {
        bridge.key(key, Some(key), pressed, false, modifiers)
    }

    #[test]
    fn bridge_forwards_physical_modifier_keys_as_is() {
        // Arrange
        let mut bridge = KeyboardBridge::new();
        // Act + Assert
        assert_eq!(
            key(&mut bridge, Key::ShiftRight, true, Modifiers::SHIFT),
            vec![press(KeyCode::ShiftRight)]
        );
        assert_eq!(
            key(&mut bridge, Key::ShiftRight, false, Modifiers::NONE),
            vec![release(KeyCode::ShiftRight)]
        );
    }

    #[test]
    fn bridge_synthesizes_egui_modifiers_before_a_key_when_no_physical_key_backs_them() {
        // Arrange: a web-style integration reports Shift only through `Modifiers`.
        let mut bridge = KeyboardBridge::new();
        // Act
        let events = key(&mut bridge, Key::A, true, Modifiers::SHIFT);
        // Assert
        assert_eq!(events, vec![press(KeyCode::ShiftLeft), press(KeyCode::A)]);
    }

    #[test]
    fn bridge_releases_a_synthesized_modifier_when_egui_drops_it() {
        // Arrange
        let mut bridge = KeyboardBridge::new();
        key(&mut bridge, Key::A, true, Modifiers::SHIFT);
        key(&mut bridge, Key::A, false, Modifiers::SHIFT);
        // Act + Assert
        assert_eq!(
            bridge.modifiers_changed(Modifiers::NONE),
            vec![release(KeyCode::ShiftLeft)]
        );
        assert!(bridge.modifiers_changed(Modifiers::NONE).is_empty());
    }

    #[test]
    fn bridge_synthesizes_presses_on_modifiers_changed() {
        // Arrange
        let mut bridge = KeyboardBridge::new();
        // Act + Assert
        assert_eq!(
            bridge.modifiers_changed(Modifiers::CTRL),
            vec![press(KeyCode::ControlLeft)]
        );
        // A following key sees Ctrl already down and adds nothing.
        assert_eq!(
            key(&mut bridge, Key::C, true, Modifiers::CTRL),
            vec![press(KeyCode::C)]
        );
    }

    #[test]
    fn bridge_lets_a_physical_left_modifier_take_over_a_synthesized_one_silently() {
        // Arrange: egui-winit emits ModifiersChanged before the physical Shift key event.
        let mut bridge = KeyboardBridge::new();
        assert_eq!(
            bridge.modifiers_changed(Modifiers::SHIFT),
            vec![press(KeyCode::ShiftLeft)]
        );
        // Act + Assert: the physical key now owns the scancode the server already has down.
        assert!(key(&mut bridge, Key::ShiftLeft, true, Modifiers::SHIFT).is_empty());
        assert_eq!(
            key(&mut bridge, Key::A, true, Modifiers::SHIFT),
            vec![press(KeyCode::A)]
        );
        assert!(bridge.modifiers_changed(Modifiers::NONE).is_empty());
        assert_eq!(
            key(&mut bridge, Key::ShiftLeft, false, Modifiers::NONE),
            vec![release(KeyCode::ShiftLeft)]
        );
    }

    #[test]
    fn bridge_sends_a_physical_right_modifier_alongside_a_synthesized_left() {
        // Arrange
        let mut bridge = KeyboardBridge::new();
        bridge.modifiers_changed(Modifiers::SHIFT);
        // Act + Assert
        assert_eq!(
            key(&mut bridge, Key::ShiftRight, true, Modifiers::SHIFT),
            vec![press(KeyCode::ShiftRight)]
        );
        // The physical key now backs Shift, so the synthesized left is let go.
        assert_eq!(
            key(&mut bridge, Key::A, true, Modifiers::SHIFT),
            vec![release(KeyCode::ShiftLeft), press(KeyCode::A)]
        );
        assert_eq!(
            key(&mut bridge, Key::ShiftRight, false, Modifiers::NONE),
            vec![release(KeyCode::ShiftRight)]
        );
        assert!(bridge.modifiers_changed(Modifiers::NONE).is_empty());
    }

    #[test]
    fn bridge_does_not_synthesize_a_physically_held_modifier() {
        // Arrange
        let mut bridge = KeyboardBridge::new();
        // Act + Assert
        assert_eq!(
            key(&mut bridge, Key::ControlLeft, true, Modifiers::CTRL),
            vec![press(KeyCode::ControlLeft)]
        );
        assert!(bridge.modifiers_changed(Modifiers::CTRL).is_empty());
        assert_eq!(
            key(&mut bridge, Key::C, true, Modifiers::CTRL),
            vec![press(KeyCode::C)]
        );
        assert_eq!(
            key(&mut bridge, Key::ControlLeft, false, Modifiers::NONE),
            vec![release(KeyCode::ControlLeft)]
        );
    }

    #[test]
    fn bridge_forwards_alt_gr_even_though_egui_reports_no_alt() {
        // Arrange: Linux reports AltGr as a level-3 shift, never as `Modifiers::alt`.
        let mut bridge = KeyboardBridge::new();
        // Act + Assert
        assert_eq!(
            key(&mut bridge, Key::AltRight, true, Modifiers::NONE),
            vec![press(KeyCode::AltRight)]
        );
        assert_eq!(
            key(&mut bridge, Key::Q, true, Modifiers::NONE),
            vec![press(KeyCode::Q)]
        );
        assert_eq!(
            key(&mut bridge, Key::Q, false, Modifiers::NONE),
            vec![release(KeyCode::Q)]
        );
        assert_eq!(
            key(&mut bridge, Key::AltRight, false, Modifiers::NONE),
            vec![release(KeyCode::AltRight)]
        );
    }

    #[test]
    fn bridge_release_all_releases_physical_then_synthesized_modifiers() {
        // Arrange
        let mut bridge = KeyboardBridge::new();
        key(&mut bridge, Key::AltRight, true, Modifiers::NONE);
        bridge.modifiers_changed(Modifiers::SHIFT);
        // Act + Assert
        assert_eq!(
            bridge.release_all(),
            vec![release(KeyCode::AltRight), release(KeyCode::ShiftLeft)]
        );
        assert!(bridge.release_all().is_empty());
    }

    #[test]
    fn bridge_swallows_text_after_a_mapped_key_press() {
        // Arrange
        let mut bridge = KeyboardBridge::new();
        key(&mut bridge, Key::A, true, Modifiers::NONE);
        // Act + Assert: the "a" was already delivered as a scancode…
        assert!(!bridge.text_wanted(Modifiers::NONE));
        // …but the next text (say an IME commit) has no scancode behind it.
        assert!(bridge.text_wanted(Modifiers::NONE));
    }

    #[test]
    fn bridge_wants_text_after_an_unmapped_key_press() {
        // Arrange
        let mut bridge = KeyboardBridge::new();
        // Act
        let events = bridge.key(
            Key::Backslash,
            Some(Key::IntlBackslash),
            true,
            false,
            Modifiers::NONE,
        );
        // Assert
        assert!(events.is_empty());
        assert!(bridge.text_wanted(Modifiers::NONE));
    }

    #[test]
    fn bridge_suppresses_text_while_ctrl_or_alt_is_held() {
        // Arrange
        let mut bridge = KeyboardBridge::new();
        // Act + Assert
        bridge.key(
            Key::Backslash,
            Some(Key::IntlBackslash),
            true,
            false,
            Modifiers::ALT,
        );
        assert!(!bridge.text_wanted(Modifiers::ALT));
        bridge.key(
            Key::Backslash,
            Some(Key::IntlBackslash),
            true,
            false,
            Modifiers::CTRL,
        );
        assert!(!bridge.text_wanted(Modifiers::CTRL));
    }
}
