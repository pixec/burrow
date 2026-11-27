//! virtio-input: a keyboard and an absolute tablet.
//!
//! Each is a virtio device of its own. [`Input`] answers its configuration
//! space and holds the events the host sent until the guest posts buffers
//! for them on the event queue.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

/// The event queue, then the status queue.
pub const QUEUES: usize = 2;
/// `virtio_input_config`: select, subsel, size, five reserved bytes and a
/// 128-byte payload.
pub const CONFIG_SIZE: usize = 136;
/// One `virtio_input_event`: type, code and value.
pub const EVENT_SIZE: usize = 8;
/// The tablet's axes run from 0 to this on both axes, whatever the mode.
pub const TABLET_MAX: i32 = 0x7fff;
/// Events held for a guest that is not taking them. A batch that does not
/// fit is dropped whole.
pub const MAX_PENDING: usize = 1024;

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;
pub const EV_LED: u16 = 0x11;
/// The first evdev key code that is a button rather than a key.
pub const BTN_MISC: u16 = 0x100;
pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;
pub const REL_HWHEEL: u16 = 0x06;
pub const REL_WHEEL: u16 = 0x08;
pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;
/// The last key the keyboard reports, `KEY_MICMUTE`.
const KEY_LAST: u16 = 248;

const CFG_ID_NAME: u8 = 0x01;
const CFG_ID_DEVIDS: u8 = 0x03;
const CFG_EV_BITS: u8 = 0x11;
const CFG_ABS_INFO: u8 = 0x12;
const BUS_VIRTUAL: u16 = 0x06;
const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Keyboard,
    Tablet,
}

impl Kind {
    pub const ALL: [Kind; 2] = [Kind::Keyboard, Kind::Tablet];

    /// Which device an event from the host belongs to. Synchronisation
    /// events are the device's own to add.
    pub fn of(event: &InputEvent) -> Option<Kind> {
        match event.kind {
            EV_KEY if event.code > 0 && event.code <= KEY_LAST => Some(Kind::Keyboard),
            EV_KEY if [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE].contains(&event.code) => Some(Kind::Tablet),
            EV_REL if [REL_WHEEL, REL_HWHEEL].contains(&event.code) => Some(Kind::Tablet),
            EV_ABS if [ABS_X, ABS_Y].contains(&event.code) => Some(Kind::Tablet),
            _ => None,
        }
    }

    pub fn index(self) -> usize {
        self as usize
    }

    fn name(self) -> &'static [u8] {
        match self {
            Kind::Keyboard => b"Burrow Keyboard",
            Kind::Tablet => b"Burrow Tablet",
        }
    }

    /// The codes it reports for an event type, as an evdev bitmap.
    fn bits(self, event_type: u8) -> Vec<u8> {
        let codes: Vec<u16> = match (self, u16::from(event_type)) {
            (Kind::Keyboard, EV_KEY) => (1..=KEY_LAST).collect(),
            (Kind::Keyboard, EV_LED) => vec![0, 1, 2],
            (Kind::Tablet, EV_KEY) => vec![BTN_LEFT, BTN_RIGHT, BTN_MIDDLE],
            (Kind::Tablet, EV_REL) => vec![REL_HWHEEL, REL_WHEEL],
            (Kind::Tablet, EV_ABS) => vec![ABS_X, ABS_Y],
            _ => vec![],
        };
        let mut bitmap = vec![
            0u8;
            codes
                .iter()
                .max()
                .map_or(0, |max| usize::from(*max) / 8 + 1)
        ];
        for code in codes {
            bitmap[usize::from(code) / 8] |= 1 << (code % 8);
        }
        bitmap
    }
}

/// An evdev event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputEvent {
    pub kind: u16,
    pub code: u16,
    pub value: i32,
}

impl InputEvent {
    pub fn new(kind: u16, code: u16, value: i32) -> Self {
        Self { kind, code, value }
    }

    pub fn to_bytes(self) -> [u8; EVENT_SIZE] {
        let mut b = [0u8; EVENT_SIZE];
        b[0..2].copy_from_slice(&self.kind.to_le_bytes());
        b[2..4].copy_from_slice(&self.code.to_le_bytes());
        b[4..8].copy_from_slice(&self.value.to_le_bytes());
        b
    }
}

/// The configuration selector a snapshot carries. Pending events are not
/// kept: input queued at a pause is stale by the restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputState {
    version: u32,
    kind: Kind,
    select: u8,
    subsel: u8,
}

pub struct Input {
    kind: Kind,
    select: u8,
    subsel: u8,
    pending: VecDeque<InputEvent>,
}

impl Input {
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            select: 0,
            subsel: 0,
            pending: VecDeque::new(),
        }
    }

    pub fn restore(state: InputState) -> Result<Self, crate::gpu::StateError> {
        if state.version != STATE_VERSION {
            return Err(crate::gpu::StateError::Version(state.version));
        }
        Ok(Self {
            select: state.select,
            subsel: state.subsel,
            ..Self::new(state.kind)
        })
    }

    pub fn state(&self) -> InputState {
        InputState {
            version: STATE_VERSION,
            kind: self.kind,
            select: self.select,
            subsel: self.subsel,
        }
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn reset(&mut self) {
        *self = Self::new(self.kind);
    }

    fn payload(&self) -> Vec<u8> {
        match self.select {
            CFG_ID_NAME => self.kind.name().to_vec(),
            CFG_ID_DEVIDS => {
                let product: u16 = match self.kind {
                    Kind::Keyboard => 1,
                    Kind::Tablet => 3,
                };
                [BUS_VIRTUAL, 0x0627, product, 1]
                    .iter()
                    .flat_map(|w| w.to_le_bytes())
                    .collect()
            }
            CFG_EV_BITS => self.kind.bits(self.subsel),
            CFG_ABS_INFO
                if self.kind == Kind::Tablet
                    && [ABS_X, ABS_Y].contains(&u16::from(self.subsel)) =>
            {
                [0, TABLET_MAX, 0, 0, 0]
                    .iter()
                    .flat_map(|w: &i32| w.to_le_bytes())
                    .collect()
            }
            _ => Vec::new(),
        }
    }

    pub fn read_config(&self, offset: u64, data: &mut [u8]) {
        let payload = self.payload();
        let mut config = [0u8; CONFIG_SIZE];
        config[0] = self.select;
        config[1] = self.subsel;
        config[2] = payload.len() as u8;
        config[8..8 + payload.len()].copy_from_slice(&payload);
        let Ok(offset) = usize::try_from(offset) else {
            return;
        };
        if let Some(src) = config.get(offset..offset.saturating_add(data.len())) {
            data.copy_from_slice(src);
        }
    }

    /// Only `select` and `subsel` are writable.
    pub fn write_config(&mut self, offset: u64, data: &[u8]) {
        for (i, byte) in data.iter().enumerate() {
            match offset + i as u64 {
                0 => self.select = *byte,
                1 => self.subsel = *byte,
                _ => {}
            }
        }
    }

    /// Queues a batch of this device's events, closed by a synchronisation
    /// event. Returns false if it was dropped for want of room.
    pub fn push(&mut self, events: &[InputEvent]) -> bool {
        if events.is_empty() {
            return true;
        }
        if self.pending.len() + events.len() + 1 > MAX_PENDING {
            return false;
        }
        self.pending.extend(events);
        self.pending.push_back(InputEvent::new(EV_SYN, 0, 0));
        true
    }

    /// The next event for the guest, left queued until [`Self::pop`].
    pub fn peek(&self) -> Option<InputEvent> {
        self.pending.front().copied()
    }

    pub fn pop(&mut self) {
        self.pending.pop_front();
    }

    pub fn clear_pending(&mut self) {
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn select(input: &mut Input, select: u8, subsel: u8) -> Vec<u8> {
        input.write_config(0, &[select, subsel]);
        let mut config = [0u8; CONFIG_SIZE];
        input.read_config(0, &mut config);
        assert_eq!(&config[..2], &[select, subsel]);
        config[8..8 + usize::from(config[2])].to_vec()
    }

    fn has(bitmap: &[u8], code: u16) -> bool {
        bitmap
            .get(usize::from(code) / 8)
            .is_some_and(|b| b & (1 << (code % 8)) != 0)
    }

    #[test]
    fn the_keyboard_reports_keys_and_leds() {
        let mut kbd = Input::new(Kind::Keyboard);
        assert_eq!(select(&mut kbd, CFG_ID_NAME, 0), b"Burrow Keyboard");
        let keys = select(&mut kbd, CFG_EV_BITS, EV_KEY as u8);
        assert_eq!(keys.len(), 32);
        assert!(has(&keys, 30) && has(&keys, KEY_LAST) && !has(&keys, 0));
        assert_eq!(select(&mut kbd, CFG_EV_BITS, EV_LED as u8), vec![0b111]);
        assert!(select(&mut kbd, CFG_EV_BITS, EV_ABS as u8).is_empty());
        assert!(select(&mut kbd, CFG_ABS_INFO, 0).is_empty());
        assert_eq!(
            select(&mut kbd, CFG_ID_DEVIDS, 0),
            vec![6, 0, 0x27, 6, 1, 0, 1, 0]
        );
    }

    #[test]
    fn the_tablet_is_absolute_with_three_buttons_and_wheels() {
        let mut tablet = Input::new(Kind::Tablet);
        let abs = select(&mut tablet, CFG_EV_BITS, EV_ABS as u8);
        assert_eq!(abs, vec![0b11]);
        let buttons = select(&mut tablet, CFG_EV_BITS, EV_KEY as u8);
        assert!(has(&buttons, BTN_LEFT) && has(&buttons, BTN_MIDDLE) && !has(&buttons, 30));
        let rel = select(&mut tablet, CFG_EV_BITS, EV_REL as u8);
        assert!(has(&rel, REL_WHEEL) && has(&rel, REL_HWHEEL));
        let info = select(&mut tablet, CFG_ABS_INFO, ABS_Y as u8);
        assert_eq!(info.len(), 20);
        assert_eq!(
            i32::from_le_bytes(info[4..8].try_into().unwrap()),
            TABLET_MAX
        );
        assert!(select(&mut tablet, CFG_ABS_INFO, 5).is_empty());
        assert!(select(&mut tablet, 0x7f, 0).is_empty());
    }

    #[test]
    fn events_route_to_their_device() {
        assert_eq!(
            Kind::of(&InputEvent::new(EV_KEY, 30, 1)),
            Some(Kind::Keyboard)
        );
        assert_eq!(
            Kind::of(&InputEvent::new(EV_KEY, BTN_LEFT, 1)),
            Some(Kind::Tablet)
        );
        assert_eq!(
            Kind::of(&InputEvent::new(EV_ABS, ABS_X, 5)),
            Some(Kind::Tablet)
        );
        assert_eq!(
            Kind::of(&InputEvent::new(EV_REL, REL_WHEEL, -1)),
            Some(Kind::Tablet)
        );
        assert_eq!(Kind::of(&InputEvent::new(EV_SYN, 0, 0)), None);
        assert_eq!(Kind::of(&InputEvent::new(EV_KEY, 0, 1)), None);
        assert_eq!(Kind::of(&InputEvent::new(EV_KEY, 0x2ff, 1)), None);
        assert_eq!(Kind::of(&InputEvent::new(EV_LED, 0, 1)), None);
    }

    #[test]
    fn a_batch_is_closed_with_a_sync_and_dropped_whole_when_full() {
        let mut kbd = Input::new(Kind::Keyboard);
        assert!(kbd.push(&[
            InputEvent::new(EV_KEY, 30, 1),
            InputEvent::new(EV_KEY, 30, 0)
        ]));
        assert_eq!(kbd.peek(), Some(InputEvent::new(EV_KEY, 30, 1)));
        kbd.pop();
        kbd.pop();
        assert_eq!(kbd.peek().unwrap().to_bytes(), [0; 8]);
        kbd.pop();
        assert_eq!(kbd.peek(), None);
        let big = vec![InputEvent::new(EV_KEY, 30, 1); MAX_PENDING];
        assert!(!kbd.push(&big));
        assert_eq!(kbd.peek(), None);
        assert_eq!(
            InputEvent::new(EV_ABS, ABS_Y, 0x1234).to_bytes(),
            [3, 0, 1, 0, 0x34, 0x12, 0, 0]
        );
    }

    #[test]
    fn the_selector_survives_a_snapshot_and_events_do_not() {
        let mut tablet = Input::new(Kind::Tablet);
        tablet.write_config(0, &[CFG_EV_BITS, EV_ABS as u8]);
        tablet.push(&[InputEvent::new(EV_ABS, ABS_X, 1)]);
        let json = serde_json::to_string(&tablet.state()).unwrap();
        let restored = Input::restore(serde_json::from_str(&json).unwrap()).unwrap();
        assert_eq!(restored.state(), tablet.state());
        assert_eq!(restored.peek(), None);
        assert_eq!(restored.kind(), Kind::Tablet);
    }
}
