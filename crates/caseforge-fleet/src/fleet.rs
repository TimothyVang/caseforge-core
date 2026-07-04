//! Fleet model: a set of investigations + a cursor, with pure navigation.
//! No I/O in the reducer, so keyboard navigation is fully unit-testable.

use crate::status::{derive_status, Status};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Enter,
    Open,
    Quit,
    Other,
}

pub struct FleetState {
    pub entries: Vec<Status>,
    pub cursor: usize,
    pub quit: bool,
}

impl FleetState {
    pub fn scan(dirs: &[PathBuf], now_secs: u64) -> Self {
        let entries = dirs.iter().map(|d| derive_status(d, now_secs)).collect();
        FleetState { entries, cursor: 0, quit: false }
    }

    pub fn selected(&self) -> Option<&Status> {
        self.entries.get(self.cursor)
    }

    /// Pure navigation. Returns the same-shaped state (mutated in place).
    pub fn on_key(&mut self, key: Key) {
        if self.entries.is_empty() {
            if key == Key::Quit {
                self.quit = true;
            }
            return;
        }
        let last = self.entries.len() - 1;
        match key {
            Key::Up => self.cursor = self.cursor.saturating_sub(1),
            Key::Down => self.cursor = (self.cursor + 1).min(last),
            Key::Quit => self.quit = true,
            Key::Enter | Key::Open | Key::Other => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(n: usize) -> FleetState {
        FleetState {
            entries: (0..n)
                .map(|_| derive_status(&PathBuf::from("/nope"), 0))
                .collect(),
            cursor: 0,
            quit: false,
        }
    }

    #[test]
    fn cursor_moves_within_bounds() {
        let mut s = state(3);
        s.on_key(Key::Up); // clamp at 0
        assert_eq!(s.cursor, 0);
        s.on_key(Key::Down);
        assert_eq!(s.cursor, 1);
        s.on_key(Key::Down);
        s.on_key(Key::Down); // clamp at last
        assert_eq!(s.cursor, 2);
    }

    #[test]
    fn quit_sets_flag() {
        let mut s = state(2);
        assert!(!s.quit);
        s.on_key(Key::Quit);
        assert!(s.quit);
    }

    #[test]
    fn empty_fleet_only_quits() {
        let mut s = state(0);
        s.on_key(Key::Down);
        assert_eq!(s.cursor, 0);
        s.on_key(Key::Quit);
        assert!(s.quit);
    }
}
