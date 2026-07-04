//! Fleet model: a set of investigations + a cursor, with pure navigation.
//! No I/O in the reducer, so keyboard navigation is fully unit-testable.

use crate::session::Session;
use crate::status::{derive_status, Status};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Enter,
    Open,
    Back,
    Quit,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    List,
    Detail,
}

pub struct FleetState {
    pub entries: Vec<Status>,
    /// Live launched investigations, keyed by their run dir. Present => attach
    /// shows live PTY output instead of the on-disk audit tail.
    pub sessions: HashMap<PathBuf, Session>,
    pub cursor: usize,
    pub view: View,
    pub pending_open: bool,
    /// Some(buffer) => the launch input prompt is active.
    pub input: Option<String>,
    pub quit: bool,
}

impl FleetState {
    pub fn scan(dirs: &[PathBuf], now_secs: u64) -> Self {
        let entries = dirs.iter().map(|d| derive_status(d, now_secs)).collect();
        FleetState { entries, sessions: HashMap::new(), cursor: 0, view: View::List, pending_open: false, input: None, quit: false }
    }

    /// Re-derive every investigation's status (called on the live-refresh tick).
    pub fn refresh(&mut self, now_secs: u64) {
        for e in self.entries.iter_mut() {
            *e = derive_status(&e.dir, now_secs);
        }
    }

    /// Launch an investigation as a live PTY session tracked under `run_dir`.
    pub fn launch(&mut self, run_dir: PathBuf, program: &str, args: &[String]) -> anyhow::Result<()> {
        let sess = Session::spawn(program, args)?;
        if !self.entries.iter().any(|e| e.dir == run_dir) {
            self.entries.push(derive_status(&run_dir, 0));
        }
        self.sessions.insert(run_dir, sess);
        Ok(())
    }

    pub fn begin_input(&mut self) { self.input = Some(String::new()); }
    pub fn cancel_input(&mut self) { self.input = None; }
    pub fn input_push(&mut self, c: char) {
        if let Some(b) = self.input.as_mut() { b.push(c); }
    }
    pub fn input_backspace(&mut self) {
        if let Some(b) = self.input.as_mut() { b.pop(); }
    }
    /// Take + clear the input buffer (on Enter).
    pub fn take_input(&mut self) -> Option<String> {
        self.input.take().filter(|b| !b.trim().is_empty())
    }

    /// Launch `evidence` under `workdir` via `cmd investigate ... --run-dir`.
    pub fn launch_investigation(&mut self, evidence: &str, workdir: &Path, cmd: &str) -> anyhow::Result<()> {
        let base = Path::new(evidence).file_name().and_then(|s| s.to_str()).unwrap_or("case");
        let run_dir = workdir.join(format!("{base}-run"));
        std::fs::create_dir_all(&run_dir).ok();
        let args = crate::launch::investigate_launch_args(evidence, &run_dir, &[]);
        self.launch(run_dir, cmd, &args)
    }

    /// Live output tail for a launched investigation, if one is tracked.
    pub fn live_output(&self, dir: &Path, n: usize) -> Option<Vec<String>> {
        self.sessions.get(dir).map(|s| s.snapshot_tail(n))
    }

    /// A tracked-and-running session forces Working, else the on-disk state.
    pub fn effective_state(&self, s: &Status) -> crate::status::RunState {
        if self.sessions.contains_key(&s.dir) {
            crate::status::RunState::Working
        } else {
            s.state
        }
    }

    pub fn selected(&self) -> Option<&Status> {
        self.entries.get(self.cursor)
    }

    /// Pure navigation. Returns the same-shaped state (mutated in place).
    pub fn on_key(&mut self, key: Key) {
        if key == Key::Quit {
            self.quit = true;
            return;
        }
        if self.entries.is_empty() {
            if key == Key::Back {
                self.quit = true;
            }
            return;
        }
        let last = self.entries.len() - 1;
        match (self.view, key) {
            (View::List, Key::Up) => self.cursor = self.cursor.saturating_sub(1),
            (View::List, Key::Down) => self.cursor = (self.cursor + 1).min(last),
            (View::List, Key::Enter) => self.view = View::Detail,
            (View::List, Key::Back) => self.quit = true,
            (View::Detail, Key::Back) => self.view = View::List,
            (_, Key::Open) => self.pending_open = true,
            _ => {}
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
            sessions: std::collections::HashMap::new(),
            cursor: 0,
            view: View::List,
            pending_open: false,
            input: None,
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
    fn enter_opens_detail_back_returns() {
        let mut s = state(3);
        s.on_key(Key::Enter);
        assert_eq!(s.view, View::Detail);
        s.on_key(Key::Back);
        assert_eq!(s.view, View::List);
    }

    #[test]
    fn input_mode_edits_and_takes() {
        let mut s = state(1);
        assert!(s.input.is_none());
        s.begin_input();
        s.input_push('e'); s.input_push('v'); s.input_push('x');
        s.input_backspace();
        assert_eq!(s.input.as_deref(), Some("ev"));
        assert_eq!(s.take_input().as_deref(), Some("ev"));
        assert!(s.input.is_none());
    }

    #[test]
    fn blank_input_is_discarded() {
        let mut s = state(1);
        s.begin_input();
        assert_eq!(s.take_input(), None);
    }

    #[test]
    fn open_sets_pending() {
        let mut s = state(2);
        s.on_key(Key::Open);
        assert!(s.pending_open);
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
