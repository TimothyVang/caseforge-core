//! caseforge-fleet — DFIR investigation multiplexer (clean-room, herdr-inspired).
//! Interactive at a TTY; static status scan when piped (keeps CI/tests headless).

mod fleet;
mod status;
mod ui;

use fleet::{FleetState, Key};
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{self, Event, KeyCode};
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::crossterm::{cursor, execute};
use ratatui::Terminal;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn map_key(code: KeyCode) -> Key {
    match code {
        KeyCode::Up | KeyCode::Char('k') => Key::Up,
        KeyCode::Down | KeyCode::Char('j') => Key::Down,
        KeyCode::Enter => Key::Enter,
        KeyCode::Char('o') => Key::Open,
        KeyCode::Char('q') | KeyCode::Esc => Key::Quit,
        _ => Key::Other,
    }
}

fn run_interactive(mut st: FleetState) -> io::Result<()> {
    enable_raw_mode()?;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen, cursor::Hide)?;
    let mut term = Terminal::new(CrosstermBackend::new(out))?;
    let res = (|| -> io::Result<()> {
        loop {
            term.draw(|f| ui::render(f, &st))?;
            if let Event::Key(k) = event::read()? {
                st.on_key(map_key(k.code));
                if st.quit {
                    break;
                }
            }
        }
        Ok(())
    })();
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen, cursor::Show)?;
    res
}

fn print_static(st: &FleetState) {
    println!("FLEET \u{b7} caseforge  {} investigations", st.entries.len());
    for (i, s) in st.entries.iter().enumerate() {
        println!(
            "  {:>2} {:<8?} custody={:<15?} {}",
            i + 1,
            s.state,
            s.custody,
            s.dir.display()
        );
    }
}

fn main() -> io::Result<()> {
    let dirs: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    if dirs.is_empty() {
        eprintln!("usage: caseforge-fleet <run-dir> [run-dir ...]");
        std::process::exit(2);
    }
    let st = FleetState::scan(&dirs, now_secs());
    if io::stdout().is_terminal() {
        run_interactive(st)
    } else {
        print_static(&st);
        Ok(())
    }
}
