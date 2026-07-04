//! caseforge-fleet — DFIR investigation multiplexer (clean-room, herdr-inspired).
//! Interactive at a TTY; static status scan when piped (keeps CI/tests headless).

mod fleet;
mod launch;
mod session;
mod status;
mod ui;


use fleet::{FleetState, Key};
use std::io::{self, IsTerminal, Stdout};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyModifiers};
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
        KeyCode::Char('q') | KeyCode::Esc => Key::Back,
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
            if event::poll(Duration::from_millis(1000))? {
                if let Event::Key(k) = event::read()? {
                    if st.input.is_some() {
                        match k.code {
                            KeyCode::Char(c) => st.input_push(c),
                            KeyCode::Backspace => st.input_backspace(),
                            KeyCode::Esc => st.cancel_input(),
                            KeyCode::Enter => {
                                if let Some(ev) = st.take_input() {
                                    let workdir = std::env::var("FLEET_WORKDIR")
                                        .map(PathBuf::from)
                                        .unwrap_or_else(|_| std::env::temp_dir().join("caseforge-fleet"));
                                    let cmd = std::env::var("CASEFORGE_CMD")
                                        .unwrap_or_else(|_| "caseforge".to_string());
                                    let _ = st.launch_investigation(&ev, &workdir, &cmd);
                                }
                            }
                            _ => {}
                        }
                    } else if k.modifiers.contains(KeyModifiers::CONTROL)
                        && matches!(k.code, KeyCode::Char('c'))
                    {
                        st.quit = true;
                    } else if matches!(k.code, KeyCode::Char('n')) {
                        st.begin_input();
                    } else {
                        st.on_key(map_key(k.code));
                        if st.pending_open {
                            st.pending_open = false;
                            if let Some(dir) = st.selected().map(|s| s.dir.clone()) {
                                open_viewer(&mut term, &dir)?;
                            }
                        }
                    }
                    if st.quit {
                        break;
                    }
                }
            } else {
                // tick: re-derive live status (working -> done transitions show up)
                st.refresh(now_secs());
            }
        }
        Ok(())
    })();
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen, cursor::Show)?;
    res
}

fn open_viewer(term: &mut Terminal<CrosstermBackend<Stdout>>, dir: &Path) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen, cursor::Show)?;
    let cmd = std::env::var("CASEFORGE_CMD").unwrap_or_else(|_| "caseforge".to_string());
    let (prog, args) = launch::viewer_command(&cmd, dir);
    let _ = std::process::Command::new(prog).args(args).status();
    enable_raw_mode()?;
    execute!(term.backend_mut(), EnterAlternateScreen, cursor::Hide)?;
    term.clear()?;
    Ok(())
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
