//! ratatui render for the fleet grid. Pure: (state) -> widgets. Snapshot-testable
//! via TestBackend so the render itself is verified, not just the model.

use crate::fleet::FleetState;
use crate::status::{Custody, RunState, Status};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

const LILAC: Color = Color::Rgb(184, 168, 255);
const SEAFOAM: Color = Color::Rgb(115, 217, 194);
const BUTTER: Color = Color::Rgb(255, 215, 106);
const COBALT: Color = Color::Rgb(120, 140, 255);
const CORAL: Color = Color::Rgb(255, 98, 87);

fn dot_color(state: RunState) -> Color {
    match state {
        RunState::Blocked => CORAL,
        RunState::Working => BUTTER,
        RunState::Done => COBALT,
        RunState::Idle => Color::DarkGray,
    }
}

fn state_label(state: RunState) -> &'static str {
    match state {
        RunState::Blocked => "blocked",
        RunState::Working => "working",
        RunState::Done => "done",
        RunState::Idle => "idle",
    }
}

fn custody_span(c: Custody) -> Span<'static> {
    let (txt, col) = match c {
        Custody::Complete => ("complete", SEAFOAM),
        Custody::CustodyInvalid => ("custody-invalid", CORAL),
        Custody::Incomplete => ("incomplete", BUTTER),
        Custody::Unknown => ("unknown", Color::DarkGray),
    };
    Span::styled(format!("{:<15}", txt), Style::default().fg(col))
}

fn dir_name(s: &Status) -> String {
    s.dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| s.dir.display().to_string())
}

fn row(i: usize, s: &Status, sel: bool) -> Line<'static> {
    let dim = Style::default().add_modifier(Modifier::DIM);
    let arrow = if sel {
        Span::styled("\u{25b6} ", Style::default().fg(LILAC))
    } else {
        Span::raw("  ")
    };
    let label_style = if sel {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Line::from(vec![
        arrow,
        Span::styled(format!("{:>2} ", i + 1), dim),
        Span::styled("\u{25cf} ", Style::default().fg(dot_color(s.state))),
        Span::styled(format!("{:<8}", state_label(s.state)), label_style),
        Span::raw(" "),
        custody_span(s.custody),
        Span::raw(" "),
        Span::styled(dir_name(s), dim),
    ])
}

pub fn render(f: &mut Frame, st: &FleetState) {
    let dim = Style::default().add_modifier(Modifier::DIM);
    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled(
                "FLEET \u{b7} caseforge",
                Style::default().fg(LILAC).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("   {} investigations", st.entries.len()),
                dim,
            ),
        ]),
        Line::from(""),
    ];
    if st.entries.is_empty() {
        lines.push(Line::from(Span::styled("  no investigations found", dim)));
    } else {
        for (i, s) in st.entries.iter().enumerate() {
            lines.push(row(i, s, i == st.cursor));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "\u{2191}\u{2193} move \u{b7} enter attach \u{b7} o open viewer \u{b7} q quit",
        dim,
    )));
    f.render_widget(Paragraph::new(lines), f.area());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::derive_status;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::{Path, PathBuf};

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/synthetic")
    }

    fn buffer_text(st: &FleetState) -> String {
        let mut term = Terminal::new(TestBackend::new(90, 12)).unwrap();
        term.draw(|f| render(f, st)).unwrap();
        let buf = term.backend().buffer().clone();
        let area = *buf.area();
        let mut out = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn renders_fleet_header_and_rows() {
        let dirs = vec![
            fixtures().join("sample-run"),
            fixtures().join("custody-invalid-run"),
        ];
        let st = FleetState::scan(&dirs, 4_000_000_000);
        let text = buffer_text(&st);
        assert!(text.contains("FLEET"), "header present");
        assert!(text.contains("sample-run"), "row 1 present");
        assert!(text.contains("custody-invalid"), "invalid custody shown");
        assert!(text.contains("done"), "state shown");
        assert!(text.contains("\u{25b6}"), "cursor arrow present");
    }

    #[test]
    fn empty_fleet_degrades() {
        let st = FleetState::scan(&[], 0);
        assert!(buffer_text(&st).contains("no investigations found"));
    }

    #[test]
    fn cursor_moves_highlight() {
        let dirs: Vec<_> = ["sample-run", "no-report-run", "custody-invalid-run"]
            .iter()
            .map(|d| fixtures().join(d))
            .collect();
        let mut st = FleetState::scan(&dirs, 4_000_000_000);
        st.cursor = 2;
        let _ = derive_status(&dirs[0], 0); // touch import
        let text = buffer_text(&st);
        // arrow should be on the 3rd data row -> the custody-invalid line
        let arrow_line = text.lines().find(|l| l.contains("\u{25b6}")).unwrap();
        assert!(arrow_line.contains("custody-invalid"));
    }
}
