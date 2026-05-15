//! UI drawing module — renders the 4-panel TUI layout.
//! All rendering is pure: reads from AppState, draws to Frame.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::app::{AppState, Mode};

// ── Color Palette ──
const BG: Color = Color::Rgb(15, 15, 25);
const BORDER: Color = Color::Rgb(50, 50, 80);
const BORDER_FLASH: Color = Color::Rgb(255, 200, 0);
const TITLE: Color = Color::Rgb(120, 180, 255);
const COMPLETED: Color = Color::Rgb(0, 255, 136);
const HIGHLIGHT: Color = Color::Rgb(255, 200, 0);
const DARK: Color = Color::Rgb(50, 50, 70);
const COORD: Color = Color::Rgb(0, 230, 255);
const ZERO_RUN: Color = Color::Rgb(90, 90, 110);
const STATUS_VAL: Color = Color::Rgb(0, 200, 255);
const LABEL: Color = Color::Rgb(100, 100, 140);
const SEPARATOR: Color = Color::Rgb(60, 60, 90);

/// Main draw entry point — called every frame from the main loop.
pub fn draw_ui(frame: &mut Frame, state: &AppState) {
    let area = frame.area();

    // Fill background
    let bg_block = Block::default().style(Style::default().bg(BG));
    frame.render_widget(bg_block, area);

    // ── Main vertical split: Top(3) | Middle(fill) | Bottom(3) ──
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Fill(1),
            Constraint::Length(3),
        ])
        .split(area);

    // ── Middle horizontal split: Left(30%) | Right(70%) ──
    let middle_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(main_chunks[1]);

    draw_source(frame, state, main_chunks[0]);
    draw_hierarchy(frame, state, middle_chunks[0]);
    draw_scanner(frame, state, middle_chunks[1]);
    draw_status(frame, state, main_chunks[2]);
}

// ─────────────────────────────────────────────────────────────
//  Top Panel: Source Data Progress
// ─────────────────────────────────────────────────────────────
fn draw_source(frame: &mut Frame, state: &AppState, area: Rect) {
    let pct = if state.total_chunks > 0 {
        state.completed_chunks as f64 / state.total_chunks as f64 * 100.0
    } else {
        0.0
    };

    let mode_label = match &state.mode {
        Mode::Encrypt { .. } => "Encrypt",
        Mode::Decrypt { .. } => "Decrypt",
    };
    let title = format!(
        " \u{1F4E6} {} [{}/{}] {:.0}% ",
        mode_label, state.completed_chunks, state.total_chunks, pct
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .title(Span::styled(title, Style::default().fg(TITLE).add_modifier(Modifier::BOLD)))
        .style(Style::default().bg(BG));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    // Build styled hex representation of each chunk
    let mut spans: Vec<Span> = Vec::with_capacity(state.total_chunks * 2);
    for i in 0..state.total_chunks {
        let start = i * state.chunk_size;
        let end = ((i + 1) * state.chunk_size).min(state.source_data.len());
        let hex: String = state.source_data[start..end]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        let style = if i < state.completed_chunks {
            Style::default().fg(COMPLETED)
        } else if i == state.current_chunk {
            // Pulsing effect
            if state.tick % 12 < 6 {
                Style::default()
                    .fg(Color::Rgb(20, 20, 30))
                    .bg(HIGHLIGHT)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(HIGHLIGHT)
                    .add_modifier(Modifier::BOLD)
            }
        } else {
            Style::default().fg(DARK)
        };

        spans.push(Span::styled(hex, style));
        if i < state.total_chunks - 1 {
            spans.push(Span::styled(" ", Style::default().fg(DARK)));
        }
    }

    let paragraph = Paragraph::new(Line::from(spans));
    frame.render_widget(paragraph, inner);
}

// ─────────────────────────────────────────────────────────────
//  Middle-Left: Hierarchy (Coordinate List)
// ─────────────────────────────────────────────────────────────
fn draw_hierarchy(frame: &mut Frame, state: &AppState, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .title(Span::styled(
            " \u{1F4CB} Hierarchy ",
            Style::default().fg(TITLE).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(BG));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.height == 0 {
        return;
    }

    let max_visible = inner.height as usize;
    let start = state.coordinates.len().saturating_sub(max_visible);

    let items: Vec<ListItem> = state.coordinates[start..]
        .iter()
        .enumerate()
        .map(|(idx, coord)| {
            let is_latest = start + idx == state.coordinates.len().saturating_sub(1);
            let style = if is_latest && state.match_flash > 0 {
                Style::default()
                    .fg(HIGHLIGHT)
                    .add_modifier(Modifier::BOLD)
            } else if coord.contains("0.0") {
                Style::default().fg(ZERO_RUN)
            } else {
                Style::default().fg(COORD)
            };
            let prefix = if is_latest { "\u{25B6} " } else { "  " };
            ListItem::new(Span::styled(format!("{}{}", prefix, coord), style))
        })
        .collect();

    let list = List::new(items).style(Style::default().bg(BG));
    frame.render_widget(list, inner);
}

// ─────────────────────────────────────────────────────────────
//  Middle-Right: Hash Scanner (Scene)
// ─────────────────────────────────────────────────────────────
fn draw_scanner(frame: &mut Frame, state: &AppState, area: Rect) {
    let border_color = if state.match_flash > 6 {
        BORDER_FLASH
    } else {
        BORDER
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(Span::styled(
            " \u{26A1} Scanner ",
            Style::default().fg(TITLE).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(BG));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let width = inner.width as usize;
    let height = inner.height as usize;
    if width == 0 || height == 0 {
        return;
    }

    // Reserve 2 lines at bottom for pointer + info
    let hash_row_count = height.saturating_sub(2).max(1);
    let mut lines: Vec<Line> = Vec::with_capacity(height);

    for row in 0..hash_row_count {
        let line_idx = row % state.hash_lines.len();
        let line_data = &state.hash_lines[line_idx];

        if line_data.is_empty() {
            lines.push(Line::from(Span::styled(
                " ".repeat(width),
                Style::default().fg(DARK),
            )));
            continue;
        }

        // Scroll offset: each line scrolls at a different speed for parallax
        let speed = (row + 1) * 2;
        let offset = (state.tick as usize * speed) % line_data.len();

        let visible: String = line_data.chars().cycle().skip(offset).take(width).collect();

        let is_pointer_row = row == state.pointer_line_idx % hash_row_count;

        let spans: Vec<Span> = visible
            .chars()
            .enumerate()
            .map(|(col, ch)| {
                // Match flash highlight near pointer
                let in_match_zone = state.match_flash > 0
                    && is_pointer_row
                    && col >= state.pointer_pos.saturating_sub(6)
                    && col <= state.pointer_pos.wrapping_add(6);

                if in_match_zone {
                    Span::styled(
                        ch.to_string(),
                        Style::default()
                            .fg(Color::Rgb(20, 20, 30))
                            .bg(HIGHLIGHT)
                            .add_modifier(Modifier::BOLD),
                    )
                } else {
                    // Subtle color variation per character
                    let g = 150u8.wrapping_add(((col * 7 + row * 19) % 80) as u8);
                    let b = 130u8.wrapping_add(((col * 5 + row * 13) % 70) as u8);
                    let r = 40u8.wrapping_add(((col * 3 + row * 11) % 50) as u8);
                    Span::styled(ch.to_string(), Style::default().fg(Color::Rgb(r, g, b)))
                }
            })
            .collect();

        lines.push(Line::from(spans));
    }

    // ── Pointer line ──
    let ptr_pos = state.pointer_pos.min(width.saturating_sub(1));
    let mut pointer_chars: Vec<Span> = Vec::with_capacity(width);
    for col in 0..width {
        if col == ptr_pos {
            pointer_chars.push(Span::styled(
                "\u{25B2}",
                Style::default()
                    .fg(HIGHLIGHT)
                    .add_modifier(Modifier::BOLD),
            ));
        } else if col == ptr_pos.wrapping_sub(1) || col == ptr_pos + 1 {
            pointer_chars.push(Span::styled(
                "\u{2500}",
                Style::default().fg(Color::Rgb(180, 140, 0)),
            ));
        } else {
            pointer_chars.push(Span::styled(" ", Style::default()));
        }
    }
    lines.push(Line::from(pointer_chars));

    // ── Info line ──
    let info = format!(
        " Scan #{} | Hash: BLAKE3-256 | Dict offset: {} ",
        state.scan_count,
        state.scan_count.wrapping_mul(32)
    );
    lines.push(Line::from(Span::styled(
        info,
        Style::default().fg(Color::Rgb(70, 70, 100)),
    )));

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, inner);
}

// ─────────────────────────────────────────────────────────────
//  Bottom Panel: Status
// ─────────────────────────────────────────────────────────────
fn draw_status(frame: &mut Frame, state: &AppState, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .title(Span::styled(
            " \u{25C9} Status ",
            Style::default().fg(TITLE).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(BG));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rate_str = if state.hash_rate > 1_000_000.0 {
        format!("{:.2}M h/s", state.hash_rate / 1_000_000.0)
    } else if state.hash_rate > 1_000.0 {
        format!("{:.1}K h/s", state.hash_rate / 1_000.0)
    } else {
        format!("{:.0} h/s", state.hash_rate)
    };

    let sep = Span::styled(" \u{2502} ", Style::default().fg(SEPARATOR));

    let line = if state.finished && !state.status_message.is_empty() {
        Line::from(Span::styled(
            format!(" {} — Press any key to exit", state.status_message),
            Style::default().fg(COMPLETED).add_modifier(Modifier::BOLD),
        ))
    } else {
        Line::from(vec![
            Span::styled(" Rate: ", Style::default().fg(LABEL)),
            Span::styled(rate_str, Style::default().fg(STATUS_VAL).add_modifier(Modifier::BOLD)),
            sep.clone(),
            Span::styled("Compress: ", Style::default().fg(LABEL)),
            Span::styled(
                format!("{:.4}x", state.compression_ratio),
                Style::default().fg(STATUS_VAL).add_modifier(Modifier::BOLD),
            ),
            sep.clone(),
            Span::styled("Elapsed: ", Style::default().fg(LABEL)),
            Span::styled(
                format!("{:.1}s", state.elapsed_secs),
                Style::default().fg(STATUS_VAL).add_modifier(Modifier::BOLD),
            ),
            sep.clone(),
            Span::styled("Chunks: ", Style::default().fg(LABEL)),
            Span::styled(
                format!("{}/{}", state.completed_chunks, state.total_chunks),
                Style::default().fg(COMPLETED).add_modifier(Modifier::BOLD),
            ),
            sep,
            Span::styled("Dict: ", Style::default().fg(LABEL)),
            Span::styled(
                "BLAKE3",
                Style::default().fg(Color::Rgb(180, 120, 255)).add_modifier(Modifier::BOLD),
            ),
        ])
    };

    let paragraph = Paragraph::new(line);
    frame.render_widget(paragraph, inner);
}
