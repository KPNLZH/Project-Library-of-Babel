//! Project Library of Babel — TUI Encryption/Decryption Tool
//!
//! Usage:
//!   babel_crypt encrypt <input_file> <password> [chunk_size]
//!   babel_crypt decrypt <archive.babel.txt> <password>

use std::io;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crossterm::{
    ExecutableCommand,
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::prelude::*;

mod app;
mod crypto;
mod scanner;
mod ui;

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 4 {
        print_usage();
        return Ok(());
    }

    let command = args[1].as_str();
    let file_path = &args[2];
    let password = &args[3];

    // Build AppState based on mode
    let state = match command {
        "encrypt" => {
            let chunk_size: usize = if args.len() >= 5 {
                args[4].parse().unwrap_or(1)
            } else {
                1
            };
            app::AppState::new_encrypt(file_path, password, chunk_size)?
        }
        "decrypt" => app::AppState::new_decrypt(file_path, password)?,
        _ => {
            print_usage();
            return Ok(());
        }
    };

    let state = Arc::new(Mutex::new(state));

    // ── Terminal setup ──
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    terminal.clear()?;

    // ── Spawn scanner thread ──
    let scanner_state = Arc::clone(&state);
    let scanner_handle = thread::spawn(move || {
        scanner::run_scanner(scanner_state);
    });

    // ── Main render loop (~60 fps) ──
    let target_frame_time = Duration::from_millis(16);

    loop {
        let frame_start = Instant::now();

        // Poll input
        if event::poll(Duration::from_millis(0))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => {
                    state.lock().unwrap().running = false;
                    break;
                }
                _ => {}
            }
        }

        // Check if scanner finished — wait a moment then auto-exit
        {
            let s = state.lock().unwrap();
            if s.finished {
                // Keep showing the final state for a beat
                drop(s);
                // Render final frame
                {
                    let s = state.lock().unwrap();
                    terminal.draw(|frame| ui::draw_ui(frame, &s))?;
                }
                // Wait for user to see it (or press q)
                loop {
                    if event::poll(Duration::from_millis(100))?
                        && let Event::Key(key) = event::read()?
                        && key.kind == KeyEventKind::Press
                    {
                        break;
                    }
                }
                break;
            }
        }

        // Tick
        state.lock().unwrap().tick += 1;

        // Draw
        {
            let s = state.lock().unwrap();
            terminal.draw(|frame| ui::draw_ui(frame, &s))?;
        }

        // Frame-rate limiter
        let elapsed = frame_start.elapsed();
        if elapsed < target_frame_time {
            thread::sleep(target_frame_time - elapsed);
        }
    }

    // ── Cleanup ──
    state.lock().unwrap().running = false;
    let _ = scanner_handle.join();

    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;

    // Print final message to stdout after TUI exits
    let s = state.lock().unwrap();
    if !s.status_message.is_empty() {
        println!("{}", s.status_message);
    }
    println!("Project Library of Babel — session ended.");

    Ok(())
}

fn print_usage() {
    eprintln!("Project Library of Babel v0.1");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  babel_crypt encrypt <input_file> <password> [chunk_size]");
    eprintln!("  babel_crypt decrypt <archive.babel.txt> <password>");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  babel_crypt encrypt secret.txt mypassword");
    eprintln!("  babel_crypt encrypt data.bin mypassword 2");
    eprintln!("  babel_crypt decrypt secret.txt.babel.txt mypassword");
}
