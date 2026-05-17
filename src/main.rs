//! Project Library of Babel — TUI Encryption/Decryption Tool
//!
//! Usage:
//!   babel_crypt encrypt <input_file> <password> [chunk_size] [--binary|--text]
//!   babel_crypt decrypt <archive> <password>
//!   babel_crypt analyze <input_file>   # show expected output sizes per chunk_size

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
mod codec;
mod crypto;
mod scanner;
mod ui;

use app::OutputFormat;

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        print_usage();
        return Ok(());
    }

    let command = args[1].as_str();

    // ── analyze sub-command (no TUI) ──────────────────────────────────────────
    if command == "analyze" {
        let path = &args[2];
        return cmd_analyze(path);
    }

    if args.len() < 4 {
        print_usage();
        return Ok(());
    }

    let file_path = &args[2];
    let password  = &args[3];

    // ── Detect flags anywhere in remaining args ───────────────────────────────
    let rest = &args[4..];
    let want_binary = rest.iter().any(|a| a == "--binary" || a == "-b");
    let want_text   = rest.iter().any(|a| a == "--text"   || a == "-t");

    // chunk_size: first positional arg in rest that is a plain number
    let chunk_size: usize = rest
        .iter()
        .find(|a| !a.starts_with('-'))
        .and_then(|a| a.parse().ok())
        .unwrap_or(1);

    // Default: text (backward-compat). --binary overrides.
    let format = if want_binary && !want_text {
        OutputFormat::Binary
    } else {
        OutputFormat::Text
    };

    // ── Build AppState ────────────────────────────────────────────────────────
    let state = match command {
        "encrypt" => app::AppState::new_encrypt(file_path, password, chunk_size, format)?,
        "decrypt" => app::AppState::new_decrypt(file_path, password)?,
        _ => {
            print_usage();
            return Ok(());
        }
    };

    let state = Arc::new(Mutex::new(state));

    // ── Terminal setup ────────────────────────────────────────────────────────
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    terminal.clear()?;

    // ── Spawn scanner thread ──────────────────────────────────────────────────
    let scanner_state = Arc::clone(&state);
    let scanner_handle = thread::spawn(move || {
        scanner::run_scanner(scanner_state);
    });

    // ── Main render loop (~250 fps) ───────────────────────────────────────────
    let target_frame_time = Duration::from_millis(4);

    loop {
        let frame_start = Instant::now();

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

        {
            let s = state.lock().unwrap();
            if s.finished {
                drop(s);
                {
                    let s = state.lock().unwrap();
                    terminal.draw(|frame| ui::draw_ui(frame, &s))?;
                }
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

        state.lock().unwrap().tick += 1;

        {
            let s = state.lock().unwrap();
            terminal.draw(|frame| ui::draw_ui(frame, &s))?;
        }

        let elapsed = frame_start.elapsed();
        if elapsed < target_frame_time {
            thread::sleep(target_frame_time - elapsed);
        }
    }

    // ── Cleanup ───────────────────────────────────────────────────────────────
    state.lock().unwrap().running = false;
    let _ = scanner_handle.join();

    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;

    let s = state.lock().unwrap();
    if !s.status_message.is_empty() {
        println!("{}", s.status_message);
    }
    println!("Project Library of Babel — session ended.");

    Ok(())
}

// ── analyze command ───────────────────────────────────────────────────────────

fn cmd_analyze(path: &str) -> io::Result<()> {
    let data = std::fs::read(path)?;
    let src_bytes = data.len();

    println!("Project Library of Babel — Size Estimator");
    println!("Input : {} ({} bytes)", path, src_bytes);
    println!();
    println!(
        "{:<12} {:>12} {:>14} {:>14} {:>14} {:>14}",
        "chunk_size", "avg_hashes", "txt_size", "bin_raw", "bin_ans", "speedup_est"
    );
    println!("{}", "-".repeat(82));

    for cs in 1usize..=4 {
        let avg = crypto::avg_hashes_per_chunk(cs);
        let n_chunks = src_bytes.div_ceil(cs);

        // ZeroRun count per chunk = avg - 1 (geometric distribution)
        let avg_zero_run = (avg - 1.0).max(0.0);

        // Text format: each chunk produces "x{run}_0.0, {idx}" → ~14 chars avg
        // More precisely: run encoded in decimal = log10(avg_zero_run) + 1 digits
        let run_digits = if avg_zero_run > 1.0 { avg_zero_run.log10().ceil() as usize } else { 1 };
        let txt_per_chunk = run_digits + 9 + 3; // "x{d}_0.0, {idx=1digit}, "
        let txt_header = 120usize; // fixed header size approx
        let txt_size = txt_header + n_chunks * txt_per_chunk;

        // Binary raw: LEB128(zero_run) + 1 byte sentinel + 1 byte index
        // LEB128(n) uses ceil(log2(n+1)/7) bytes
        let leb_bytes = if avg_zero_run < 128.0 { 1 }
                        else if avg_zero_run < 16384.0 { 2 }
                        else { 3 };
        let bin_raw = 4 + 1 + 16 + 32 + 4 + n_chunks * (1 + leb_bytes + 1);

        // ANS/range-coding reduces entropy-close sequences.
        // Index bytes (0..31) and sentinel 0xFF have very different distributions.
        // For chunk_size=1: Index is uniform in 0..31 (5 bits), zero-run is geometric.
        // Rough entropy estimate: ~6.5 bits/byte for mixed stream → ~81% of raw.
        // For larger chunk sizes the zero-run is more extreme → higher compressibility.
        let compress_factor = match cs {
            1 => 0.82,
            2 => 0.70,
            3 => 0.62,
            _ => 0.58,
        };
        let bin_ans = (4 + 1 + 16 + 32 + 4) + ((n_chunks * (1 + leb_bytes + 1)) as f64 * compress_factor) as usize;

        let speedup = if avg <= 1.0 { "instant".to_string() } else { format!("{:.0}x slower", avg / crypto::avg_hashes_per_chunk(1)) };

        println!(
            "{:<12} {:>12.0} {:>13}B {:>13}B {:>13}B {:>14}",
            cs, avg, txt_size, bin_raw, bin_ans, speedup
        );
    }

    println!();
    println!("Recommendations:");
    println!("  --binary (default ext: .babel.bin) saves ~40-60% vs text format.");
    println!("  chunk_size=1 is fastest to encrypt; larger sizes are much slower");
    println!("  because average hashes-per-chunk grow as 256^chunk_size / windows.");
    println!();
    println!("Usage examples:");
    println!("  babel_crypt encrypt {} pass --binary", path);
    println!("  babel_crypt encrypt {} pass 1 --binary", path);

    Ok(())
}

fn print_usage() {
    eprintln!("Project Library of Babel v0.2");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  babel_crypt encrypt <input_file> <password> [chunk_size] [--binary|--text]");
    eprintln!("  babel_crypt decrypt <archive> <password>");
    eprintln!("  babel_crypt analyze <input_file>");
    eprintln!();
    eprintln!("Flags:");
    eprintln!("  --binary  (-b)  Write compact binary archive (.babel.bin) [ANS/range-coded]");
    eprintln!("  --text    (-t)  Write human-readable text archive (.babel.txt) [default]");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  babel_crypt encrypt secret.txt mypassword --binary");
    eprintln!("  babel_crypt encrypt data.bin mypassword 2 --binary");
    eprintln!("  babel_crypt decrypt secret.txt.babel.bin mypassword");
    eprintln!("  babel_crypt decrypt secret.txt.babel.txt mypassword");
    eprintln!("  babel_crypt analyze secret.txt");
}