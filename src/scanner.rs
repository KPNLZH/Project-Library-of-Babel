//! Scanner thread — orchestrates real BLAKE3 hash-dictionary encryption/decryption,
//! updating shared AppState for TUI visualization.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::app::{AppState, Mode};
use crate::crypto::{self, CoordEntry};

/// Entry point — dispatches to encrypt or decrypt based on mode.
pub fn run_scanner(state: Arc<Mutex<AppState>>) {
    let mode_info = {
        let s = state.lock().unwrap();
        match &s.mode {
            Mode::Encrypt {
                password,
                chunk_size,
                ..
            } => ("encrypt", password.clone(), *chunk_size, String::new()),
            Mode::Decrypt {
                archive_path,
                password,
            } => (
                "decrypt",
                password.clone(),
                0,
                archive_path.clone(),
            ),
        }
    };

    match mode_info.0 {
        "encrypt" => run_encrypt(state, &mode_info.1, mode_info.2),
        "decrypt" => run_decrypt(state, &mode_info.1, &mode_info.3),
        _ => unreachable!(),
    }
}

// ─────────────────────────────────────────────────────────────
//  Encrypt
// ─────────────────────────────────────────────────────────────
fn run_encrypt(state: Arc<Mutex<AppState>>, password: &str, chunk_size: usize) {
    let start_time = Instant::now();
    let mut last_rate_update = Instant::now();
    let mut last_count: u64 = 0;

    // Read source data (clone out of lock)
    let source_data = state.lock().unwrap().source_data.clone();
    let total_chunks = source_data.len().div_ceil(chunk_size);

    // Step 1: Generate salt, compute seed
    let salt = crypto::generate_salt();
    let salt_hex = crypto::hex_encode(&salt);
    let mut current_hash = crypto::compute_seed(password.as_bytes(), &salt);
    let checksum = blake3::hash(&source_data).to_hex().to_string();

    let mut all_coords: Vec<CoordEntry> = Vec::new();
    let mut hash_count: u64 = 0;

    // Step 2: Process each chunk
    for (chunk_idx, chunk) in source_data.chunks(chunk_size).enumerate() {
        if !state.lock().unwrap().running {
            return;
        }

        let mut miss_count: u64 = 0;

        loop {
            if !state.lock().unwrap().running {
                return;
            }

            let hash_bytes: [u8; 32] = *current_hash.as_bytes();
            hash_count += 1;

            // Update hash display periodically to reduce lock contention
            if hash_count % 128 == 0 {
                push_hash_display(&state, &current_hash, hash_count);
            }

            if let Some(pos) = crypto::find_chunk_in_hash(&hash_bytes, chunk) {
                // ── Match found ──
                if miss_count > 0 {
                    all_coords.push(CoordEntry::ZeroRun(miss_count));
                }
                all_coords.push(CoordEntry::Index(pos));

                // Update state with match info
                {
                    let mut s = state.lock().unwrap();
                    let coord_str = if miss_count > 0 {
                        format!("x{}_0.0, I={}", miss_count, pos)
                    } else {
                        format!("I={}", pos)
                    };
                    s.coordinates.push(coord_str);
                    s.completed_chunks = chunk_idx + 1;
                    s.current_chunk = (chunk_idx + 1).min(total_chunks);
                    s.match_flash = 12;
                    s.pointer_pos = (pos * 2).min(54);
                    s.compression_ratio =
                        all_coords.len() as f64 / source_data.len() as f64;
                    update_rate(&mut s, hash_count, &mut last_rate_update, &mut last_count, &start_time);
                }

                // Vectorize: H_next = H(H_i + I)
                current_hash = crypto::vectorize_hash(&current_hash, pos);
                break;
            } else {
                // ── No match — advance ──
                miss_count += 1;
                current_hash = crypto::advance_hash(&current_hash);

                // Update stats periodically
                if miss_count.is_multiple_of(50) {
                    let mut s = state.lock().unwrap();
                    s.scan_count = hash_count;
                    s.pointer_pos = (hash_count % 50) as usize;
                    update_rate(&mut s, hash_count, &mut last_rate_update, &mut last_count, &start_time);
                    if s.match_flash > 0 {
                        s.match_flash = s.match_flash.saturating_sub(1);
                    }
                }
            }
        }
    }

    // Step 3: Write output file
    let output_path = state.lock().unwrap().output_path.clone();
    let output = crypto::format_output(&salt_hex, &all_coords, &checksum, chunk_size);

    let mut s = state.lock().unwrap();
    s.completed_chunks = s.total_chunks;
    match std::fs::write(&output_path, &output) {
        Ok(()) => {
            s.status_message = format!("Encrypted -> {}", output_path);
        }
        Err(e) => {
            s.status_message = format!("Error: {}", e);
        }
    }
    s.finished = true;
    s.elapsed_secs = start_time.elapsed().as_secs_f64();
}

// ─────────────────────────────────────────────────────────────
//  Decrypt
// ─────────────────────────────────────────────────────────────
fn run_decrypt(state: Arc<Mutex<AppState>>, password: &str, archive_path: &str) {
    let start_time = Instant::now();
    let mut last_rate_update = Instant::now();
    let mut last_count: u64 = 0;

    // Read and parse archive
    let content = match std::fs::read_to_string(archive_path) {
        Ok(c) => c,
        Err(e) => {
            let mut s = state.lock().unwrap();
            s.status_message = format!("Error reading archive: {}", e);
            s.finished = true;
            return;
        }
    };

    let (salt_hex, coords, expected_checksum, chunk_size) =
        match crypto::parse_archive(&content) {
            Ok(v) => v,
            Err(e) => {
                let mut s = state.lock().unwrap();
                s.status_message = format!("Parse error: {}", e);
                s.finished = true;
                return;
            }
        };

    // Update chunk_size from archive
    state.lock().unwrap().chunk_size = chunk_size;

    let salt = match crypto::hex_decode(&salt_hex) {
        Ok(s) => s,
        Err(e) => {
            let mut s = state.lock().unwrap();
            s.status_message = format!("Salt decode error: {}", e);
            s.finished = true;
            return;
        }
    };

    let mut current_hash = crypto::compute_seed(password.as_bytes(), &salt);
    let mut output_data: Vec<u8> = Vec::new();
    let mut hash_count: u64 = 0;
    let mut data_chunk_idx: usize = 0;

    // Process each coordinate entry
    for entry in &coords {
        if !state.lock().unwrap().running {
            return;
        }

        match entry {
            CoordEntry::ZeroRun(count) => {
                // Skip N hashes
                for i in 0..*count {
                    current_hash = crypto::advance_hash(&current_hash);
                    hash_count += 1;

                    // Update display periodically
                    if i % 50 == 0 {
                        push_hash_display(&state, &current_hash, hash_count);
                        let mut s = state.lock().unwrap();
                        s.scan_count = hash_count;
                        update_rate(&mut s, hash_count, &mut last_rate_update, &mut last_count, &start_time);
                    }
                }
                // Display the zero-run
                let mut s = state.lock().unwrap();
                s.coordinates.push(format!("x{}_0.0", count));
            }
            CoordEntry::Index(pos) => {
                hash_count += 1;
                let hash_bytes = current_hash.as_bytes();
                let start = *pos;
                let end = (start + chunk_size).min(32);
                output_data.extend_from_slice(&hash_bytes[start..end]);

                push_hash_display(&state, &current_hash, hash_count);

                data_chunk_idx += 1;
                {
                    let mut s = state.lock().unwrap();
                    s.coordinates.push(format!("I={}", pos));
                    s.completed_chunks = data_chunk_idx;
                    s.current_chunk = data_chunk_idx;
                    s.match_flash = 12;
                    s.pointer_pos = (pos * 2).min(54);
                    s.scan_count = hash_count;
                    // Update source_data with reconstructed bytes
                    s.source_data = output_data.clone();
                    update_rate(&mut s, hash_count, &mut last_rate_update, &mut last_count, &start_time);
                }

                current_hash = crypto::vectorize_hash(&current_hash, *pos);
            }
        }
    }

    // Verify checksum
    let actual_checksum = blake3::hash(&output_data).to_hex().to_string();
    let checksum_ok = expected_checksum.is_empty() || actual_checksum == expected_checksum;

    // Write output
    let output_path = state.lock().unwrap().output_path.clone();
    let mut s = state.lock().unwrap();
    s.completed_chunks = s.total_chunks;

    match std::fs::write(&output_path, &output_data) {
        Ok(()) => {
            if checksum_ok {
                s.status_message =
                    format!("Decrypted -> {} (checksum OK)", output_path);
            } else {
                s.status_message = format!(
                    "Decrypted -> {} (CHECKSUM MISMATCH!)",
                    output_path
                );
            }
        }
        Err(e) => {
            s.status_message = format!("Error writing output: {}", e);
        }
    }
    s.finished = true;
    s.elapsed_secs = start_time.elapsed().as_secs_f64();
}

// ─────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────

/// Push hash hex into display lines for TUI animation.
fn push_hash_display(
    state: &Arc<Mutex<AppState>>,
    hash: &blake3::Hash,
    hash_count: u64,
) {
    let hex = hash.to_hex();
    let hex_str = hex.as_str();
    let mut s = state.lock().unwrap();
    let line_idx = (hash_count as usize) % s.hash_lines.len();
    s.hash_lines[line_idx].push_str(&hex_str[..16]);
    // Trim to prevent unbounded growth
    if s.hash_lines[line_idx].len() > 600 {
        let len = s.hash_lines[line_idx].len();
        s.hash_lines[line_idx] = s.hash_lines[line_idx][len - 400..].to_string();
    }
    s.scan_count = hash_count;
}

/// Update hash rate and elapsed time.
fn update_rate(
    s: &mut AppState,
    hash_count: u64,
    last_rate_update: &mut Instant,
    last_count: &mut u64,
    start_time: &Instant,
) {
    let now = Instant::now();
    if now.duration_since(*last_rate_update) >= Duration::from_millis(200) {
        let dt = now.duration_since(*last_rate_update).as_secs_f64();
        let dc = hash_count - *last_count;
        s.hash_rate = dc as f64 / dt;
        *last_count = hash_count;
        *last_rate_update = now;
    }
    s.elapsed_secs = start_time.elapsed().as_secs_f64();
}
