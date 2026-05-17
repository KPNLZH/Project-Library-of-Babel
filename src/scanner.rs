//! Scanner thread — orchestrates real BLAKE3 hash-dictionary encryption/decryption,
//! updating shared AppState for TUI visualization.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use rayon::prelude::*;

use crate::app::{AppState, Mode, OutputFormat};
use crate::crypto::{self, MatchCoord};

/// Entry point — dispatches to encrypt or decrypt based on mode.
pub fn run_scanner(state: Arc<Mutex<AppState>>) {
    let (cmd, password, chunk_size, path, format) = {
        let s = state.lock().unwrap();
        match &s.mode {
            Mode::Encrypt { password, chunk_size, format, .. } =>
                ("encrypt", password.clone(), *chunk_size, String::new(), *format),
            Mode::Decrypt { archive_path, password, format } =>
                ("decrypt", password.clone(), 0, archive_path.clone(), *format),
        }
    };

    match cmd {
        "encrypt" => run_encrypt(state, &password, chunk_size, format),
        "decrypt" => run_decrypt(state, &password, &path, format),
        _ => unreachable!(),
    }
}

// ─────────────────────────────────────────────────────────────
//  Encrypt
// ─────────────────────────────────────────────────────────────
fn run_encrypt(state: Arc<Mutex<AppState>>, password: &str, chunk_size: usize, format: OutputFormat) {
    let start_time = Instant::now();

    let source_data = state.lock().unwrap().source_data.clone();

    let salt = crypto::generate_salt();
    let salt_hex = crypto::hex_encode(&salt);
    let checksum = blake3::hash(&source_data).to_hex().to_string();

    let total_chunks = source_data.len().div_ceil(chunk_size);

    // Spawn a thread to update hash rate independently of the parallel workers
    let state_for_rate = Arc::clone(&state);
    let running_flag = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let running_flag_clone = Arc::clone(&running_flag);
    let rate_updater = std::thread::spawn(move || {
        let mut last_rate_update = Instant::now();
        let mut last_count: u64 = 0;
        while running_flag_clone.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(100));
            let mut s = state_for_rate.lock().unwrap();
            let hash_count = s.scan_count;
            update_rate(&mut s, hash_count, &mut last_rate_update, &mut last_count, &start_time);
        }
    });

    let all_coords: Vec<MatchCoord> = source_data
        .par_chunks(chunk_size)
        .enumerate()
        .map(|(chunk_idx, chunk)| {
            if !state.lock().unwrap().running {
                return MatchCoord { misses: 0, index: 0 };
            }

            let mut current_hash = crypto::compute_seed_for_chunk(password.as_bytes(), &salt, chunk_idx);
            let mut miss_count: u64 = 0;
            let mut local_scan_count: u64 = 0;

            loop {
                let hash_bytes: [u8; 32] = *current_hash.as_bytes();
                local_scan_count += 1;

                if let Some(pos) = crypto::find_chunk_in_hash(&hash_bytes, chunk) {
                    let mut s = state.lock().unwrap();
                    s.scan_count += local_scan_count;
                    if chunk_idx % 10 == 0 || chunk_idx == total_chunks - 1 {
                        s.completed_chunks = s.completed_chunks.max(chunk_idx + 1);
                        s.current_chunk = chunk_idx + 1;
                        s.match_flash = 12;
                        s.pointer_pos = (pos * 2).min(54);
                        s.estimated_bin_bytes = 4 + 1 + 16 + 32 + 4 + (chunk_idx + 1) * 2;
                        
                        let coord_str = if miss_count > 0 {
                            format!("x{}_0.0, I={}", miss_count, pos)
                        } else {
                            format!("I={}", pos)
                        };
                        s.coordinates.push(coord_str);
                        if s.coordinates.len() > 100 {
                            s.coordinates.remove(0);
                        }
                    }
                    return MatchCoord { misses: miss_count, index: pos };
                } else {
                    miss_count += 1;
                    current_hash = crypto::advance_hash(&current_hash);

                    if local_scan_count % 10000 == 0 {
                        let mut s = state.lock().unwrap();
                        if !s.running { return MatchCoord { misses: 0, index: 0 }; }
                        s.scan_count += local_scan_count;
                        local_scan_count = 0;
                        s.pointer_pos = (miss_count % 50) as usize;
                        if s.match_flash > 0 {
                            s.match_flash = s.match_flash.saturating_sub(1);
                        }
                    }
                }
            }
        })
        .collect();

    running_flag.store(false, std::sync::atomic::Ordering::Relaxed);
    let _ = rate_updater.join();

    if !state.lock().unwrap().running {
        return;
    }

    {
        let mut s = state.lock().unwrap();
        s.compression_ratio = all_coords.len() as f64 / source_data.len() as f64;
    }

    // ── Write output ──────────────────────────────────────────────────────────
    let output_path = state.lock().unwrap().output_path.clone();

    let write_result = match format {
        OutputFormat::Text => {
            let text = crypto::format_output(&salt_hex, &all_coords, &checksum, chunk_size);
            std::fs::write(&output_path, text.as_bytes())
        }
        OutputFormat::Binary => {
            let bin = crate::codec::encode(&salt, &checksum, &all_coords, chunk_size as u8);
            std::fs::write(&output_path, &bin)
        }
    };

    let mut s = state.lock().unwrap();
    s.completed_chunks = s.total_chunks;

    match write_result {
        Ok(()) => {
            let file_size = std::fs::metadata(&output_path).map(|m| m.len()).unwrap_or(0);
            let src_size = source_data.len() as u64;
            let ratio = if src_size > 0 { file_size as f64 / src_size as f64 } else { 0.0 };
            s.status_message = format!(
                "Encrypted -> {} | {} bytes (ratio {:.3}x) [{}]",
                output_path, file_size, ratio, format.label()
            );
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
fn run_decrypt(state: Arc<Mutex<AppState>>, password: &str, archive_path: &str, format: OutputFormat) {
    let start_time = Instant::now();

    // ── Parse archive (text or binary) ───────────────────────────────────────
    let (salt_bytes, coords, expected_checksum, chunk_size) = match format {
        OutputFormat::Text => {
            let content = match std::fs::read_to_string(archive_path) {
                Ok(c) => c,
                Err(e) => {
                    let mut s = state.lock().unwrap();
                    s.status_message = format!("Error reading archive: {}", e);
                    s.finished = true;
                    return;
                }
            };
            match crypto::parse_archive(&content) {
                Ok((salt_hex, coords, checksum, cs)) => {
                    let salt = match crypto::hex_decode(&salt_hex) {
                        Ok(s) => s,
                        Err(e) => {
                            let mut st = state.lock().unwrap();
                            st.status_message = format!("Salt decode error: {}", e);
                            st.finished = true;
                            return;
                        }
                    };
                    (salt, coords, checksum, cs)
                }
                Err(e) => {
                    let mut s = state.lock().unwrap();
                    s.status_message = format!("Parse error: {}", e);
                    s.finished = true;
                    return;
                }
            }
        }
        OutputFormat::Binary => {
            let data = match std::fs::read(archive_path) {
                Ok(d) => d,
                Err(e) => {
                    let mut s = state.lock().unwrap();
                    s.status_message = format!("Error reading archive: {}", e);
                    s.finished = true;
                    return;
                }
            };
            match crate::codec::decode(&data) {
                Ok((salt, checksum, coords, cs)) => {
                    (salt.to_vec(), coords, checksum, cs as usize)
                }
                Err(e) => {
                    let mut s = state.lock().unwrap();
                    s.status_message = format!("Decode error: {}", e);
                    s.finished = true;
                    return;
                }
            }
        }
    };

    state.lock().unwrap().chunk_size = chunk_size;
    let total_chunks = coords.len();
    state.lock().unwrap().total_chunks = total_chunks;

    let state_for_rate = Arc::clone(&state);
    let running_flag = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let running_flag_clone = Arc::clone(&running_flag);
    let rate_updater = std::thread::spawn(move || {
        let mut last_rate_update = Instant::now();
        let mut last_count: u64 = 0;
        while running_flag_clone.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(100));
            let mut s = state_for_rate.lock().unwrap();
            let hash_count = s.scan_count;
            update_rate(&mut s, hash_count, &mut last_rate_update, &mut last_count, &start_time);
        }
    });

    let mut output_data: Vec<u8> = vec![0; total_chunks * chunk_size];

    let chunks_output: Vec<Vec<u8>> = coords
        .par_iter()
        .enumerate()
        .map(|(chunk_idx, coord)| {
            if !state.lock().unwrap().running {
                return Vec::new();
            }

            let mut current_hash = crypto::compute_seed_for_chunk(password.as_bytes(), &salt_bytes, chunk_idx);
            
            let mut local_scan_count = 0;
            for _ in 0..coord.misses {
                current_hash = crypto::advance_hash(&current_hash);
                local_scan_count += 1;
                
                if local_scan_count % 10000 == 0 {
                    let mut s = state.lock().unwrap();
                    s.scan_count += local_scan_count;
                    local_scan_count = 0;
                }
            }

            let hash_bytes = current_hash.as_bytes();
            let start = coord.index;
            let end = (start + chunk_size).min(32);
            
            let mut s = state.lock().unwrap();
            s.scan_count += local_scan_count + 1;
            if chunk_idx % 10 == 0 || chunk_idx == total_chunks - 1 {
                s.completed_chunks = s.completed_chunks.max(chunk_idx + 1);
                s.current_chunk = chunk_idx + 1;
                s.match_flash = 12;
                s.pointer_pos = (coord.index * 2).min(54);
            }

            hash_bytes[start..end].to_vec()
        })
        .collect();

    running_flag.store(false, std::sync::atomic::Ordering::Relaxed);
    let _ = rate_updater.join();

    if !state.lock().unwrap().running { return; }

    output_data.clear();
    for chunk in chunks_output {
        output_data.extend_from_slice(&chunk);
    }

    let actual_checksum = blake3::hash(&output_data).to_hex().to_string();
    let checksum_ok = expected_checksum.is_empty() || actual_checksum == expected_checksum;

    let output_path = state.lock().unwrap().output_path.clone();
    let mut s = state.lock().unwrap();
    s.completed_chunks = s.total_chunks;
    s.source_data = output_data.clone();

    match std::fs::write(&output_path, &output_data) {
        Ok(()) => {
            if checksum_ok {
                s.status_message = format!(
                    "Decrypted -> {} ({} bytes, checksum OK) [{}]",
                    output_path, output_data.len(), format.label()
                );
            } else {
                s.status_message = format!(
                    "Decrypted -> {} (CHECKSUM MISMATCH!) [{}]",
                    output_path, format.label()
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
        let dc = hash_count.saturating_sub(*last_count);
        s.hash_rate = dc as f64 / dt;
        *last_count = hash_count;
        *last_rate_update = now;
    }
    s.elapsed_secs = start_time.elapsed().as_secs_f64();
}