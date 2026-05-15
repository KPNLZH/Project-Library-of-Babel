//! Core encryption/decryption logic for the Project Library of Babel system.
//!
//! Implements the hash-dictionary-space scanning algorithm:
//!   G₀ = H(P + S), then for each chunk scan H_i until match.

use rand::Rng;

/// A single entry in the coordinate list.
#[derive(Debug, Clone)]
pub enum CoordEntry {
    /// Match found at byte position I within the 32-byte hash.
    Index(usize),
    /// N consecutive misses (hash advances without a match).
    ZeroRun(u64),
}

// ── Primitive operations ──

/// Generate a random 16-byte salt.
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    let mut rng = rand::rng();
    for b in &mut salt {
        *b = rng.random();
    }
    salt
}

/// G₀ = H(P + S)
pub fn compute_seed(password: &[u8], salt: &[u8]) -> blake3::Hash {
    let mut input = Vec::with_capacity(password.len() + salt.len());
    input.extend_from_slice(password);
    input.extend_from_slice(salt);
    blake3::hash(&input)
}

/// H_{i+1} = H(H_i)
pub fn advance_hash(hash: &blake3::Hash) -> blake3::Hash {
    blake3::hash(hash.as_bytes())
}

/// H_next = H(H_i + I)  (vectorization)
pub fn vectorize_hash(hash: &blake3::Hash, index: usize) -> blake3::Hash {
    let mut input = hash.as_bytes().to_vec();
    input.extend_from_slice(&(index as u32).to_le_bytes());
    blake3::hash(&input)
}

/// Search for `chunk` as a contiguous subsequence within the 32-byte hash.
pub fn find_chunk_in_hash(hash_bytes: &[u8; 32], chunk: &[u8]) -> Option<usize> {
    if chunk.is_empty() || chunk.len() > 32 {
        return None;
    }
    hash_bytes.windows(chunk.len()).position(|w| w == chunk)
}

// ── Hex helpers ──

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("Hex string has odd length".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex at {}: {}", i, e))
        })
        .collect()
}

// ── Output format ──

/// Serialize coordinates to the body string: "14, x8_0.0, 7, 22, ..."
pub fn format_coords(coords: &[CoordEntry]) -> String {
    coords
        .iter()
        .map(|c| match c {
            CoordEntry::Index(pos) => pos.to_string(),
            CoordEntry::ZeroRun(n) => format!("x{}_0.0", n),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Build the complete archive text file.
pub fn format_output(
    salt_hex: &str,
    coords: &[CoordEntry],
    checksum: &str,
    chunk_size: usize,
) -> String {
    format!(
        "[Header]\n\
         Version: ABGRUND INDEX 0.1\n\
         Hash: BLAKE3-256\n\
         Salt: {}\n\
         ChunkSize: {}\n\
         \n\
         [Body]\n\
         {}\n\
         \n\
         [Footer]\n\
         Checksum: {}\n",
        salt_hex,
        chunk_size,
        format_coords(coords),
        checksum,
    )
}

// ── Archive parser ──

/// Parse an archive file back into its components.
pub fn parse_archive(content: &str) -> Result<(String, Vec<CoordEntry>, String, usize), String> {
    let mut salt = String::new();
    let mut chunk_size: usize = 1;
    let mut checksum = String::new();
    let mut body = String::new();
    let mut section = "";

    for line in content.lines() {
        let t = line.trim();
        match t {
            "[Header]" => {
                section = "header";
                continue;
            }
            "[Body]" => {
                section = "body";
                continue;
            }
            "[Footer]" => {
                section = "footer";
                continue;
            }
            _ => {}
        }
        match section {
            "header" => {
                if let Some(v) = t.strip_prefix("Salt: ") {
                    salt = v.to_string();
                } else if let Some(v) = t.strip_prefix("ChunkSize: ") {
                    chunk_size = v.parse().map_err(|e| format!("Invalid ChunkSize: {}", e))?;
                }
            }
            "body" => {
                if !t.is_empty() {
                    if !body.is_empty() {
                        body.push_str(", ");
                    }
                    body.push_str(t);
                }
            }
            "footer" => {
                if let Some(v) = t.strip_prefix("Checksum: ") {
                    checksum = v.to_string();
                }
            }
            _ => {}
        }
    }

    let coords = parse_coords(&body)?;
    if salt.is_empty() {
        return Err("Missing Salt in archive header".into());
    }
    Ok((salt, coords, checksum, chunk_size))
}

fn parse_coords(body: &str) -> Result<Vec<CoordEntry>, String> {
    let mut entries = Vec::new();
    for part in body.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if let Some(rest) = p.strip_prefix('x') {
            let count_str = rest
                .strip_suffix("_0.0")
                .ok_or_else(|| format!("Invalid zero-run: '{}'", p))?;
            let count: u64 = count_str
                .parse()
                .map_err(|e| format!("Invalid zero-run count '{}': {}", p, e))?;
            entries.push(CoordEntry::ZeroRun(count));
        } else {
            let idx: usize = p
                .parse()
                .map_err(|e| format!("Invalid index '{}': {}", p, e))?;
            entries.push(CoordEntry::Index(idx));
        }
    }
    Ok(entries)
}

// ── Decrypt ──

/// Reconstruct original data from an archive's coordinates.
#[allow(dead_code)]
pub fn decrypt(
    salt_hex: &str,
    password: &str,
    coords: &[CoordEntry],
    chunk_size: usize,
) -> Result<Vec<u8>, String> {
    let salt = hex_decode(salt_hex)?;
    let mut current_hash = compute_seed(password.as_bytes(), &salt);
    let mut output = Vec::new();

    for entry in coords {
        match entry {
            CoordEntry::ZeroRun(count) => {
                for _ in 0..*count {
                    current_hash = advance_hash(&current_hash);
                }
            }
            CoordEntry::Index(pos) => {
                let hash_bytes = current_hash.as_bytes();
                let start = *pos;
                let end = (start + chunk_size).min(32);
                if start >= 32 {
                    return Err(format!("Index {} out of range (hash is 32 bytes)", pos));
                }
                output.extend_from_slice(&hash_bytes[start..end]);
                current_hash = vectorize_hash(&current_hash, *pos);
            }
        }
    }

    Ok(output)
}
