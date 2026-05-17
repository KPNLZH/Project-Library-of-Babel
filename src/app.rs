//! Shared application state between the UI thread and the scanner thread.
//! Wrapped in `Arc<Mutex<>>` for thread-safe access.

/// Output format selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable text archive (.babel.txt) — original format.
    Text,
    /// Compact binary archive (.babel.bin) — ANS/range-coded.
    Binary,
}

impl OutputFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            OutputFormat::Text => ".babel.txt",
            OutputFormat::Binary => ".babel.bin",
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            OutputFormat::Text => "TXT",
            OutputFormat::Binary => "BIN",
        }
    }
}

/// Operating mode of the application.
pub enum Mode {
    Encrypt {
        #[allow(dead_code)]
        input_path: String,
        password: String,
        chunk_size: usize,
        format: OutputFormat,
    },
    Decrypt {
        archive_path: String,
        password: String,
        format: OutputFormat,
    },
}

pub struct AppState {
    // ── Top: Source Progress ──
    pub source_data: Vec<u8>,
    pub completed_chunks: usize,
    pub current_chunk: usize,
    pub total_chunks: usize,
    pub chunk_size: usize,

    // ── Middle-Left: Hierarchy (Coordinate List) ──
    pub coordinates: Vec<String>,

    // ── Middle-Right: Hash Scanner ──
    pub hash_lines: Vec<String>,
    pub pointer_pos: usize,
    pub pointer_line_idx: usize,
    pub scan_count: u64,
    pub match_flash: u8,

    // ── Bottom: Status ──
    pub hash_rate: f64,
    pub compression_ratio: f64,
    pub elapsed_secs: f64,
    /// Estimated binary-coded size in bytes (updated as chunks complete).
    pub estimated_bin_bytes: usize,

    // ── Control ──
    pub running: bool,
    pub tick: u64,
    pub mode: Mode,
    pub output_path: String,
    pub finished: bool,
    pub status_message: String,
}

impl AppState {
    /// Create state for encryption mode.
    pub fn new_encrypt(
        input_path: &str,
        password: &str,
        chunk_size: usize,
        format: OutputFormat,
    ) -> std::io::Result<Self> {
        let source = std::fs::read(input_path)?;
        let total = source.len().div_ceil(chunk_size);
        let ext = format.extension();
        let output_path = format!("{}{}", input_path, ext);

        Ok(Self {
            source_data: source,
            completed_chunks: 0,
            current_chunk: 0,
            total_chunks: total,
            chunk_size,
            coordinates: Vec::new(),
            hash_lines: Self::init_hash_lines(),
            pointer_pos: 20,
            pointer_line_idx: 3,
            scan_count: 0,
            match_flash: 0,
            hash_rate: 0.0,
            compression_ratio: 0.0,
            elapsed_secs: 0.0,
            estimated_bin_bytes: 0,
            running: true,
            tick: 0,
            mode: Mode::Encrypt {
                input_path: input_path.to_string(),
                password: password.to_string(),
                chunk_size,
                format,
            },
            output_path,
            finished: false,
            status_message: String::new(),
        })
    }

    /// Create state for decryption mode.
    pub fn new_decrypt(archive_path: &str, password: &str) -> std::io::Result<Self> {
        // Detect format from extension
        let format = if archive_path.ends_with(".babel.bin") {
            OutputFormat::Binary
        } else {
            OutputFormat::Text
        };

        let (total_data_entries, chunk_size, output_path) = match format {
            OutputFormat::Text => {
                let content = std::fs::read_to_string(archive_path)?;
                let (_, coords, _, cs) = crate::crypto::parse_archive(&content)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                let count = coords.len();
                let out = if archive_path.ends_with(".babel.txt") {
                    archive_path.replace(".babel.txt", ".dec")
                } else {
                    format!("{}.dec", archive_path)
                };
                (count, cs, out)
            }
            OutputFormat::Binary => {
                let data = std::fs::read(archive_path)?;
                let (_, _, coords, cs) = crate::codec::decode(&data)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                let count = coords.len();
                let out = archive_path.replace(".babel.bin", ".dec");
                (count, cs as usize, out)
            }
        };

        Ok(Self {
            source_data: Vec::new(),
            completed_chunks: 0,
            current_chunk: 0,
            total_chunks: total_data_entries,
            chunk_size,
            coordinates: Vec::new(),
            hash_lines: Self::init_hash_lines(),
            pointer_pos: 20,
            pointer_line_idx: 3,
            scan_count: 0,
            match_flash: 0,
            hash_rate: 0.0,
            compression_ratio: 0.0,
            elapsed_secs: 0.0,
            estimated_bin_bytes: 0,
            running: true,
            tick: 0,
            mode: Mode::Decrypt {
                archive_path: archive_path.to_string(),
                password: password.to_string(),
                format,
            },
            output_path,
            finished: false,
            status_message: String::new(),
        })
    }

    /// Pre-generate hash display lines for immediate visual on frame 1.
    fn init_hash_lines() -> Vec<String> {
        let mut lines = Vec::with_capacity(12);
        let mut h = blake3::hash(b"init_display_seed_babel");
        for _ in 0..12 {
            let mut line = String::with_capacity(512);
            for _ in 0..8 {
                h = blake3::hash(h.as_bytes());
                line.push_str(&h.to_hex().as_str()[..32]);
            }
            lines.push(line);
        }
        lines
    }
}