//! Codec module — minimal binary output format with ANS-based entropy coding.
//!
//! # Archive format (.babel.bin)
//!
//! ```text
//! [4 bytes]  Magic: b"BAB\x01"
//! [1 byte]   ChunkSize (1..=4)
//! [16 bytes] Salt
//! [32 bytes] BLAKE3 checksum of original data
//! [4 bytes]  u32 LE: byte length of the ANS-coded payload
//! [N bytes]  ANS-coded payload (see below)
//! ```
//!
//! # Payload encoding
//!
//! The coordinate stream is delta-encoded using **Golomb-Rice coding**
//! and bit-packed:
//!
//! - `ZeroRun` (misses) is Rice-encoded (unary quotient + binary remainder).
//! - `Index` is encoded as a fixed 5-bit integer.
//!
//! The resulting bit-packed byte stream is then compressed with a **range-coder**
//! (arithmetic coding variant) using an adaptive **Order-1 context model** —
//! achieving optimal entropy compression by capturing structural dependencies
//! left over by the bit-packing.

use crate::crypto::MatchCoord;

// ── Magic & version ──────────────────────────────────────────────────────────

pub const MAGIC: &[u8; 4] = b"BAB\x01";

// ── Public API ───────────────────────────────────────────────────────────────

/// Encode coordinates to a compact binary archive.
pub fn encode(
    salt: &[u8; 16],
    checksum_hex: &str,
    coords: &[MatchCoord],
    chunk_size: u8,
) -> Vec<u8> {
    // 1. Serialise coords to raw bit-packed bytes
    let raw = coords_to_bytes(coords, chunk_size);

    // 2. Range-code the raw bytes using Order-1 model
    let coded = range_encode(&raw);

    // 3. Assemble archive
    let mut out = Vec::with_capacity(4 + 1 + 16 + 32 + 4 + coded.len());
    out.extend_from_slice(MAGIC);
    out.push(chunk_size);
    out.extend_from_slice(salt);
    
    let cs_bytes = hex_to_bytes32(checksum_hex);
    out.extend_from_slice(&cs_bytes);
    
    let coded_len = coded.len() as u32;
    out.extend_from_slice(&coded_len.to_le_bytes());
    out.extend_from_slice(&coded);
    out
}

/// Decode a binary archive back to its components.
pub fn decode(data: &[u8]) -> Result<([u8; 16], String, Vec<MatchCoord>, u8), String> {
    if data.len() < 4 + 1 + 16 + 32 + 4 {
        return Err("Archive too short".into());
    }
    if &data[..4] != MAGIC {
        return Err(format!(
            "Bad magic: {:?} (expected {:?})",
            &data[..4],
            MAGIC
        ));
    }
    let chunk_size = data[4];
    let salt: [u8; 16] = data[5..21].try_into().unwrap();
    let cs_bytes: [u8; 32] = data[21..53].try_into().unwrap();
    let checksum_hex = bytes32_to_hex(&cs_bytes);
    let coded_len = u32::from_le_bytes(data[53..57].try_into().unwrap()) as usize;
    if data.len() < 57 + coded_len {
        return Err("Archive truncated".into());
    }
    let coded = &data[57..57 + coded_len];
    
    let raw = range_decode(coded)?;
    let coords = bytes_to_coords(&raw, chunk_size)?;
    
    Ok((salt, checksum_hex, coords, chunk_size))
}

// ── Coord serialisation (Golomb-Rice & Bit-packing) ──────────────────────────

struct BitWriter {
    bytes: Vec<u8>,
    buffer: u64,
    bits: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self { bytes: Vec::new(), buffer: 0, bits: 0 }
    }

    fn write(&mut self, val: u64, bits: u8) {
        self.buffer |= val << self.bits;
        self.bits += bits;
        while self.bits >= 8 {
            self.bytes.push((self.buffer & 0xFF) as u8);
            self.buffer >>= 8;
            self.bits -= 8;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bits > 0 {
            self.bytes.push((self.buffer & 0xFF) as u8);
        }
        self.bytes
    }
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    buffer: u64,
    bits: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0, buffer: 0, bits: 0 }
    }

    fn read(&mut self, bits: u8) -> Result<u64, String> {
        while self.bits < bits {
            if self.pos >= self.data.len() {
                if self.bits == 0 { return Err("EOF".into()); }
                break;
            }
            self.buffer |= (self.data[self.pos] as u64) << self.bits;
            self.bits += 8;
            self.pos += 1;
        }
        if self.bits < bits {
            return Err("EOF".into());
        }
        let mask = if bits == 64 { !0 } else { (1 << bits) - 1 };
        let val = self.buffer & mask;
        self.buffer >>= bits;
        self.bits -= bits;
        Ok(val)
    }

    fn read_bit(&mut self) -> Result<u64, String> {
        self.read(1)
    }
}

fn get_rice_k(chunk_size: u8) -> u8 {
    let avg = crate::crypto::avg_hashes_per_chunk(chunk_size as usize);
    if avg <= 1.0 { return 0; }
    (avg * std::f64::consts::LN_2).log2().max(0.0).round() as u8
}

fn coords_to_bytes(coords: &[MatchCoord], chunk_size: u8) -> Vec<u8> {
    let k = get_rice_k(chunk_size);
    let mut writer = BitWriter::new();
    
    // Store number of coords so decode knows when to stop
    writer.write(coords.len() as u64, 32);

    for coord in coords {
        let q = coord.misses >> k;
        let r = coord.misses & ((1 << k) - 1);
        
        // Unary quotient: q ones, followed by a zero
        for _ in 0..q {
            writer.write(1, 1);
        }
        writer.write(0, 1);
        
        // Binary remainder
        if k > 0 {
            writer.write(r, k);
        }
        
        // Fixed 5-bit index (0..31)
        writer.write(coord.index as u64, 5);
    }
    
    writer.finish()
}

fn bytes_to_coords(data: &[u8], chunk_size: u8) -> Result<Vec<MatchCoord>, String> {
    let k = get_rice_k(chunk_size);
    let mut reader = BitReader::new(data);
    
    let len = reader.read(32)? as usize;
    let mut coords = Vec::with_capacity(len);
    
    for _ in 0..len {
        let mut q = 0;
        loop {
            let bit = reader.read_bit()?;
            if bit == 0 { break; }
            q += 1;
        }
        let r = if k > 0 { reader.read(k)? } else { 0 };
        let misses = (q << k) | r;
        let index = reader.read(5)? as usize;
        
        coords.push(MatchCoord { misses, index });
    }
    
    Ok(coords)
}

// ── Adaptive range coder (Order-1 arithmetic coding) ─────────────────────────

const MODEL_TOTAL: u32 = 1 << 14; // 16384
const MODEL_ALPHA: u32 = 257; // alphabet + 1 (EOF symbol at 256)
const EOF_SYM: usize = 256;

/// Adaptive frequency model for a single context.
struct Model {
    freq: [u32; MODEL_ALPHA as usize + 1],
    cum: [u32; MODEL_ALPHA as usize + 1],
    total: u32,
}

impl Model {
    fn new() -> Self {
        let mut freq = [1u32; MODEL_ALPHA as usize + 1];
        freq[MODEL_ALPHA as usize] = 0; // sentinel
        let mut cum = [0u32; MODEL_ALPHA as usize + 1];
        let mut t = 0u32;
        for i in 0..MODEL_ALPHA as usize {
            cum[i] = t;
            t += freq[i];
        }
        cum[MODEL_ALPHA as usize] = t;
        Model { freq, cum, total: t }
    }

    fn update(&mut self, sym: usize) {
        self.freq[sym] += 1;
        self.total += 1;
        
        let mut acc = 0u32;
        for i in 0..MODEL_ALPHA as usize {
            self.cum[i] = acc;
            acc += self.freq[i];
        }
        self.cum[MODEL_ALPHA as usize] = acc;
        self.total = acc;

        if self.total >= MODEL_TOTAL {
            self.total = 0;
            for i in 0..MODEL_ALPHA as usize {
                self.freq[i] = (self.freq[i] + 1) >> 1;
                self.cum[i] = self.total;
                self.total += self.freq[i];
            }
            self.cum[MODEL_ALPHA as usize] = self.total;
        }
    }

    fn sym_range(&self, sym: usize) -> (u32, u32, u32) {
        (self.cum[sym], self.cum[sym] + self.freq[sym], self.total)
    }

    fn find_sym(&self, target: u32) -> usize {
        for i in 0..MODEL_ALPHA as usize {
            if self.cum[i + 1] > target {
                return i;
            }
        }
        MODEL_ALPHA as usize - 1
    }
}

/// Order-1 Context Model (array of 257 Models).
struct Order1Model {
    models: Vec<Model>,
}

impl Order1Model {
    fn new() -> Self {
        let mut models = Vec::with_capacity(257);
        for _ in 0..257 {
            models.push(Model::new());
        }
        Self { models }
    }
}

struct RangeEncoder {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u32,
    out: Vec<u8>,
}

impl RangeEncoder {
    fn new() -> Self {
        Self { low: 0, range: 0xFFFF_FFFF, cache: 0, cache_size: 1, out: Vec::new() }
    }
    
    fn shift_low(&mut self) {
        let low_u32 = self.low as u32;
        let top = (self.low >> 32) as u8;
        if low_u32 < 0xFF00_0000 || top != 0 {
            let mut temp = self.cache;
            loop {
                self.out.push(temp.wrapping_add(top));
                temp = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 { break; }
            }
            self.cache = (low_u32 >> 24) as u8;
        }
        self.cache_size += 1;
        self.low = (low_u32 << 8) as u64;
    }

    fn encode(&mut self, cum_low: u32, freq: u32, total: u32) {
        self.range /= total;
        self.low += (cum_low * self.range) as u64;
        self.range *= freq;
        
        while self.range < 0x0100_0000 {
            self.shift_low();
            self.range <<= 8;
        }
    }
    
    fn flush(&mut self) {
        for _ in 0..5 {
            self.shift_low();
        }
    }
}

struct RangeDecoder<'a> {
    code: u32,
    range: u32,
    data: &'a [u8],
    pos: usize,
}

impl<'a> RangeDecoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        let mut code = 0;
        let mut pos = 0;
        pos += 1; // skip dummy byte
        for _ in 0..4 {
            code = (code << 8) | Self::read_byte(data, &mut pos);
        }
        Self { code, range: 0xFFFF_FFFF, data, pos }
    }
    
    fn read_byte(data: &[u8], pos: &mut usize) -> u32 {
        if *pos < data.len() {
            let b = data[*pos] as u32;
            *pos += 1;
            b
        } else {
            0
        }
    }
    
    fn get_freq(&self, total: u32) -> u32 {
        self.code / (self.range / total)
    }
    
    fn decode(&mut self, cum_low: u32, freq: u32, total: u32) {
        let r = self.range / total;
        self.code = self.code.wrapping_sub(cum_low * r);
        self.range = freq * r;
        
        while self.range < 0x0100_0000 {
            self.code = (self.code << 8) | Self::read_byte(self.data, &mut self.pos);
            self.range <<= 8;
        }
    }
}

fn range_encode(data: &[u8]) -> Vec<u8> {
    let mut o1model = Order1Model::new();
    let mut enc = RangeEncoder::new();
    let mut last_byte: usize = 0;

    for &b in data {
        let sym = b as usize;
        let model = &mut o1model.models[last_byte];
        let (cl, ch, total) = model.sym_range(sym);
        enc.encode(cl, ch - cl, total);
        model.update(sym);
        last_byte = sym;
    }
    
    let model = &mut o1model.models[last_byte];
    let (cl, ch, total) = model.sym_range(EOF_SYM);
    enc.encode(cl, ch - cl, total);
    enc.flush();
    enc.out
}

fn range_decode(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let mut o1model = Order1Model::new();
    let mut dec = RangeDecoder::new(data);
    let mut out = Vec::new();
    let mut last_byte: usize = 0;

    loop {
        let model = &mut o1model.models[last_byte];
        let total = model.total;
        let target = dec.get_freq(total);
        let sym = model.find_sym(target.min(total - 1));
        let (cl, ch, _) = model.sym_range(sym);
        
        dec.decode(cl, ch - cl, total);
        model.update(sym);
        
        if sym == EOF_SYM { break; }
        out.push(sym as u8);
        last_byte = sym;
    }
    Ok(out)
}

// ── Hex helpers ──────────────────────────────────────────────────────────────

fn hex_to_bytes32(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
        .collect();
    let len = bytes.len().min(32);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

fn bytes32_to_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Size estimation helper ────────────────────────────────────────────────────

/// Estimate the final archive size for a given coordinate stream.
pub fn estimate_size(coords: &[MatchCoord], chunk_size: u8) -> (usize, usize) {
    let raw = coords_to_bytes(coords, chunk_size);
    let raw_len = raw.len();
    let coded = range_encode(&raw);
    (raw_len, 4 + 1 + 16 + 32 + 4 + coded.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MatchCoord;

    #[test]
    fn round_trip_coords() {
        let coords = vec![
            MatchCoord { misses: 0, index: 3 },
            MatchCoord { misses: 127, index: 15 },
            MatchCoord { misses: 16383, index: 0 },
        ];
        let raw = coords_to_bytes(&coords, 2);
        let decoded = bytes_to_coords(&raw, 2).unwrap();
        assert_eq!(coords.len(), decoded.len());
        for (a, b) in coords.iter().zip(decoded.iter()) {
            assert_eq!(a.misses, b.misses);
            assert_eq!(a.index, b.index);
        }
    }

    #[test]
    fn round_trip_range_coder() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        let coded = range_encode(&data);
        let decoded = range_decode(&coded).unwrap();
        if data != decoded {
            for i in 0..data.len().max(decoded.len()) {
                let d = data.get(i).map(|&x| x as i32).unwrap_or(-1);
                let c = decoded.get(i).map(|&x| x as i32).unwrap_or(-1);
                if d != c {
                    panic!("Mismatch at index {}: expected {}, got {}", i, d, c);
                }
            }
        }
    }

    #[test]
    fn full_archive_round_trip() {
        let salt = [0xABu8; 16];
        let checksum = "a".repeat(64);
        let coords = vec![
            MatchCoord { misses: 500, index: 7 },
            MatchCoord { misses: 1, index: 15 },
        ];
        let archive = encode(&salt, &checksum, &coords, 1);
        let (s2, cs2, c2, sz2) = decode(&archive).unwrap();
        assert_eq!(salt, s2);
        assert_eq!(checksum, cs2);
        assert_eq!(sz2, 1);
        assert_eq!(coords.len(), c2.len());
    }
}