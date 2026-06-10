use rustler::{Encoder, Env, NifResult, Term, Binary};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, BufReader};
use std::path::Path;
use serde::{Deserialize, Serialize};

use crate::{NifError, to_nif_result};

/// Section entropy analysis result
#[derive(Debug, Serialize, Deserialize)]
pub struct SectionEntropy {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    pub is_packed: bool,
}

impl Encoder for SectionEntropy {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        (
            &self.name,
            self.offset,
            self.size,
            self.entropy,
            self.is_packed,
        ).encode(env)
    }
}

/// File analysis result
#[derive(Debug, Serialize, Deserialize)]
pub struct FileAnalysis {
    pub entropy: f64,
    pub is_packed: bool,
    pub file_size: u64,
    pub high_entropy_regions: Vec<HighEntropyRegion>,
}

impl Encoder for FileAnalysis {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        (
            self.entropy,
            self.is_packed,
            self.file_size,
            &self.high_entropy_regions.iter().map(|r| {
                (r.offset, r.size, r.entropy)
            }).collect::<Vec<_>>(),
        ).encode(env)
    }
}

/// High entropy region in a file
#[derive(Debug, Serialize, Deserialize)]
pub struct HighEntropyRegion {
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
}

/// Calculate Shannon entropy of binary data
///
/// ## Arguments
/// * `data` - Binary data to analyze
///
/// ## Returns
/// * `{:ok, entropy}` - Entropy value (0.0 - 8.0)
#[rustler::nif]
pub fn calculate(data: Binary) -> NifResult<f64> {
    let result = calculate_entropy(data.as_slice());
    to_nif_result(result)
}

fn calculate_entropy(data: &[u8]) -> Result<f64, NifError> {
    if data.is_empty() {
        return Ok(0.0);
    }

    let mut byte_counts: HashMap<u8, usize> = HashMap::new();

    // Count byte frequencies
    for &byte in data {
        *byte_counts.entry(byte).or_insert(0) += 1;
    }

    // Calculate Shannon entropy
    let len = data.len() as f64;
    let mut entropy = 0.0;

    for count in byte_counts.values() {
        let probability = *count as f64 / len;
        entropy -= probability * probability.log2();
    }

    Ok(entropy)
}

/// Calculate Shannon entropy of a file
///
/// ## Arguments
/// * `file_path` - Path to file
///
/// ## Returns
/// * `{:ok, entropy}` - Entropy value (0.0 - 8.0)
/// * `{:error, message}` - IO error
#[rustler::nif]
pub fn calculate_file(file_path: String) -> NifResult<f64> {
    let result = calculate_file_entropy(&file_path);
    to_nif_result(result)
}

fn calculate_file_entropy(file_path: &str) -> Result<f64, NifError> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Err(NifError::NotFound(format!("File not found: {}", file_path)));
    }

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut byte_counts: HashMap<u8, usize> = HashMap::new();
    let mut total_bytes = 0usize;

    let mut buffer = [0u8; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        for &byte in &buffer[..n] {
            *byte_counts.entry(byte).or_insert(0) += 1;
            total_bytes += 1;
        }
    }

    if total_bytes == 0 {
        return Ok(0.0);
    }

    let len = total_bytes as f64;
    let mut entropy = 0.0;

    for count in byte_counts.values() {
        let probability = *count as f64 / len;
        entropy -= probability * probability.log2();
    }

    Ok(entropy)
}

/// Calculate entropy for sections of data
///
/// ## Arguments
/// * `data` - Binary data to analyze
/// * `section_size` - Size of each section in bytes
///
/// ## Returns
/// * `{:ok, [entropies]}` - List of entropy values per section
#[rustler::nif]
pub fn calculate_sections(data: Binary, section_size: usize) -> NifResult<Vec<f64>> {
    let result = calculate_sections_impl(data.as_slice(), section_size);
    to_nif_result(result)
}

fn calculate_sections_impl(data: &[u8], section_size: usize) -> Result<Vec<f64>, NifError> {
    if section_size == 0 {
        return Err(NifError::InvalidInput("Section size must be > 0".to_string()));
    }

    let mut entropies = Vec::new();

    for chunk in data.chunks(section_size) {
        let entropy = calculate_entropy(chunk)?;
        entropies.push(entropy);
    }

    Ok(entropies)
}

/// Detect if binary data is packed/compressed
///
/// Uses entropy threshold and other heuristics to detect packing.
///
/// ## Arguments
/// * `data` - Binary data to analyze
///
/// ## Returns
/// * `{:ok, is_packed}` - Boolean indicating if likely packed
#[rustler::nif]
pub fn detect_packed(data: Binary) -> NifResult<bool> {
    let result = detect_packed_impl(data.as_slice());
    to_nif_result(result)
}

fn detect_packed_impl(data: &[u8]) -> Result<bool, NifError> {
    if data.is_empty() {
        return Ok(false);
    }

    let entropy = calculate_entropy(data)?;

    // High entropy threshold (7.0+) indicates likely packed/encrypted
    const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;

    if entropy > HIGH_ENTROPY_THRESHOLD {
        return Ok(true);
    }

    // Check for high entropy sections
    let section_size = (data.len() / 10).max(1024); // Divide into ~10 sections
    let section_entropies = calculate_sections_impl(data, section_size)?;

    let high_entropy_sections = section_entropies
        .iter()
        .filter(|&&e| e > HIGH_ENTROPY_THRESHOLD)
        .count();

    // If more than 50% of sections have high entropy, likely packed
    Ok(high_entropy_sections as f64 / section_entropies.len() as f64 > 0.5)
}

/// Comprehensive file analysis including entropy and packing detection
///
/// ## Arguments
/// * `file_path` - Path to file
///
/// ## Returns
/// * `{:ok, analysis}` - File analysis result
/// * `{:error, message}` - IO error
#[rustler::nif]
pub fn analyze_file(file_path: String) -> NifResult<FileAnalysis> {
    let result = analyze_file_impl(&file_path);
    to_nif_result(result)
}

fn analyze_file_impl(file_path: &str) -> Result<FileAnalysis, NifError> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Err(NifError::NotFound(format!("File not found: {}", file_path)));
    }

    // Read entire file (with size limit for safety)
    const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB limit
    let metadata = std::fs::metadata(path)?;
    let file_size = metadata.len();

    if file_size > MAX_FILE_SIZE {
        return Err(NifError::InvalidInput(
            format!("File too large: {} bytes (max: {} bytes)", file_size, MAX_FILE_SIZE)
        ));
    }

    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    // Calculate overall entropy
    let entropy = calculate_entropy(&data)?;

    // Detect packing
    let is_packed = detect_packed_impl(&data)?;

    // Find high entropy regions
    let chunk_size = 4096;
    let mut high_entropy_regions = Vec::new();
    const HIGH_ENTROPY_THRESHOLD: f64 = 7.5;

    for (i, chunk) in data.chunks(chunk_size).enumerate() {
        let chunk_entropy = calculate_entropy(chunk)?;
        if chunk_entropy > HIGH_ENTROPY_THRESHOLD {
            high_entropy_regions.push(HighEntropyRegion {
                offset: (i * chunk_size) as u64,
                size: chunk.len() as u64,
                entropy: chunk_entropy,
            });
        }
    }

    Ok(FileAnalysis {
        entropy,
        is_packed,
        file_size,
        high_entropy_regions,
    })
}

/// Detect encrypted or compressed sections in PE files
///
/// ## Arguments
/// * `pe_data` - Binary PE file data
///
/// ## Returns
/// * `{:ok, [sections]}` - List of section analyses
/// * `{:error, message}` - Parse error
#[rustler::nif]
pub fn analyze_pe_sections(pe_data: Binary) -> NifResult<Vec<SectionEntropy>> {
    let result = analyze_pe_sections_impl(pe_data.as_slice());
    to_nif_result(result)
}

fn analyze_pe_sections_impl(pe_data: &[u8]) -> Result<Vec<SectionEntropy>, NifError> {
    // Placeholder implementation
    // Real implementation would parse PE section headers
    if pe_data.len() < 64 {
        return Err(NifError::InvalidInput("Invalid PE file".to_string()));
    }

    // Check for PE signature
    if &pe_data[0..2] != b"MZ" {
        return Err(NifError::InvalidInput("Not a valid PE file".to_string()));
    }

    // Mock section analysis
    // Real implementation would:
    // 1. Parse PE headers
    // 2. Locate section table
    // 3. Analyze entropy of each section
    let mut sections = Vec::new();

    // Analyze first 10KB as mock section
    let section_data = &pe_data[0..10240.min(pe_data.len())];
    let entropy = calculate_entropy(section_data)?;

    sections.push(SectionEntropy {
        name: ".text".to_string(),
        offset: 0,
        size: section_data.len() as u64,
        entropy,
        is_packed: entropy > 7.0,
    });

    Ok(sections)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_zero() {
        let data = vec![0u8; 100];
        let entropy = calculate_entropy(&data).unwrap();
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_entropy_uniform() {
        let data: Vec<u8> = (0..=255).collect();
        let entropy = calculate_entropy(&data).unwrap();
        assert!(entropy > 7.9); // Close to maximum entropy (8.0)
    }

    #[test]
    fn test_packed_detection() {
        // High entropy data (simulating packed executable)
        let high_entropy_data: Vec<u8> = (0..=255).cycle().take(10000).collect();
        assert!(detect_packed_impl(&high_entropy_data).unwrap());

        // Low entropy data (simulating normal executable)
        let low_entropy_data = vec![0u8; 10000];
        assert!(!detect_packed_impl(&low_entropy_data).unwrap());
    }
}
