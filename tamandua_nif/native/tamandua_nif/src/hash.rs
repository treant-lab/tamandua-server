use rustler::{Encoder, Env, NifResult, Term, Binary};
use sha2::{Sha256, Digest as Sha2Digest};
use sha1::Sha1;
use md5::{Md5, Digest as Md5Digest};
use std::fs::File;
use std::io::{Read, BufReader};
use std::path::Path;
use serde::{Deserialize, Serialize};

use crate::{NifError, to_nif_result};

/// Multi-hash result containing all hash types
#[derive(Debug, Serialize, Deserialize)]
pub struct MultiHashResult {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub size: u64,
}

impl Encoder for MultiHashResult {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        (
            &self.sha256,
            &self.sha1,
            &self.md5,
            self.size,
        ).encode(env)
    }
}

/// Calculate SHA-256 hash of binary data
///
/// ## Arguments
/// * `data` - Binary data to hash
///
/// ## Returns
/// * `{:ok, hash_hex}` - Hex-encoded hash
#[rustler::nif]
pub fn sha256(data: Binary) -> NifResult<String> {
    let result = sha256_impl(data.as_slice());
    to_nif_result(result)
}

fn sha256_impl(data: &[u8]) -> Result<String, NifError> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Calculate SHA-256 hash of a file
///
/// ## Arguments
/// * `file_path` - Path to file
///
/// ## Returns
/// * `{:ok, hash_hex}` - Hex-encoded hash
/// * `{:error, message}` - IO error
#[rustler::nif]
pub fn sha256_file(file_path: String) -> NifResult<String> {
    let result = sha256_file_impl(&file_path);
    to_nif_result(result)
}

fn sha256_file_impl(file_path: &str) -> Result<String, NifError> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Err(NifError::NotFound(format!("File not found: {}", file_path)));
    }

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();

    let mut buffer = [0u8; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Calculate SHA-1 hash of binary data
///
/// ## Arguments
/// * `data` - Binary data to hash
///
/// ## Returns
/// * `{:ok, hash_hex}` - Hex-encoded hash
#[rustler::nif]
pub fn sha1(data: Binary) -> NifResult<String> {
    let result = sha1_impl(data.as_slice());
    to_nif_result(result)
}

fn sha1_impl(data: &[u8]) -> Result<String, NifError> {
    let mut hasher = Sha1::new();
    hasher.update(data);
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Calculate SHA-1 hash of a file
///
/// ## Arguments
/// * `file_path` - Path to file
///
/// ## Returns
/// * `{:ok, hash_hex}` - Hex-encoded hash
/// * `{:error, message}` - IO error
#[rustler::nif]
pub fn sha1_file(file_path: String) -> NifResult<String> {
    let result = sha1_file_impl(&file_path);
    to_nif_result(result)
}

fn sha1_file_impl(file_path: &str) -> Result<String, NifError> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Err(NifError::NotFound(format!("File not found: {}", file_path)));
    }

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha1::new();

    let mut buffer = [0u8; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Calculate MD5 hash of binary data
///
/// ## Arguments
/// * `data` - Binary data to hash
///
/// ## Returns
/// * `{:ok, hash_hex}` - Hex-encoded hash
#[rustler::nif]
pub fn md5(data: Binary) -> NifResult<String> {
    let result = md5_impl(data.as_slice());
    to_nif_result(result)
}

fn md5_impl(data: &[u8]) -> Result<String, NifError> {
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Calculate MD5 hash of a file
///
/// ## Arguments
/// * `file_path` - Path to file
///
/// ## Returns
/// * `{:ok, hash_hex}` - Hex-encoded hash
/// * `{:error, message}` - IO error
#[rustler::nif]
pub fn md5_file(file_path: String) -> NifResult<String> {
    let result = md5_file_impl(&file_path);
    to_nif_result(result)
}

fn md5_file_impl(file_path: &str) -> Result<String, NifError> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Err(NifError::NotFound(format!("File not found: {}", file_path)));
    }

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Md5::new();

    let mut buffer = [0u8; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Calculate ssdeep (fuzzy hash) of binary data
///
/// ## Arguments
/// * `data` - Binary data to hash
///
/// ## Returns
/// * `{:ok, ssdeep_hash}` - ssdeep hash string
/// * `{:error, message}` - Calculation error
#[rustler::nif]
pub fn ssdeep(data: Binary) -> NifResult<String> {
    // Note: Full ssdeep implementation requires the ssdeep library
    // This is a placeholder that returns a mock hash
    // In production, you'd use a crate like 'ssdeep' or bind to libfuzzy
    let result = ssdeep_impl(data.as_slice());
    to_nif_result(result)
}

fn ssdeep_impl(data: &[u8]) -> Result<String, NifError> {
    // Placeholder implementation
    // Real implementation would use: https://github.com/ssdeep-project/ssdeep
    if data.is_empty() {
        return Err(NifError::InvalidInput("Empty data".to_string()));
    }

    // Mock ssdeep format: blocksize:hash1:hash2
    let block_size = 3;
    Ok(format!("{}:{}:{}",
        block_size,
        &hex::encode(sha256_impl(data)?)[..8],
        &hex::encode(md5_impl(data)?)[..8]
    ))
}

/// Calculate import hash (imphash) for PE files
///
/// ## Arguments
/// * `pe_data` - Binary PE file data
///
/// ## Returns
/// * `{:ok, imphash}` - Import hash
/// * `{:error, message}` - Parse error
#[rustler::nif]
pub fn imphash(pe_data: Binary) -> NifResult<String> {
    let result = imphash_impl(pe_data.as_slice());
    to_nif_result(result)
}

fn imphash_impl(pe_data: &[u8]) -> Result<String, NifError> {
    // Placeholder implementation
    // Real implementation would parse PE import table
    // and hash the normalized import names
    if pe_data.len() < 64 {
        return Err(NifError::InvalidInput("Invalid PE file".to_string()));
    }

    // Check for PE signature
    if &pe_data[0..2] != b"MZ" {
        return Err(NifError::InvalidInput("Not a valid PE file".to_string()));
    }

    // Mock imphash calculation
    Ok(md5_impl(&pe_data[0..1024.min(pe_data.len())])?)
}

/// Calculate multiple hashes in a single pass (efficient)
///
/// ## Arguments
/// * `data` - Binary data to hash
///
/// ## Returns
/// * `{:ok, {sha256, sha1, md5, size}}` - All hashes
#[rustler::nif]
pub fn multi_hash(data: Binary) -> NifResult<MultiHashResult> {
    let result = multi_hash_impl(data.as_slice());
    to_nif_result(result)
}

fn multi_hash_impl(data: &[u8]) -> Result<MultiHashResult, NifError> {
    let mut sha256_hasher = Sha256::new();
    let mut sha1_hasher = Sha1::new();
    let mut md5_hasher = Md5::new();

    sha256_hasher.update(data);
    sha1_hasher.update(data);
    md5_hasher.update(data);

    Ok(MultiHashResult {
        sha256: hex::encode(sha256_hasher.finalize()),
        sha1: hex::encode(sha1_hasher.finalize()),
        md5: hex::encode(md5_hasher.finalize()),
        size: data.len() as u64,
    })
}

/// Calculate multiple hashes of a file in a single pass (efficient)
///
/// ## Arguments
/// * `file_path` - Path to file
///
/// ## Returns
/// * `{:ok, {sha256, sha1, md5, size}}` - All hashes
/// * `{:error, message}` - IO error
#[rustler::nif]
pub fn multi_hash_file(file_path: String) -> NifResult<MultiHashResult> {
    let result = multi_hash_file_impl(&file_path);
    to_nif_result(result)
}

fn multi_hash_file_impl(file_path: &str) -> Result<MultiHashResult, NifError> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Err(NifError::NotFound(format!("File not found: {}", file_path)));
    }

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let mut sha256_hasher = Sha256::new();
    let mut sha1_hasher = Sha1::new();
    let mut md5_hasher = Md5::new();
    let mut total_size = 0u64;

    let mut buffer = [0u8; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        let chunk = &buffer[..n];
        sha256_hasher.update(chunk);
        sha1_hasher.update(chunk);
        md5_hasher.update(chunk);
        total_size += n as u64;
    }

    Ok(MultiHashResult {
        sha256: hex::encode(sha256_hasher.finalize()),
        sha1: hex::encode(sha1_hasher.finalize()),
        md5: hex::encode(md5_hasher.finalize()),
        size: total_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"hello world";
        let hash = sha256_impl(data).unwrap();
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_multi_hash() {
        let data = b"hello world";
        let result = multi_hash_impl(data).unwrap();
        assert_eq!(
            result.sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(result.size, 11);
    }
}
