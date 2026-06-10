use rustler::{Encoder, Env, NifResult, Term};

mod yara_scanner;
mod hash;
mod entropy;
mod sigma;
mod ioc;

rustler::init!(
    "Elixir.TamanduaServer.Native",
    [
        // YARA functions
        yara_scanner::compile_rules,
        yara_scanner::scan_bytes,
        yara_scanner::scan_file,
        yara_scanner::list_rules,

        // Hashing functions
        hash::sha256,
        hash::sha256_file,
        hash::sha1,
        hash::sha1_file,
        hash::md5,
        hash::md5_file,
        hash::ssdeep,
        hash::multi_hash,
        hash::multi_hash_file,

        // Entropy functions
        entropy::calculate,
        entropy::calculate_file,
        entropy::calculate_sections,
        entropy::detect_packed,
        entropy::analyze_file,

        // Sigma functions
        sigma::parse_rule,
        sigma::match_event,
        sigma::compile_rules_batch,
        sigma::validate_rule,

        // IOC functions
        ioc::match_ip,
        ioc::match_domain,
        ioc::match_hash,
        ioc::extract_iocs,
        ioc::match_iocs_batch,
    ]
);

/// Common error type for NIF operations
#[derive(Debug, thiserror::Error)]
pub enum NifError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("YARA error: {0}")]
    Yara(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Not found: {0}")]
    NotFound(String),
}

impl Encoder for NifError {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let error_tuple = (
            rustler::types::atom::error(),
            format!("{}", self),
        );
        error_tuple.encode(env)
    }
}

/// Helper to convert Result to NifResult
pub fn to_nif_result<T: Encoder>(result: Result<T, NifError>) -> NifResult<T> {
    result.map_err(|e| rustler::Error::Term(Box::new(e)))
}
