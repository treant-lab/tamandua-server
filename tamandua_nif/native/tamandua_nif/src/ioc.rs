use rustler::{Encoder, Env, NifResult, Term};
use serde::{Deserialize, Serialize};
use regex::Regex;
use std::net::IpAddr;
use std::str::FromStr;

use crate::{NifError, to_nif_result};

/// IOC match result
#[derive(Debug, Serialize, Deserialize)]
pub struct IocMatch {
    pub ioc_type: String,
    pub value: String,
    pub matched: bool,
    pub context: Option<String>,
}

impl Encoder for IocMatch {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        (
            &self.ioc_type,
            &self.value,
            self.matched,
            &self.context,
        ).encode(env)
    }
}

/// Extracted IOCs from text
#[derive(Debug, Serialize, Deserialize)]
pub struct ExtractedIocs {
    pub ips: Vec<String>,
    pub domains: Vec<String>,
    pub urls: Vec<String>,
    pub hashes: Vec<String>,
    pub emails: Vec<String>,
}

impl Encoder for ExtractedIocs {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        (
            &self.ips,
            &self.domains,
            &self.urls,
            &self.hashes,
            &self.emails,
        ).encode(env)
    }
}

/// Match IP address against IOC
///
/// ## Arguments
/// * `ip` - IP address string
/// * `ioc` - IOC pattern (exact IP or CIDR)
///
/// ## Returns
/// * `{:ok, matched}` - Boolean indicating match
/// * `{:error, message}` - Parse error
#[rustler::nif]
pub fn match_ip(ip: String, ioc: String) -> NifResult<bool> {
    let result = match_ip_impl(&ip, &ioc);
    to_nif_result(result)
}

fn match_ip_impl(ip: &str, ioc: &str) -> Result<bool, NifError> {
    let ip_addr = IpAddr::from_str(ip)
        .map_err(|e| NifError::Parse(format!("Invalid IP: {}", e)))?;

    // Check if IOC is CIDR notation
    if ioc.contains('/') {
        match_cidr(&ip_addr, ioc)
    } else {
        // Exact match
        let ioc_addr = IpAddr::from_str(ioc)
            .map_err(|e| NifError::Parse(format!("Invalid IOC IP: {}", e)))?;
        Ok(ip_addr == ioc_addr)
    }
}

fn match_cidr(ip: &IpAddr, cidr: &str) -> Result<bool, NifError> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(NifError::Parse("Invalid CIDR format".to_string()));
    }

    let network = IpAddr::from_str(parts[0])
        .map_err(|e| NifError::Parse(format!("Invalid CIDR network: {}", e)))?;

    let prefix_len: u8 = parts[1].parse()
        .map_err(|e| NifError::Parse(format!("Invalid CIDR prefix: {}", e)))?;

    match (ip, network) {
        (IpAddr::V4(ip_v4), IpAddr::V4(net_v4)) => {
            let ip_bits = u32::from(*ip_v4);
            let net_bits = u32::from(net_v4);
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u32 << (32 - prefix_len)
            };
            Ok((ip_bits & mask) == (net_bits & mask))
        }
        (IpAddr::V6(ip_v6), IpAddr::V6(net_v6)) => {
            let ip_bits = u128::from(*ip_v6);
            let net_bits = u128::from(net_v6);
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u128 << (128 - prefix_len)
            };
            Ok((ip_bits & mask) == (net_bits & mask))
        }
        _ => Ok(false),
    }
}

/// Match domain against IOC
///
/// ## Arguments
/// * `domain` - Domain name
/// * `ioc` - IOC pattern (exact or wildcard)
///
/// ## Returns
/// * `{:ok, matched}` - Boolean indicating match
#[rustler::nif]
pub fn match_domain(domain: String, ioc: String) -> NifResult<bool> {
    let result = match_domain_impl(&domain, &ioc);
    to_nif_result(result)
}

fn match_domain_impl(domain: &str, ioc: &str) -> Result<bool, NifError> {
    let domain_lower = domain.to_lowercase();
    let ioc_lower = ioc.to_lowercase();

    if ioc_lower.starts_with('*') {
        // Wildcard subdomain match
        let pattern = ioc_lower.trim_start_matches('*');
        Ok(domain_lower.ends_with(pattern))
    } else if ioc_lower.contains('*') {
        // General wildcard match
        let regex_pattern = ioc_lower
            .replace(".", "\\.")
            .replace("*", ".*");
        let re = Regex::new(&format!("^{}$", regex_pattern))
            .map_err(|e| NifError::Parse(format!("Invalid regex: {}", e)))?;
        Ok(re.is_match(&domain_lower))
    } else {
        // Exact match
        Ok(domain_lower == ioc_lower)
    }
}

/// Match hash against IOC
///
/// ## Arguments
/// * `hash` - Hash value (any type)
/// * `ioc` - IOC hash value
///
/// ## Returns
/// * `{:ok, matched}` - Boolean indicating match
#[rustler::nif]
pub fn match_hash(hash: String, ioc: String) -> NifResult<bool> {
    let result = match_hash_impl(&hash, &ioc);
    to_nif_result(result)
}

fn match_hash_impl(hash: &str, ioc: &str) -> Result<bool, NifError> {
    // Case-insensitive hash comparison
    Ok(hash.to_lowercase() == ioc.to_lowercase())
}

/// Extract IOCs from text
///
/// ## Arguments
/// * `text` - Text to extract IOCs from
///
/// ## Returns
/// * `{:ok, iocs}` - Extracted IOCs by type
#[rustler::nif]
pub fn extract_iocs(text: String) -> NifResult<ExtractedIocs> {
    let result = extract_iocs_impl(&text);
    to_nif_result(result)
}

fn extract_iocs_impl(text: &str) -> Result<ExtractedIocs, NifError> {
    // IP address regex (simplified)
    let ip_regex = Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        .map_err(|e| NifError::Parse(format!("IP regex error: {}", e)))?;

    // Domain regex
    let domain_regex = Regex::new(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
        .map_err(|e| NifError::Parse(format!("Domain regex error: {}", e)))?;

    // URL regex
    let url_regex = Regex::new(r"https?://[^\s]+")
        .map_err(|e| NifError::Parse(format!("URL regex error: {}", e)))?;

    // Hash regex (MD5, SHA1, SHA256)
    let hash_regex = Regex::new(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
        .map_err(|e| NifError::Parse(format!("Hash regex error: {}", e)))?;

    // Email regex
    let email_regex = Regex::new(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
        .map_err(|e| NifError::Parse(format!("Email regex error: {}", e)))?;

    let ips: Vec<String> = ip_regex
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect();

    let domains: Vec<String> = domain_regex
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .filter(|d| !ips.contains(d)) // Exclude IPs
        .collect();

    let urls: Vec<String> = url_regex
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect();

    let hashes: Vec<String> = hash_regex
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect();

    let emails: Vec<String> = email_regex
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect();

    Ok(ExtractedIocs {
        ips,
        domains,
        urls,
        hashes,
        emails,
    })
}

/// Match multiple IOCs against a list in batch
///
/// ## Arguments
/// * `values` - List of values to check
/// * `iocs` - List of IOC patterns
/// * `ioc_type` - Type of IOC ("ip", "domain", "hash")
///
/// ## Returns
/// * `{:ok, [matches]}` - List of match results
#[rustler::nif]
pub fn match_iocs_batch(
    values: Vec<String>,
    iocs: Vec<String>,
    ioc_type: String,
) -> NifResult<Vec<IocMatch>> {
    let result = match_iocs_batch_impl(&values, &iocs, &ioc_type);
    to_nif_result(result)
}

fn match_iocs_batch_impl(
    values: &[String],
    iocs: &[String],
    ioc_type: &str,
) -> Result<Vec<IocMatch>, NifError> {
    let mut matches = Vec::new();

    for value in values {
        for ioc in iocs {
            let matched = match ioc_type {
                "ip" => match_ip_impl(value, ioc)?,
                "domain" => match_domain_impl(value, ioc)?,
                "hash" => match_hash_impl(value, ioc)?,
                _ => return Err(NifError::InvalidInput(format!("Unknown IOC type: {}", ioc_type))),
            };

            if matched {
                matches.push(IocMatch {
                    ioc_type: ioc_type.to_string(),
                    value: value.clone(),
                    matched: true,
                    context: Some(ioc.clone()),
                });
                break; // Stop at first match for this value
            }
        }
    }

    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_ip_exact() {
        assert!(match_ip_impl("192.168.1.1", "192.168.1.1").unwrap());
        assert!(!match_ip_impl("192.168.1.1", "192.168.1.2").unwrap());
    }

    #[test]
    fn test_match_ip_cidr() {
        assert!(match_ip_impl("192.168.1.50", "192.168.1.0/24").unwrap());
        assert!(!match_ip_impl("192.168.2.50", "192.168.1.0/24").unwrap());
    }

    #[test]
    fn test_match_domain() {
        assert!(match_domain_impl("evil.com", "evil.com").unwrap());
        assert!(match_domain_impl("sub.evil.com", "*.evil.com").unwrap());
        assert!(!match_domain_impl("good.com", "evil.com").unwrap());
    }

    #[test]
    fn test_extract_iocs() {
        let text = "Connect to 192.168.1.1 or visit evil.com at http://evil.com/malware.exe";
        let iocs = extract_iocs_impl(text).unwrap();

        assert!(iocs.ips.contains(&"192.168.1.1".to_string()));
        assert!(iocs.domains.contains(&"evil.com".to_string()));
        assert_eq!(iocs.urls.len(), 1);
    }
}
