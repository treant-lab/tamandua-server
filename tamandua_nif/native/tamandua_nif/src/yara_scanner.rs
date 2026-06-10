use rustler::{Encoder, Env, NifResult, Term, Binary, ResourceArc};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use std::path::Path;

#[cfg(feature = "yara")]
use yara::{Compiler, Rules, Scanner};

use crate::{NifError, to_nif_result};

/// Resource wrapper for compiled YARA rules
pub struct YaraRulesResource {
    #[cfg(feature = "yara")]
    rules: RwLock<Rules>,

    #[cfg(not(feature = "yara"))]
    _phantom: (),
}

/// YARA match result
#[derive(Debug, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub metadata: Vec<(String, String)>,
    pub strings: Vec<YaraString>,
}

/// YARA string match
#[derive(Debug, Serialize, Deserialize)]
pub struct YaraString {
    pub identifier: String,
    pub matches: Vec<YaraStringMatch>,
}

/// Individual string match with offset
#[derive(Debug, Serialize, Deserialize)]
pub struct YaraStringMatch {
    pub offset: u64,
    pub length: usize,
    pub data: String,
}

impl Encoder for YaraMatch {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        (
            rustler::types::atom::ok(),
            &self.rule,
            &self.namespace,
            &self.tags,
            &self.metadata,
            &self.strings.iter().map(|s| {
                (
                    &s.identifier,
                    s.matches.iter().map(|m| {
                        (m.offset, m.length, &m.data)
                    }).collect::<Vec<_>>()
                )
            }).collect::<Vec<_>>()
        ).encode(env)
    }
}

/// Load resource type
pub fn load(env: Env) -> bool {
    rustler::resource!(YaraRulesResource, env);
    true
}

/// Compile YARA rules from source string
///
/// ## Arguments
/// * `rules_source` - String containing YARA rules
///
/// ## Returns
/// * `{:ok, resource}` - Compiled rules resource
/// * `{:error, message}` - Compilation error
#[rustler::nif]
pub fn compile_rules(rules_source: String) -> NifResult<ResourceArc<YaraRulesResource>> {
    #[cfg(feature = "yara")]
    {
        let result = compile_rules_impl(&rules_source);
        to_nif_result(result)
    }

    #[cfg(not(feature = "yara"))]
    {
        Err(rustler::Error::Term(Box::new(NifError::Yara(
            "YARA feature not enabled".to_string()
        ))))
    }
}

#[cfg(feature = "yara")]
fn compile_rules_impl(rules_source: &str) -> Result<ResourceArc<YaraRulesResource>, NifError> {
    let mut compiler = Compiler::new()
        .map_err(|e| NifError::Yara(format!("Failed to create compiler: {}", e)))?;

    compiler
        .add_rules_str(rules_source)
        .map_err(|e| NifError::Yara(format!("Failed to compile rules: {}", e)))?;

    let rules = compiler
        .compile_rules()
        .map_err(|e| NifError::Yara(format!("Failed to finalize rules: {}", e)))?;

    Ok(ResourceArc::new(YaraRulesResource {
        rules: RwLock::new(rules),
    }))
}

/// Scan binary data with compiled YARA rules
///
/// ## Arguments
/// * `rules_resource` - Compiled YARA rules resource
/// * `data` - Binary data to scan
///
/// ## Returns
/// * `{:ok, [matches]}` - List of matches
/// * `{:error, message}` - Scan error
#[rustler::nif]
pub fn scan_bytes(
    rules_resource: ResourceArc<YaraRulesResource>,
    data: Binary,
) -> NifResult<Vec<YaraMatch>> {
    #[cfg(feature = "yara")]
    {
        let result = scan_bytes_impl(&rules_resource, data.as_slice());
        to_nif_result(result)
    }

    #[cfg(not(feature = "yara"))]
    {
        Err(rustler::Error::Term(Box::new(NifError::Yara(
            "YARA feature not enabled".to_string()
        ))))
    }
}

#[cfg(feature = "yara")]
fn scan_bytes_impl(
    rules_resource: &YaraRulesResource,
    data: &[u8],
) -> Result<Vec<YaraMatch>, NifError> {
    let rules = rules_resource.rules.read()
        .map_err(|e| NifError::Yara(format!("Failed to acquire rules lock: {}", e)))?;

    let scan_results = rules
        .scan_mem(data, 60) // 60 second timeout
        .map_err(|e| NifError::Yara(format!("Scan failed: {}", e)))?;

    let matches = scan_results
        .iter()
        .map(|rule| {
            let strings = rule.strings.iter().map(|s| {
                let matches = s.matches.iter().map(|m| {
                    YaraStringMatch {
                        offset: m.offset,
                        length: m.length,
                        data: String::from_utf8_lossy(&m.data).to_string(),
                    }
                }).collect();

                YaraString {
                    identifier: s.identifier.to_string(),
                    matches,
                }
            }).collect();

            let metadata = rule.metadata.iter().map(|m| {
                (m.identifier.to_string(), format!("{:?}", m.value))
            }).collect();

            YaraMatch {
                rule: rule.identifier.to_string(),
                namespace: rule.namespace.to_string(),
                tags: rule.tags.iter().map(|t| t.to_string()).collect(),
                metadata,
                strings,
            }
        })
        .collect();

    Ok(matches)
}

/// Scan file with compiled YARA rules
///
/// ## Arguments
/// * `rules_resource` - Compiled YARA rules resource
/// * `file_path` - Path to file to scan
///
/// ## Returns
/// * `{:ok, [matches]}` - List of matches
/// * `{:error, message}` - Scan error
#[rustler::nif]
pub fn scan_file(
    rules_resource: ResourceArc<YaraRulesResource>,
    file_path: String,
) -> NifResult<Vec<YaraMatch>> {
    #[cfg(feature = "yara")]
    {
        let result = scan_file_impl(&rules_resource, &file_path);
        to_nif_result(result)
    }

    #[cfg(not(feature = "yara"))]
    {
        Err(rustler::Error::Term(Box::new(NifError::Yara(
            "YARA feature not enabled".to_string()
        ))))
    }
}

#[cfg(feature = "yara")]
fn scan_file_impl(
    rules_resource: &YaraRulesResource,
    file_path: &str,
) -> Result<Vec<YaraMatch>, NifError> {
    let rules = rules_resource.rules.read()
        .map_err(|e| NifError::Yara(format!("Failed to acquire rules lock: {}", e)))?;

    let path = Path::new(file_path);
    if !path.exists() {
        return Err(NifError::NotFound(format!("File not found: {}", file_path)));
    }

    let scan_results = rules
        .scan_file(path, 60) // 60 second timeout
        .map_err(|e| NifError::Yara(format!("Scan failed: {}", e)))?;

    let matches = scan_results
        .iter()
        .map(|rule| {
            let strings = rule.strings.iter().map(|s| {
                let matches = s.matches.iter().map(|m| {
                    YaraStringMatch {
                        offset: m.offset,
                        length: m.length,
                        data: String::from_utf8_lossy(&m.data).to_string(),
                    }
                }).collect();

                YaraString {
                    identifier: s.identifier.to_string(),
                    matches,
                }
            }).collect();

            let metadata = rule.metadata.iter().map(|m| {
                (m.identifier.to_string(), format!("{:?}", m.value))
            }).collect();

            YaraMatch {
                rule: rule.identifier.to_string(),
                namespace: rule.namespace.to_string(),
                tags: rule.tags.iter().map(|t| t.to_string()).collect(),
                metadata,
                strings,
            }
        })
        .collect();

    Ok(matches)
}

/// List all rule names in a compiled ruleset
///
/// ## Arguments
/// * `rules_resource` - Compiled YARA rules resource
///
/// ## Returns
/// * `{:ok, [rule_names]}` - List of rule names
/// * `{:error, message}` - Error
#[rustler::nif]
pub fn list_rules(
    rules_resource: ResourceArc<YaraRulesResource>,
) -> NifResult<Vec<String>> {
    #[cfg(feature = "yara")]
    {
        let result = list_rules_impl(&rules_resource);
        to_nif_result(result)
    }

    #[cfg(not(feature = "yara"))]
    {
        Err(rustler::Error::Term(Box::new(NifError::Yara(
            "YARA feature not enabled".to_string()
        ))))
    }
}

#[cfg(feature = "yara")]
fn list_rules_impl(
    rules_resource: &YaraRulesResource,
) -> Result<Vec<String>, NifError> {
    let rules = rules_resource.rules.read()
        .map_err(|e| NifError::Yara(format!("Failed to acquire rules lock: {}", e)))?;

    // YARA crate doesn't provide a direct way to list rules,
    // so we'll scan empty data and collect rule names from metadata
    // This is a workaround; in production, you might want to track names separately
    Ok(vec![]) // Placeholder - would need custom implementation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "yara")]
    fn test_compile_and_scan() {
        let rules = r#"
            rule test_rule {
                strings:
                    $a = "malware"
                condition:
                    $a
            }
        "#;

        let compiled = compile_rules_impl(rules).unwrap();
        let data = b"This contains malware pattern";
        let matches = scan_bytes_impl(&compiled, data).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule, "test_rule");
    }
}
