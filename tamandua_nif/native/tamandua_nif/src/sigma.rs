use rustler::{Encoder, Env, NifResult, Term};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use regex::Regex;

use crate::{NifError, to_nif_result};

/// Parsed Sigma rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub level: String,
    pub status: Option<String>,
    pub author: Option<String>,
    pub tags: Vec<String>,
    pub logsource: LogSource,
    pub detection: Detection,
    pub fields: Vec<String>,
}

/// Log source specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    pub product: Option<String>,
    pub service: Option<String>,
    pub category: Option<String>,
}

/// Detection logic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub searches: HashMap<String, SearchExpression>,
    pub condition: String,
}

/// Search expression (field patterns)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SearchExpression {
    Simple(HashMap<String, FieldValue>),
    List(Vec<HashMap<String, FieldValue>>),
}

/// Field value with modifiers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldValue {
    String(String),
    Number(i64),
    List(Vec<String>),
    Null,
}

impl Encoder for SigmaRule {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        (
            &self.id,
            &self.title,
            &self.description,
            &self.level,
            &self.status,
            &self.author,
            &self.tags,
        ).encode(env)
    }
}

/// Parse a Sigma rule from YAML string
///
/// ## Arguments
/// * `yaml_content` - YAML string containing Sigma rule
///
/// ## Returns
/// * `{:ok, rule}` - Parsed Sigma rule
/// * `{:error, message}` - Parse error
#[rustler::nif]
pub fn parse_rule(yaml_content: String) -> NifResult<SigmaRule> {
    let result = parse_rule_impl(&yaml_content);
    to_nif_result(result)
}

fn parse_rule_impl(yaml_content: &str) -> Result<SigmaRule, NifError> {
    let value: serde_yaml::Value = serde_yaml::from_str(yaml_content)
        .map_err(|e| NifError::Parse(format!("YAML parse error: {}", e)))?;

    let map = value.as_mapping()
        .ok_or_else(|| NifError::Parse("Root must be a mapping".to_string()))?;

    // Parse required fields
    let id = map.get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| NifError::Parse("Missing 'id' field".to_string()))?
        .to_string();

    let title = map.get("title")
        .and_then(|v| v.as_str())
        .ok_or_else(|| NifError::Parse("Missing 'title' field".to_string()))?
        .to_string();

    let description = map.get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let level = map.get("level")
        .and_then(|v| v.as_str())
        .unwrap_or("medium")
        .to_string();

    let status = map.get("status")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let author = map.get("author")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Parse tags
    let tags = map.get("tags")
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Parse logsource
    let logsource = map.get("logsource")
        .and_then(|v| v.as_mapping())
        .map(|ls_map| LogSource {
            product: ls_map.get("product").and_then(|v| v.as_str()).map(|s| s.to_string()),
            service: ls_map.get("service").and_then(|v| v.as_str()).map(|s| s.to_string()),
            category: ls_map.get("category").and_then(|v| v.as_str()).map(|s| s.to_string()),
        })
        .ok_or_else(|| NifError::Parse("Missing 'logsource' field".to_string()))?;

    // Parse detection
    let detection = map.get("detection")
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| NifError::Parse("Missing 'detection' field".to_string()))?;

    let condition = detection.get("condition")
        .and_then(|v| v.as_str())
        .ok_or_else(|| NifError::Parse("Missing 'condition' in detection".to_string()))?
        .to_string();

    let mut searches = HashMap::new();
    for (key, value) in detection.iter() {
        let key_str = key.as_str()
            .ok_or_else(|| NifError::Parse("Detection key must be string".to_string()))?;

        if key_str == "condition" {
            continue;
        }

        let search_expr = parse_search_expression(value)?;
        searches.insert(key_str.to_string(), search_expr);
    }

    // Parse fields
    let fields = map.get("fields")
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    Ok(SigmaRule {
        id,
        title,
        description,
        level,
        status,
        author,
        tags,
        logsource,
        detection: Detection {
            searches,
            condition,
        },
        fields,
    })
}

fn parse_search_expression(value: &serde_yaml::Value) -> Result<SearchExpression, NifError> {
    if let Some(mapping) = value.as_mapping() {
        let mut fields = HashMap::new();
        for (k, v) in mapping.iter() {
            let key = k.as_str()
                .ok_or_else(|| NifError::Parse("Field key must be string".to_string()))?
                .to_string();
            let field_value = parse_field_value(v)?;
            fields.insert(key, field_value);
        }
        Ok(SearchExpression::Simple(fields))
    } else if let Some(sequence) = value.as_sequence() {
        let mut list = Vec::new();
        for item in sequence {
            if let Some(mapping) = item.as_mapping() {
                let mut fields = HashMap::new();
                for (k, v) in mapping.iter() {
                    let key = k.as_str()
                        .ok_or_else(|| NifError::Parse("Field key must be string".to_string()))?
                        .to_string();
                    let field_value = parse_field_value(v)?;
                    fields.insert(key, field_value);
                }
                list.push(fields);
            }
        }
        Ok(SearchExpression::List(list))
    } else {
        Err(NifError::Parse("Invalid search expression".to_string()))
    }
}

fn parse_field_value(value: &serde_yaml::Value) -> Result<FieldValue, NifError> {
    if value.is_null() {
        Ok(FieldValue::Null)
    } else if let Some(s) = value.as_str() {
        Ok(FieldValue::String(s.to_string()))
    } else if let Some(n) = value.as_i64() {
        Ok(FieldValue::Number(n))
    } else if let Some(seq) = value.as_sequence() {
        let strings: Vec<String> = seq.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        Ok(FieldValue::List(strings))
    } else {
        Err(NifError::Parse("Unsupported field value type".to_string()))
    }
}

/// Match an event against a parsed Sigma rule
///
/// ## Arguments
/// * `rule_json` - JSON-encoded Sigma rule
/// * `event_json` - JSON-encoded event data
///
/// ## Returns
/// * `{:ok, matched}` - Boolean indicating match
/// * `{:error, message}` - Match error
#[rustler::nif]
pub fn match_event(rule_json: String, event_json: String) -> NifResult<bool> {
    let result = match_event_impl(&rule_json, &event_json);
    to_nif_result(result)
}

fn match_event_impl(rule_json: &str, event_json: &str) -> Result<bool, NifError> {
    let rule: SigmaRule = serde_json::from_str(rule_json)
        .map_err(|e| NifError::Parse(format!("Rule parse error: {}", e)))?;

    let event: JsonValue = serde_json::from_str(event_json)
        .map_err(|e| NifError::Parse(format!("Event parse error: {}", e)))?;

    let event_obj = event.as_object()
        .ok_or_else(|| NifError::Parse("Event must be JSON object".to_string()))?;

    // Evaluate all search expressions
    let mut search_results = HashMap::new();
    for (name, search_expr) in &rule.detection.searches {
        let matched = match_search_expression(search_expr, event_obj)?;
        search_results.insert(name.clone(), matched);
    }

    // Evaluate condition
    evaluate_condition(&rule.detection.condition, &search_results)
}

fn match_search_expression(
    search_expr: &SearchExpression,
    event: &serde_json::Map<String, JsonValue>,
) -> Result<bool, NifError> {
    match search_expr {
        SearchExpression::Simple(fields) => {
            // All fields must match (AND logic)
            for (field_name, field_value) in fields {
                if !match_field(field_name, field_value, event)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        SearchExpression::List(list) => {
            // Any item must match (OR logic)
            for fields in list {
                let mut all_match = true;
                for (field_name, field_value) in fields {
                    if !match_field(field_name, field_value, event)? {
                        all_match = false;
                        break;
                    }
                }
                if all_match {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

fn match_field(
    field_name: &str,
    field_value: &FieldValue,
    event: &serde_json::Map<String, JsonValue>,
) -> Result<bool, NifError> {
    let event_value = event.get(field_name);

    match field_value {
        FieldValue::Null => Ok(event_value.is_none() || event_value.unwrap().is_null()),
        FieldValue::String(pattern) => {
            if let Some(ev) = event_value {
                let event_str = ev.as_str().unwrap_or("");
                Ok(match_pattern(pattern, event_str))
            } else {
                Ok(false)
            }
        }
        FieldValue::Number(n) => {
            if let Some(ev) = event_value {
                Ok(ev.as_i64() == Some(*n))
            } else {
                Ok(false)
            }
        }
        FieldValue::List(patterns) => {
            if let Some(ev) = event_value {
                let event_str = ev.as_str().unwrap_or("");
                Ok(patterns.iter().any(|p| match_pattern(p, event_str)))
            } else {
                Ok(false)
            }
        }
    }
}

fn match_pattern(pattern: &str, value: &str) -> bool {
    if pattern.contains('*') || pattern.contains('?') {
        // Wildcard matching
        let regex_pattern = pattern
            .replace(".", "\\.")
            .replace("*", ".*")
            .replace("?", ".");
        if let Ok(re) = Regex::new(&format!("^{}$", regex_pattern)) {
            return re.is_match(value);
        }
    }

    // Exact match
    pattern == value || value.contains(pattern)
}

fn evaluate_condition(
    condition: &str,
    search_results: &HashMap<String, bool>,
) -> Result<bool, NifError> {
    // Simple condition evaluation
    // Supports: search_name, AND, OR, NOT, ( )
    let mut result = false;
    let mut current_op = "OR";

    for token in condition.split_whitespace() {
        match token {
            "and" | "AND" => current_op = "AND",
            "or" | "OR" => current_op = "OR",
            "not" | "NOT" => current_op = "NOT",
            "(" | ")" => continue,
            search_name => {
                let search_result = search_results.get(search_name).copied().unwrap_or(false);
                match current_op {
                    "AND" => result = result && search_result,
                    "OR" => result = result || search_result,
                    "NOT" => result = !search_result,
                    _ => result = search_result,
                }
            }
        }
    }

    Ok(result)
}

/// Compile multiple Sigma rules in batch
///
/// ## Arguments
/// * `yaml_contents` - List of YAML strings
///
/// ## Returns
/// * `{:ok, [rules]}` - List of parsed rules
/// * `{:error, message}` - Parse error
#[rustler::nif]
pub fn compile_rules_batch(yaml_contents: Vec<String>) -> NifResult<Vec<SigmaRule>> {
    let result = compile_rules_batch_impl(&yaml_contents);
    to_nif_result(result)
}

fn compile_rules_batch_impl(yaml_contents: &[String]) -> Result<Vec<SigmaRule>, NifError> {
    let mut rules = Vec::new();

    for yaml in yaml_contents {
        match parse_rule_impl(yaml) {
            Ok(rule) => rules.push(rule),
            Err(e) => {
                // Log error but continue processing
                eprintln!("Failed to parse rule: {}", e);
            }
        }
    }

    Ok(rules)
}

/// Validate a Sigma rule
///
/// ## Arguments
/// * `yaml_content` - YAML string containing Sigma rule
///
/// ## Returns
/// * `{:ok, valid}` - Boolean indicating validity
/// * `{:error, message}` - Validation error details
#[rustler::nif]
pub fn validate_rule(yaml_content: String) -> NifResult<bool> {
    let result = validate_rule_impl(&yaml_content);
    to_nif_result(result)
}

fn validate_rule_impl(yaml_content: &str) -> Result<bool, NifError> {
    match parse_rule_impl(yaml_content) {
        Ok(_) => Ok(true),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let yaml = r#"
id: test-rule-001
title: Test Rule
description: A test rule
level: high
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    CommandLine: "*cmd.exe*"
  condition: selection
"#;

        let rule = parse_rule_impl(yaml).unwrap();
        assert_eq!(rule.id, "test-rule-001");
        assert_eq!(rule.title, "Test Rule");
        assert_eq!(rule.level, "high");
    }

    #[test]
    fn test_match_event() {
        let rule_json = r#"{
            "id": "test",
            "title": "Test",
            "level": "high",
            "logsource": {"product": "windows"},
            "detection": {
                "searches": {
                    "selection": {
                        "Simple": {
                            "EventID": {"String": "4688"}
                        }
                    }
                },
                "condition": "selection"
            },
            "tags": [],
            "fields": []
        }"#;

        let event_json = r#"{"EventID": "4688", "CommandLine": "cmd.exe"}"#;

        let result = match_event_impl(rule_json, event_json).unwrap();
        assert!(result);
    }
}
