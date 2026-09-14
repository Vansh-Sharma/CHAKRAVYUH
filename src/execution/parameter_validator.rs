// Parameter Validator — Engine 2 of the Execution Ring
//
// Validates tool call parameters against configurable JSON schemas.
// Each tool can have its own parameter schema.
// Parameters not matching the schema are blocked.
//
// Latency Budget: <0.5ms p99

use serde::{Deserialize, Serialize};

/// Configuration for a tool's parameter schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolParameterSchema {
    pub tool_name: String,
    /// JSON Schema for the tool's parameters.
    /// We validate: required fields present, string max_length,
    /// integer min/max, and type checks.
    pub schema: ParameterSchema,
}

/// Simplified JSON Schema for parameter validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterSchema {
    #[serde(default)]
    pub required_fields: Vec<String>,
    #[serde(default)]
    pub properties: std::collections::HashMap<String, PropertySpec>,
}

/// Specification for a single parameter property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertySpec {
    #[serde(rename = "type")]
    pub prop_type: PropertyType,
    #[serde(default)]
    pub max_length: Option<usize>,
    #[serde(default)]
    pub min_length: Option<usize>,
    #[serde(default)]
    pub minimum: Option<i64>,
    #[serde(default)]
    pub maximum: Option<i64>,
    /// If true, allow only these exact values.
    #[serde(default)]
    pub enum_values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PropertyType {
    String,
    Integer,
    Number,
    Boolean,
    Array,
    Object,
}

/// Configuration for the Parameter Validator engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterValidatorConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub tool_schemas: Vec<ToolParameterSchema>,
}

fn default_enabled() -> bool {
    true
}

impl Default for ParameterValidatorConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            tool_schemas: vec![
                ToolParameterSchema {
                    tool_name: "web_search".into(),
                    schema: ParameterSchema {
                        required_fields: vec!["query".into()],
                        properties: {
                            let mut m = std::collections::HashMap::new();
                            m.insert(
                                "query".into(),
                                PropertySpec {
                                    prop_type: PropertyType::String,
                                    max_length: Some(200),
                                    min_length: Some(1),
                                    minimum: None,
                                    maximum: None,
                                    enum_values: vec![],
                                },
                            );
                            m.insert(
                                "max_results".into(),
                                PropertySpec {
                                    prop_type: PropertyType::Integer,
                                    max_length: None,
                                    min_length: None,
                                    minimum: Some(1),
                                    maximum: Some(20),
                                    enum_values: vec![],
                                },
                            );
                            m
                        },
                    },
                },
                ToolParameterSchema {
                    tool_name: "calculator".into(),
                    schema: ParameterSchema {
                        required_fields: vec!["expression".into()],
                        properties: {
                            let mut m = std::collections::HashMap::new();
                            m.insert(
                                "expression".into(),
                                PropertySpec {
                                    prop_type: PropertyType::String,
                                    max_length: Some(100),
                                    min_length: Some(1),
                                    minimum: None,
                                    maximum: None,
                                    enum_values: vec![],
                                },
                            );
                            m
                        },
                    },
                },
                ToolParameterSchema {
                    tool_name: "file_read".into(),
                    schema: ParameterSchema {
                        required_fields: vec!["path".into()],
                        properties: {
                            let mut m = std::collections::HashMap::new();
                            m.insert(
                                "path".into(),
                                PropertySpec {
                                    prop_type: PropertyType::String,
                                    max_length: Some(500),
                                    min_length: Some(1),
                                    minimum: None,
                                    maximum: None,
                                    enum_values: vec![],
                                },
                            );
                            m
                        },
                    },
                },
            ],
        }
    }
}

/// Result of a parameter validation check.
#[derive(Debug, Clone, Serialize)]
pub struct ParameterValidatorResult {
    pub decision: crate::decision::Decision,
    pub reason: String,
    pub tool_name: String,
    pub violations: Vec<String>,
    pub latency_ms: f64,
}

/// The Parameter Validator engine.
///
/// Validates tool call parameters against the configured schema.
/// If no schema is configured for a tool, it passes (open policy).
#[derive(Clone)]
pub struct ParameterValidator {
    config: ParameterValidatorConfig,
}

impl ParameterValidator {
    pub fn new(config: &ParameterValidatorConfig) -> crate::Result<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    /// Validate tool call parameters against the tool's schema.
    pub fn evaluate(
        &self,
        tool_name: &str,
        params: &serde_json::Value,
    ) -> ParameterValidatorResult {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return ParameterValidatorResult {
                decision: crate::decision::Decision::Allow,
                reason: "parameter_validator engine disabled".into(),
                tool_name: tool_name.into(),
                violations: vec![],
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }

        // Find schema for this tool.
        let tool_schema = self
            .config
            .tool_schemas
            .iter()
            .find(|s| s.tool_name == tool_name);

        let Some(tool_schema) = tool_schema else {
            // No schema configured for this tool — allow (open policy).
            return ParameterValidatorResult {
                decision: crate::decision::Decision::Allow,
                reason: format!(
                    "no parameter schema configured for tool '{}'; allowing",
                    tool_name
                ),
                tool_name: tool_name.into(),
                violations: vec![],
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        };

        let mut violations = vec![];

        // Check required fields.
        for field in &tool_schema.schema.required_fields {
            if !params.get(field).is_some() {
                violations.push(format!("required field '{}' is missing", field));
            }
        }

        // Check property constraints.
        if let Some(obj) = params.as_object() {
            for (key, value) in obj {
                if let Some(spec) = tool_schema.schema.properties.get(key) {
                    violations.extend(validate_property(key, value, spec));
                }
            }
        } else if !tool_schema.schema.required_fields.is_empty() {
            violations.push("parameters must be a JSON object".into());
        }

        let decision = if violations.is_empty() {
            crate::decision::Decision::Allow
        } else {
            crate::decision::Decision::Deny {
                code: "EXEC_PARAM_VALIDATION_FAILED".into(),
                retry_after: None,
            }
        };

        let reason = if violations.is_empty() {
            format!("all parameter constraints passed for tool '{}'", tool_name)
        } else {
            format!(
                "parameter validation failed for tool '{}': {}",
                tool_name,
                violations.join("; ")
            )
        };

        ParameterValidatorResult {
            decision,
            reason,
            tool_name: tool_name.into(),
            violations,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
        }
    }
}

/// Validate a single parameter value against its specification.
fn validate_property(key: &str, value: &serde_json::Value, spec: &PropertySpec) -> Vec<String> {
    let mut violations = vec![];

    match &spec.prop_type {
        PropertyType::String => {
            if let Some(s) = value.as_str() {
                if let Some(max) = spec.max_length {
                    if s.len() > max {
                        violations.push(format!("'{}' exceeds max_length ({})", key, max));
                    }
                }
                if let Some(min) = spec.min_length {
                    if s.len() < min {
                        violations.push(format!("'{}' below min_length ({})", key, min));
                    }
                }
                if !spec.enum_values.is_empty() && !spec.enum_values.contains(&s.to_string()) {
                    violations.push(format!(
                        "'{}' value '{}' not in allowed values {:?}",
                        key, s, spec.enum_values
                    ));
                }
            } else {
                violations.push(format!("'{}' expected type string, got {}", key, value));
            }
        }
        PropertyType::Integer => {
            if let Some(n) = value.as_i64() {
                if let Some(min) = spec.minimum {
                    if n < min {
                        violations.push(format!("'{}' value {} below minimum {}", key, n, min));
                    }
                }
                if let Some(max) = spec.maximum {
                    if n > max {
                        violations.push(format!("'{}' value {} above maximum {}", key, n, max));
                    }
                }
            } else {
                violations.push(format!("'{}' expected type integer, got {}", key, value));
            }
        }
        PropertyType::Number => {
            if !value.is_number() {
                violations.push(format!("'{}' expected type number, got {}", key, value));
            }
        }
        PropertyType::Boolean => {
            if !value.is_boolean() {
                violations.push(format!("'{}' expected type boolean, got {}", key, value));
            }
        }
        PropertyType::Array => {
            if !value.is_array() {
                violations.push(format!("'{}' expected type array, got {}", key, value));
            }
        }
        PropertyType::Object => {
            if !value.is_object() {
                violations.push(format!("'{}' expected type object, got {}", key, value));
            }
        }
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_params_pass() {
        let engine = ParameterValidator::new(&ParameterValidatorConfig::default()).unwrap();
        let params = serde_json::json!({"query": "rust programming", "max_results": 5});
        let result = engine.evaluate("web_search", &params);
        assert!(result.decision.is_allow());
        assert!(result.violations.is_empty());
    }

    #[test]
    fn missing_required_field_fails() {
        let engine = ParameterValidator::new(&ParameterValidatorConfig::default()).unwrap();
        let params = serde_json::json!({"max_results": 5});
        let result = engine.evaluate("web_search", &params);
        assert!(result.decision.is_deny());
        assert!(result.violations.iter().any(|v| v.contains("missing")));
    }

    #[test]
    fn string_max_length_enforced() {
        let engine = ParameterValidator::new(&ParameterValidatorConfig::default()).unwrap();
        let long_query = "a".repeat(201);
        let params = serde_json::json!({"query": long_query});
        let result = engine.evaluate("web_search", &params);
        assert!(result.decision.is_deny());
        assert!(result.violations.iter().any(|v| v.contains("max_length")));
    }

    #[test]
    fn integer_range_enforced() {
        let engine = ParameterValidator::new(&ParameterValidatorConfig::default()).unwrap();
        let params = serde_json::json!({"query": "test", "max_results": 25});
        let result = engine.evaluate("web_search", &params);
        assert!(result.decision.is_deny());
        assert!(result.violations.iter().any(|v| v.contains("maximum")));
    }

    #[test]
    fn no_schema_allows_anything() {
        let engine = ParameterValidator::new(&ParameterValidatorConfig::default()).unwrap();
        let params = serde_json::json!({"anything": "goes"});
        let result = engine.evaluate("unknown_tool", &params);
        assert!(result.decision.is_allow());
    }
}
