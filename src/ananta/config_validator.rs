// ═══════════════════════════════════════════════════════════════
// ANANTA Configuration Validator
//
// Production-grade configuration validation and management for ANANTA.
// Provides schema validation, migration, env interpolation, diffing,
// templating, and hot-reload support.
// ═══════════════════════════════════════════════════════════════

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

// ═══════════════════════════════════════════════════════════════
// Section 1: Schema Validation Engine
// ═══════════════════════════════════════════════════════════════

/// Supported value types for schema validation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SchemaType {
    String,
    Integer,
    Float,
    Boolean,
    Array,
    Object,
}

impl std::fmt::Display for SchemaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaType::String => write!(f, "string"),
            SchemaType::Integer => write!(f, "integer"),
            SchemaType::Float => write!(f, "float"),
            SchemaType::Boolean => write!(f, "boolean"),
            SchemaType::Array => write!(f, "array"),
            SchemaType::Object => write!(f, "object"),
        }
    }
}

/// Constraints applied to string-typed values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringConstraints {
    /// Minimum length (inclusive).
    #[serde(default)]
    pub min_length: Option<usize>,
    /// Maximum length (inclusive).
    #[serde(default)]
    pub max_length: Option<usize>,
    /// Regex pattern the string must match.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Compiled regex, not serialized.
    #[serde(skip)]
    pub compiled_pattern: Option<Regex>,
    /// Valid format hint (e.g. "uri", "email", "ipv4").
    #[serde(default)]
    pub format: Option<String>,
}

impl StringConstraints {
    /// Create a new StringConstraints with default values.
    pub fn new() -> Self {
        Self {
            min_length: None,
            max_length: None,
            pattern: None,
            compiled_pattern: None,
            format: None,
        }
    }

    /// Set the minimum length constraint.
    pub fn min_length(mut self, len: usize) -> Self {
        self.min_length = Some(len);
        self
    }

    /// Set the maximum length constraint.
    pub fn max_length(mut self, len: usize) -> Self {
        self.max_length = Some(len);
        self
    }

    /// Set a regex pattern constraint. Compiles the pattern immediately.
    pub fn pattern(mut self, pat: &str) -> Result<Self, String> {
        let compiled =
            Regex::new(pat).map_err(|e| format!("invalid regex pattern '{}': {}", pat, e))?;
        self.pattern = Some(pat.to_string());
        self.compiled_pattern = Some(compiled);
        Ok(self)
    }

    /// Validate a string value against all constraints.
    pub fn validate(&self, value: &str) -> Result<(), String> {
        if let Some(min) = self.min_length {
            if value.len() < min {
                return Err(format!(
                    "string length {} is below minimum {}",
                    value.len(),
                    min
                ));
            }
        }
        if let Some(max) = self.max_length {
            if value.len() > max {
                return Err(format!(
                    "string length {} exceeds maximum {}",
                    value.len(),
                    max
                ));
            }
        }
        if let Some(ref compiled) = self.compiled_pattern {
            if !compiled.is_match(value) {
                return Err(format!(
                    "string '{}' does not match pattern '{}'",
                    value,
                    self.pattern.as_deref().unwrap_or("(unknown)")
                ));
            }
        }
        if let Some(ref fmt) = self.format {
            match fmt.as_str() {
                "uri" => {
                    if !value.starts_with("http://") && !value.starts_with("https://") {
                        return Err(format!("'{}' is not a valid URI", value));
                    }
                }
                "email" => {
                    let email_re = Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").unwrap();
                    if !email_re.is_match(value) {
                        return Err(format!("'{}' is not a valid email", value));
                    }
                }
                "ipv4" => {
                    let parts: Vec<&str> = value.split('.').collect();
                    if parts.len() != 4 {
                        return Err(format!("'{}' is not a valid IPv4 address", value));
                    }
                    for part in &parts {
                        part.parse::<u8>()
                            .map_err(|_| format!("'{}' is not a valid IPv4 address", value))?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl Default for StringConstraints {
    fn default() -> Self {
        Self::new()
    }
}

/// Constraints applied to numeric values (integer or float).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NumberConstraints {
    /// Minimum value (inclusive).
    #[serde(default)]
    pub minimum: Option<f64>,
    /// Maximum value (inclusive).
    #[serde(default)]
    pub maximum: Option<f64>,
    /// Exclusive minimum (value must be strictly greater).
    #[serde(default)]
    pub exclusive_minimum: Option<f64>,
    /// Exclusive maximum (value must be strictly less).
    #[serde(default)]
    pub exclusive_maximum: Option<f64>,
    /// Must be a multiple of this value.
    #[serde(default)]
    pub multiple_of: Option<f64>,
}

impl NumberConstraints {
    /// Create a new NumberConstraints with default values.
    pub fn new() -> Self {
        Self {
            minimum: None,
            maximum: None,
            exclusive_minimum: None,
            exclusive_maximum: None,
            multiple_of: None,
        }
    }

    /// Set the minimum (inclusive) constraint.
    pub fn minimum(mut self, val: f64) -> Self {
        self.minimum = Some(val);
        self
    }

    /// Set the maximum (inclusive) constraint.
    pub fn maximum(mut self, val: f64) -> Self {
        self.maximum = Some(val);
        self
    }

    /// Set the exclusive minimum constraint.
    pub fn exclusive_minimum(mut self, val: f64) -> Self {
        self.exclusive_minimum = Some(val);
        self
    }

    /// Set the exclusive maximum constraint.
    pub fn exclusive_maximum(mut self, val: f64) -> Self {
        self.exclusive_maximum = Some(val);
        self
    }

    /// Set the multiple_of constraint.
    pub fn multiple_of(mut self, val: f64) -> Self {
        self.multiple_of = Some(val);
        self
    }

    /// Validate a numeric value against all constraints.
    pub fn validate(&self, value: f64) -> Result<(), String> {
        if let Some(min) = self.minimum {
            if value < min {
                return Err(format!("value {} is below minimum {}", value, min));
            }
        }
        if let Some(max) = self.maximum {
            if value > max {
                return Err(format!("value {} exceeds maximum {}", value, max));
            }
        }
        if let Some(ex_min) = self.exclusive_minimum {
            if value <= ex_min {
                return Err(format!(
                    "value {} must be strictly greater than {}",
                    value, ex_min
                ));
            }
        }
        if let Some(ex_max) = self.exclusive_maximum {
            if value >= ex_max {
                return Err(format!(
                    "value {} must be strictly less than {}",
                    value, ex_max
                ));
            }
        }
        if let Some(mult) = self.multiple_of {
            if mult != 0.0 {
                let remainder = value % mult;
                // Use an epsilon for floating point comparison
                if (remainder.abs() > 1e-9) && ((mult - remainder).abs() > 1e-9) {
                    return Err(format!("value {} is not a multiple of {}", value, mult));
                }
            }
        }
        Ok(())
    }
}

impl Default for NumberConstraints {
    fn default() -> Self {
        Self::new()
    }
}

/// Constraints applied to array-typed values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArrayConstraints {
    /// Minimum number of items.
    #[serde(default)]
    pub min_items: Option<usize>,
    /// Maximum number of items.
    #[serde(default)]
    pub max_items: Option<usize>,
    /// Whether all items must be unique.
    #[serde(default)]
    pub unique_items: bool,
    /// Schema that every array item must conform to.
    #[serde(default)]
    pub items_schema: Option<Box<SchemaNode>>,
}

impl Default for ArrayConstraints {
    fn default() -> Self {
        Self {
            min_items: None,
            max_items: None,
            unique_items: false,
            items_schema: None,
        }
    }
}

/// Constraints applied to object-typed values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectConstraints {
    /// Fields that must be present.
    #[serde(default)]
    pub required: Vec<String>,
    /// Whether properties not listed in `properties` are allowed.
    #[serde(default = "default_true_obj")]
    pub additional_properties: bool,
    /// Minimum number of properties.
    #[serde(default)]
    pub min_properties: Option<usize>,
    /// Maximum number of properties.
    #[serde(default)]
    pub max_properties: Option<usize>,
}

fn default_true_obj() -> bool {
    true
}

impl Default for ObjectConstraints {
    fn default() -> Self {
        Self {
            required: Vec::new(),
            additional_properties: true,
            min_properties: None,
            max_properties: None,
        }
    }
}

/// A node in the schema tree describing configuration structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaNode {
    /// The expected type(s) for this node.
    #[serde(default)]
    pub schema_type: Option<SchemaType>,
    /// Human-readable description for documentation and error messages.
    #[serde(default)]
    pub description: Option<String>,
    /// Allowed enum values. If set, the value must be one of these.
    #[serde(default)]
    pub enum_values: Vec<Value>,
    /// Default value if the field is absent.
    #[serde(default)]
    pub default_value: Option<Value>,
    /// String-specific constraints.
    #[serde(default)]
    pub string_constraints: Option<StringConstraints>,
    /// Number-specific constraints.
    #[serde(default)]
    pub number_constraints: Option<NumberConstraints>,
    /// Array-specific constraints.
    #[serde(default)]
    pub array_constraints: Option<ArrayConstraints>,
    /// Object-specific constraints.
    #[serde(default)]
    pub object_constraints: Option<ObjectConstraints>,
    /// Property schemas for object types. Maps property name to its schema.
    #[serde(default)]
    pub properties: BTreeMap<String, SchemaNode>,
}

impl SchemaNode {
    /// Create a new empty SchemaNode.
    pub fn new() -> Self {
        Self {
            schema_type: None,
            description: None,
            enum_values: Vec::new(),
            default_value: None,
            string_constraints: None,
            number_constraints: None,
            array_constraints: None,
            object_constraints: None,
            properties: BTreeMap::new(),
        }
    }

    /// Builder-style: set the type.
    pub fn typed(mut self, t: SchemaType) -> Self {
        self.schema_type = Some(t);
        self
    }

    /// Builder-style: set the description.
    pub fn description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }

    /// Builder-style: add a property to an object schema.
    pub fn property(mut self, name: &str, schema: SchemaNode) -> Self {
        self.properties.insert(name.to_string(), schema);
        self
    }

    /// Builder-style: mark a property as required.
    pub fn required(mut self, fields: &[&str]) -> Self {
        let obj = self
            .object_constraints
            .get_or_insert_with(ObjectConstraints::default);
        obj.required = fields.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Builder-style: set enum values.
    pub fn enum_values(mut self, values: Vec<Value>) -> Self {
        self.enum_values = values;
        self
    }

    /// Builder-style: set string constraints.
    pub fn string_constraints(mut self, constraints: StringConstraints) -> Self {
        self.string_constraints = Some(constraints);
        self
    }

    /// Builder-style: set number constraints.
    pub fn number_constraints(mut self, constraints: NumberConstraints) -> Self {
        self.number_constraints = Some(constraints);
        self
    }

    /// Builder-style: set array constraints.
    pub fn array_constraints(mut self, constraints: ArrayConstraints) -> Self {
        self.array_constraints = Some(constraints);
        self
    }

    /// Builder-style: disallow additional properties.
    pub fn no_additional_properties(mut self) -> Self {
        let obj = self
            .object_constraints
            .get_or_insert_with(ObjectConstraints::default);
        obj.additional_properties = false;
        self
    }

    /// Builder-style: set the default value.
    pub fn default_value(mut self, val: Value) -> Self {
        self.default_value = Some(val);
        self
    }
}

impl Default for SchemaNode {
    fn default() -> Self {
        Self::new()
    }
}

/// A single validation error with path and message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationError {
    /// Dot-separated path to the offending field (e.g. "sentinel.check_interval_ms").
    pub path: String,
    /// Human-readable error description.
    pub message: String,
    /// Error code for programmatic handling.
    pub code: ValidationErrorCode,
}

/// Categorised error codes for validation failures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ValidationErrorCode {
    /// Field is missing but required.
    RequiredFieldMissing,
    /// Value is the wrong type.
    TypeMismatch,
    /// Value does not satisfy a string constraint.
    StringConstraintViolation,
    /// Value does not satisfy a number constraint.
    NumberConstraintViolation,
    /// Value does not satisfy an array constraint.
    ArrayConstraintViolation,
    /// Value does not satisfy an object constraint.
    ObjectConstraintViolation,
    /// Value is not one of the allowed enum variants.
    EnumViolation,
    /// Property not defined in schema and additionalProperties is false.
    AdditionalPropertyNotAllowed,
    /// Value failed a nested schema validation.
    NestedValidationFailed,
}

/// Result of validating a configuration value against a schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether validation passed (no errors).
    pub is_valid: bool,
    /// All validation errors encountered.
    pub errors: Vec<ValidationError>,
    /// Warnings for questionable but valid values.
    pub warnings: Vec<String>,
}

impl ValidationResult {
    /// Create a successful (empty) validation result.
    pub fn valid() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Create a failed validation result with the given errors.
    pub fn invalid(errors: Vec<ValidationError>) -> Self {
        let is_valid = errors.is_empty();
        Self {
            is_valid,
            errors,
            warnings: Vec::new(),
        }
    }

    /// Merge another validation result into this one.
    pub fn merge(&mut self, other: ValidationResult) {
        self.is_valid = self.is_valid && other.is_valid;
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
    }
}

/// The schema validation engine. Validates JSON values against [`SchemaNode`] definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaValidator {
    /// The root schema to validate against.
    pub root_schema: SchemaNode,
    /// Whether to apply defaults for missing optional fields.
    #[serde(default = "default_true_obj")]
    pub apply_defaults: bool,
    /// Whether to stop at the first error or collect all errors.
    #[serde(default)]
    pub collect_all_errors: bool,
}

impl SchemaValidator {
    /// Create a new validator with the given root schema.
    pub fn new(root_schema: SchemaNode) -> Self {
        Self {
            root_schema,
            apply_defaults: true,
            collect_all_errors: true,
        }
    }

    /// Validate a configuration value against the root schema.
    pub fn validate(&self, value: &Value) -> ValidationResult {
        self.validate_node(value, &self.root_schema, "")
    }

    /// Validate a value against a specific schema node at the given path.
    fn validate_node(&self, value: &Value, schema: &SchemaNode, path: &str) -> ValidationResult {
        let mut result = ValidationResult::valid();
        let display_path = if path.is_empty() {
            "(root)".to_string()
        } else {
            path.to_string()
        };

        // Check type
        if let Some(ref expected_type) = schema.schema_type {
            if !self.check_type(value, expected_type) {
                result.errors.push(ValidationError {
                    path: display_path.clone(),
                    message: format!(
                        "expected type '{}', got '{}'",
                        expected_type,
                        self.actual_type_name(value)
                    ),
                    code: ValidationErrorCode::TypeMismatch,
                });
                if !self.collect_all_errors {
                    return result;
                }
            }
        }

        // Check enum values
        if !schema.enum_values.is_empty() {
            let matches = schema.enum_values.iter().any(|ev| ev == value);
            if !matches {
                result.errors.push(ValidationError {
                    path: display_path.clone(),
                    message: format!("value '{}' is not one of: {:?}", value, schema.enum_values),
                    code: ValidationErrorCode::EnumViolation,
                });
                if !self.collect_all_errors {
                    return result;
                }
            }
        }

        // Type-specific validation
        match value {
            Value::String(s) => {
                if let Some(ref sc) = schema.string_constraints {
                    if let Err(msg) = sc.validate(s) {
                        result.errors.push(ValidationError {
                            path: display_path.clone(),
                            message: msg,
                            code: ValidationErrorCode::StringConstraintViolation,
                        });
                    }
                }
            }
            Value::Number(n) => {
                if let Some(ref nc) = schema.number_constraints {
                    let fval = n.as_f64().unwrap_or(0.0);
                    if let Err(msg) = nc.validate(fval) {
                        result.errors.push(ValidationError {
                            path: display_path.clone(),
                            message: msg,
                            code: ValidationErrorCode::NumberConstraintViolation,
                        });
                    }
                }
            }
            Value::Array(arr) => {
                if let Some(ref ac) = schema.array_constraints {
                    if let Some(min) = ac.min_items {
                        if arr.len() < min {
                            result.errors.push(ValidationError {
                                path: display_path.clone(),
                                message: format!(
                                    "array has {} items, minimum is {}",
                                    arr.len(),
                                    min
                                ),
                                code: ValidationErrorCode::ArrayConstraintViolation,
                            });
                        }
                    }
                    if let Some(max) = ac.max_items {
                        if arr.len() > max {
                            result.errors.push(ValidationError {
                                path: display_path.clone(),
                                message: format!(
                                    "array has {} items, maximum is {}",
                                    arr.len(),
                                    max
                                ),
                                code: ValidationErrorCode::ArrayConstraintViolation,
                            });
                        }
                    }
                    if ac.unique_items {
                        let mut seen = HashSet::new();
                        for (i, item) in arr.iter().enumerate() {
                            let key = format!("{:?}", item);
                            if !seen.insert(key) {
                                result.errors.push(ValidationError {
                                    path: format!("{}[{}]", display_path, i),
                                    message: format!("duplicate array item at index {}", i),
                                    code: ValidationErrorCode::ArrayConstraintViolation,
                                });
                            }
                        }
                    }
                    if let Some(ref items_schema) = ac.items_schema {
                        for (i, item) in arr.iter().enumerate() {
                            let item_path = format!("{}[{}]", display_path, i);
                            let item_result = self.validate_node(item, items_schema, &item_path);
                            result.merge(item_result);
                        }
                    }
                }
            }
            Value::Object(map) => {
                if let Some(ref oc) = schema.object_constraints {
                    // Check required fields
                    for req_field in &oc.required {
                        if !map.contains_key(req_field.as_str()) {
                            result.errors.push(ValidationError {
                                path: format!("{}.{}", display_path, req_field),
                                message: format!("required field '{}' is missing", req_field),
                                code: ValidationErrorCode::RequiredFieldMissing,
                            });
                        }
                    }
                    // Check property count
                    if let Some(min_p) = oc.min_properties {
                        if map.len() < min_p {
                            result.errors.push(ValidationError {
                                path: display_path.clone(),
                                message: format!(
                                    "object has {} properties, minimum is {}",
                                    map.len(),
                                    min_p
                                ),
                                code: ValidationErrorCode::ObjectConstraintViolation,
                            });
                        }
                    }
                    if let Some(max_p) = oc.max_properties {
                        if map.len() > max_p {
                            result.errors.push(ValidationError {
                                path: display_path.clone(),
                                message: format!(
                                    "object has {} properties, maximum is {}",
                                    map.len(),
                                    max_p
                                ),
                                code: ValidationErrorCode::ObjectConstraintViolation,
                            });
                        }
                    }
                    // Check additional properties
                    if !oc.additional_properties {
                        for key in map.keys() {
                            if !schema.properties.contains_key(key.as_str()) {
                                result.errors.push(ValidationError {
                                    path: format!("{}.{}", display_path, key),
                                    message: format!(
                                        "additional property '{}' is not allowed",
                                        key
                                    ),
                                    code: ValidationErrorCode::AdditionalPropertyNotAllowed,
                                });
                            }
                        }
                    }
                }
                // Validate each property against its schema
                for (key, prop_schema) in &schema.properties {
                    if let Some(val) = map.get(key) {
                        let prop_path = if display_path == "(root)" {
                            key.clone()
                        } else {
                            format!("{}.{}", display_path, key)
                        };
                        let prop_result = self.validate_node(val, prop_schema, &prop_path);
                        result.merge(prop_result);
                    }
                }
            }
            _ => {}
        }

        result.is_valid = result.errors.is_empty();
        result
    }

    /// Apply default values from the schema to a configuration value, returning a new value.
    pub fn apply_defaults_to_value(&self, value: &Value, schema: &SchemaNode) -> Value {
        match value {
            Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                // Copy existing values (recursively apply defaults to objects)
                for (k, v) in map {
                    if let Some(prop_schema) = schema.properties.get(k) {
                        new_map.insert(k.clone(), self.apply_defaults_to_value(v, prop_schema));
                    } else {
                        new_map.insert(k.clone(), v.clone());
                    }
                }
                // Fill in defaults for missing properties
                for (prop_name, prop_schema) in &schema.properties {
                    if !new_map.contains_key(prop_name) {
                        if let Some(ref default) = prop_schema.default_value {
                            new_map.insert(prop_name.clone(), default.clone());
                        } else if let Some(Value::Object(_)) =
                            prop_schema.schema_type.as_ref().map(|_| value)
                        {
                            // Recurse into nested object schemas even if no default
                            let filled = self.apply_defaults_to_value(
                                &Value::Object(serde_json::Map::new()),
                                prop_schema,
                            );
                            if let Value::Object(inner) = filled {
                                if !inner.is_empty() {
                                    new_map.insert(prop_name.clone(), Value::Object(inner));
                                }
                            }
                        }
                    }
                }
                Value::Object(new_map)
            }
            other => other.clone(),
        }
    }

    /// Check whether a JSON value matches the expected schema type.
    fn check_type(&self, value: &Value, expected: &SchemaType) -> bool {
        match (value, expected) {
            (Value::String(_), SchemaType::String) => true,
            (Value::Number(n), SchemaType::Integer) => n.is_i64() || n.is_u64(),
            (Value::Number(_), SchemaType::Float) => true,
            (Value::Bool(_), SchemaType::Boolean) => true,
            (Value::Array(_), SchemaType::Array) => true,
            (Value::Object(_), SchemaType::Object) => true,
            _ => false,
        }
    }

    /// Return a human-readable name for the type of a JSON value.
    fn actual_type_name(&self, value: &Value) -> String {
        match value {
            Value::Null => "null".to_string(),
            Value::Bool(_) => "boolean".to_string(),
            Value::Number(n) => {
                if n.is_i64() || n.is_u64() {
                    "integer".to_string()
                } else {
                    "float".to_string()
                }
            }
            Value::String(_) => "string".to_string(),
            Value::Array(_) => "array".to_string(),
            Value::Object(_) => "object".to_string(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 2: Configuration Migration
// ═══════════════════════════════════════════════════════════════

/// A single migration step to transform configuration between versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MigrationStep {
    /// Add a new field with a default value at the given dot-path.
    AddField { path: String, default_value: Value },
    /// Remove a field at the given dot-path.
    RemoveField { path: String },
    /// Rename a field from old_path to new_path.
    RenameField { old_path: String, new_path: String },
    /// Transform a field's value using a built-in transformation.
    TransformValue {
        path: String,
        transformation: ValueTransformation,
    },
    /// Set a field to a specific value (overwrite).
    SetDefault { path: String, value: Value },
}

/// Built-in value transformations for migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValueTransformation {
    /// Convert a string to lowercase.
    ToLowercase,
    /// Convert a string to uppercase.
    ToUppercase,
    /// Trim whitespace from a string.
    Trim,
    /// Multiply a numeric value by a factor.
    Multiply(f64),
    /// Add a numeric offset to a value.
    Add(f64),
    /// Rename an enum variant.
    RenameVariant { from: String, to: String },
    /// Convert a string to an integer.
    ParseInt,
    /// Convert milliseconds to seconds (divide by 1000).
    MsToSeconds,
    /// Convert seconds to milliseconds (multiply by 1000).
    SecondsToMs,
}

/// A planned migration from one schema version to another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPlan {
    /// Source version identifier.
    pub from_version: String,
    /// Target version identifier.
    pub to_version: String,
    /// Ordered list of migration steps to apply.
    pub steps: Vec<MigrationStep>,
    /// Human-readable description of the migration.
    pub description: String,
    /// Timestamp when this plan was created.
    pub created_at: DateTime<Utc>,
}

impl MigrationPlan {
    /// Create a new migration plan.
    pub fn new(from: &str, to: &str, steps: Vec<MigrationStep>) -> Self {
        Self {
            from_version: from.to_string(),
            to_version: to.to_string(),
            steps,
            description: String::new(),
            created_at: Utc::now(),
        }
    }

    /// Builder-style: set the description.
    pub fn description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }
}

/// Result of a migration execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationResult {
    /// Whether the migration succeeded.
    pub success: bool,
    /// The resulting configuration value after migration.
    pub config: Value,
    /// Details of each applied step.
    pub applied_steps: Vec<MigrationStepResult>,
    /// Errors encountered during migration.
    pub errors: Vec<String>,
}

/// Result of applying a single migration step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationStepResult {
    /// The step that was applied.
    pub step: MigrationStep,
    /// Whether this particular step succeeded.
    pub success: bool,
    /// Human-readable message about what happened.
    pub message: String,
}

/// Migrates configuration values between schema versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigMigrator {
    /// All registered migration plans, keyed by "from_version -> to_version".
    pub plans: HashMap<String, MigrationPlan>,
    /// Ordered list of version identifiers (for chaining).
    pub version_chain: Vec<String>,
}

impl ConfigMigrator {
    /// Create a new empty migrator.
    pub fn new() -> Self {
        Self {
            plans: HashMap::new(),
            version_chain: Vec::new(),
        }
    }

    /// Register a migration plan.
    pub fn register_plan(&mut self, plan: MigrationPlan) {
        let key = format!("{}->{}", plan.from_version, plan.to_version);
        self.plans.insert(key, plan);
    }

    /// Set the ordered version chain for automatic multi-hop migration.
    pub fn set_version_chain(&mut self, versions: Vec<String>) {
        self.version_chain = versions;
    }

    /// Migrate a configuration value from one version to another.
    /// If no direct plan exists, attempts to chain through intermediate versions.
    pub fn migrate(&self, config: &Value, from: &str, to: &str) -> MigrationResult {
        if from == to {
            return MigrationResult {
                success: true,
                config: config.clone(),
                applied_steps: Vec::new(),
                errors: Vec::new(),
            };
        }

        // Try direct migration first
        let direct_key = format!("{}->{}", from, to);
        if let Some(plan) = self.plans.get(&direct_key) {
            return self.apply_plan(config, plan);
        }

        // Try reverse migration (in case the plans are registered backwards)
        // Actually, let's try to find a path through the version chain
        if !self.version_chain.is_empty() {
            let path = self.find_migration_path(from, to);
            if let Some(hops) = path {
                let mut current = config.clone();
                let mut all_results = Vec::new();
                let mut all_errors = Vec::new();
                let mut overall_success = true;

                for hop in hops {
                    let hop_key = format!("{}->{}", hop.from, hop.to);
                    if let Some(plan) = self.plans.get(&hop_key) {
                        let result = self.apply_plan(&current, plan);
                        if !result.success {
                            overall_success = false;
                            all_errors.extend(result.errors);
                        }
                        all_results.extend(result.applied_steps);
                        current = result.config;
                    } else {
                        overall_success = false;
                        all_errors.push(format!(
                            "missing migration plan for hop {}->{}",
                            hop.from, hop.to
                        ));
                    }
                }

                return MigrationResult {
                    success: overall_success,
                    config: current,
                    applied_steps: all_results,
                    errors: all_errors,
                };
            }
        }

        MigrationResult {
            success: false,
            config: config.clone(),
            applied_steps: Vec::new(),
            errors: vec![format!("no migration path from '{}' to '{}'", from, to)],
        }
    }

    /// Find a sequence of migration hops from source to target through the version chain.
    fn find_migration_path(&self, from: &str, to: &str) -> Option<Vec<MigrationHop>> {
        let from_idx = self.version_chain.iter().position(|v| v == from)?;
        let to_idx = self.version_chain.iter().position(|v| v == to)?;

        if from_idx >= to_idx {
            return None;
        }

        let mut hops = Vec::new();
        for i in from_idx..to_idx {
            let src = &self.version_chain[i];
            let dst = &self.version_chain[i + 1];
            hops.push(MigrationHop {
                from: src.clone(),
                to: dst.clone(),
            });
        }
        Some(hops)
    }

    /// Apply a single migration plan to a configuration value.
    fn apply_plan(&self, config: &Value, plan: &MigrationPlan) -> MigrationResult {
        let mut current = config.clone();
        let mut applied = Vec::new();
        let mut errors = Vec::new();
        let mut success = true;

        for step in &plan.steps {
            let result = self.apply_step(&mut current, step);
            let is_err = result.is_err();
            applied.push(MigrationStepResult {
                step: step.clone(),
                success: !is_err,
                message: result.clone().unwrap_or_default(),
            });
            if is_err {
                success = false;
                errors.push(result.unwrap_err());
            }
        }

        MigrationResult {
            success,
            config: current,
            applied_steps: applied,
            errors,
        }
    }

    /// Apply a single migration step, mutating the config in place.
    fn apply_step(&self, config: &mut Value, step: &MigrationStep) -> Result<String, String> {
        match step {
            MigrationStep::AddField {
                path,
                default_value,
            } => {
                self.set_at_path(config, path, default_value.clone())?;
                Ok(format!("added field '{}' with default", path))
            }
            MigrationStep::RemoveField { path } => {
                self.remove_at_path(config, path)?;
                Ok(format!("removed field '{}'", path))
            }
            MigrationStep::RenameField { old_path, new_path } => {
                let value = self
                    .get_at_path(config, old_path)
                    .ok_or_else(|| format!("field '{}' not found for rename", old_path))?
                    .clone();
                self.remove_at_path(config, old_path)?;
                self.set_at_path(config, new_path, value)?;
                Ok(format!("renamed '{}' to '{}'", old_path, new_path))
            }
            MigrationStep::TransformValue {
                path,
                transformation,
            } => {
                let current = self
                    .get_at_path_mut(config, path)
                    .ok_or_else(|| format!("field '{}' not found for transform", path))?;
                let transformed = self.apply_transformation(current, transformation)?;
                *current = transformed;
                Ok(format!("transformed field '{}'", path))
            }
            MigrationStep::SetDefault { path, value } => {
                if self.get_at_path(config, path).is_none() {
                    self.set_at_path(config, path, value.clone())?;
                    Ok(format!("set default for '{}' (field was absent)", path))
                } else {
                    Ok(format!(
                        "skipped default for '{}' (field already present)",
                        path
                    ))
                }
            }
        }
    }

    /// Apply a value transformation to a JSON value.
    fn apply_transformation(
        &self,
        value: &Value,
        tx: &ValueTransformation,
    ) -> Result<Value, String> {
        match tx {
            ValueTransformation::ToLowercase => {
                let s = value
                    .as_str()
                    .ok_or("ToLowercase requires a string value")?;
                Ok(Value::String(s.to_lowercase()))
            }
            ValueTransformation::ToUppercase => {
                let s = value
                    .as_str()
                    .ok_or("ToUppercase requires a string value")?;
                Ok(Value::String(s.to_uppercase()))
            }
            ValueTransformation::Trim => {
                let s = value.as_str().ok_or("Trim requires a string value")?;
                Ok(Value::String(s.trim().to_string()))
            }
            ValueTransformation::Multiply(factor) => {
                let n = value.as_f64().ok_or("Multiply requires a numeric value")?;
                Ok(Value::from(n * factor))
            }
            ValueTransformation::Add(offset) => {
                let n = value.as_f64().ok_or("Add requires a numeric value")?;
                Ok(Value::from(n + offset))
            }
            ValueTransformation::RenameVariant { from, to } => {
                let s = value
                    .as_str()
                    .ok_or("RenameVariant requires a string value")?;
                if s == from {
                    Ok(Value::String(to.clone()))
                } else {
                    Ok(value.clone())
                }
            }
            ValueTransformation::ParseInt => {
                let s = value.as_str().ok_or("ParseInt requires a string value")?;
                let n: i64 = s
                    .parse()
                    .map_err(|e| format!("failed to parse '{}' as integer: {}", s, e))?;
                Ok(Value::from(n))
            }
            ValueTransformation::MsToSeconds => {
                let n = value
                    .as_f64()
                    .ok_or("MsToSeconds requires a numeric value")?;
                Ok(Value::from(n / 1000.0))
            }
            ValueTransformation::SecondsToMs => {
                let n = value
                    .as_f64()
                    .ok_or("SecondsToMs requires a numeric value")?;
                Ok(Value::from(n * 1000.0))
            }
        }
    }

    /// Get a value at a dot-separated path.
    fn get_at_path<'a>(&self, config: &'a Value, path: &str) -> Option<&'a Value> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = config;
        for part in parts {
            match current {
                Value::Object(map) => {
                    current = map.get(part)?;
                }
                _ => return None,
            }
        }
        Some(current)
    }

    /// Get a mutable value at a dot-separated path.
    fn get_at_path_mut<'a>(&self, config: &'a mut Value, path: &str) -> Option<&'a mut Value> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = config;
        for part in parts {
            match current {
                Value::Object(map) => {
                    current = map.get_mut(part)?;
                }
                _ => return None,
            }
        }
        Some(current)
    }

    /// Set a value at a dot-separated path, creating intermediate objects as needed.
    fn set_at_path(&self, config: &mut Value, path: &str, value: Value) -> Result<(), String> {
        let parts: Vec<&str> = path.split('.').collect();
        if parts.is_empty() {
            return Err("empty path".to_string());
        }
        let mut current = config;
        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                // Last part: set the value
                match current {
                    Value::Object(map) => {
                        map.insert(part.to_string(), value);
                        return Ok(());
                    }
                    _ => return Err(format!("cannot set '{}' on non-object", path)),
                }
            } else {
                // Intermediate part: ensure object exists
                match current {
                    Value::Object(map) => {
                        if !map.contains_key(*part) {
                            map.insert(part.to_string(), Value::Object(serde_json::Map::new()));
                        }
                        current = map.get_mut(*part).unwrap();
                    }
                    _ => return Err(format!("cannot traverse '{}' through non-object", path)),
                }
            }
        }
        Ok(())
    }

    /// Remove a value at a dot-separated path.
    fn remove_at_path(&self, config: &mut Value, path: &str) -> Result<(), String> {
        let parts: Vec<&str> = path.split('.').collect();
        if parts.is_empty() {
            return Err("empty path".to_string());
        }
        let mut current = config;
        for (i, part) in parts.iter().enumerate() {
            match current {
                Value::Object(map) => {
                    if i == parts.len() - 1 {
                        map.remove(*part);
                        return Ok(());
                    }
                    current = map
                        .get_mut(*part)
                        .ok_or_else(|| format!("path '{}' does not exist", path))?;
                }
                _ => return Err(format!("cannot traverse '{}' through non-object", path)),
            }
        }
        Ok(())
    }
}

impl Default for ConfigMigrator {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal representation of a migration hop between two versions.
struct MigrationHop {
    from: String,
    to: String,
}

// ═══════════════════════════════════════════════════════════════
// Section 3: Environment Variable Interpolation
// ═══════════════════════════════════════════════════════════════

/// A parsed environment variable reference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvRef {
    /// The environment variable name.
    pub var_name: String,
    /// Default value if the variable is not set (from `${VAR:-default}` syntax).
    pub default_value: Option<String>,
    /// Required error message if the variable is not set (from `${VAR:?msg}` syntax).
    pub required_message: Option<String>,
    /// Whether this reference uses the default fallback syntax.
    pub has_default: bool,
    /// Whether this reference uses the required-error syntax.
    pub is_required: bool,
}

impl EnvRef {
    /// Resolve this environment variable reference against the current process environment.
    pub fn resolve(&self, env: &HashMap<String, String>) -> Result<String, String> {
        if let Some(val) = env.get(&self.var_name) {
            Ok(val.clone())
        } else if self.has_default {
            Ok(self.default_value.clone().unwrap_or_default())
        } else if self.is_required {
            Err(format!(
                "required environment variable '{}' is not set: {}",
                self.var_name,
                self.required_message.as_deref().unwrap_or("(no message)")
            ))
        } else {
            Err(format!(
                "environment variable '{}' is not set",
                self.var_name
            ))
        }
    }
}

/// Result of environment variable interpolation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterpolationResult {
    /// The fully interpolated configuration value.
    pub value: Value,
    /// All environment variable references that were resolved.
    pub resolved_refs: Vec<EnvRef>,
    /// Validation errors for missing or invalid references.
    pub errors: Vec<String>,
    /// Whether interpolation was fully successful.
    pub success: bool,
}

/// Parses and resolves environment variable references in configuration values.
///
/// Supports three syntaxes:
/// - `${VAR_NAME}` — required, error if not set
/// - `${VAR_NAME:-default}` — optional, uses `default` if not set
/// - `${VAR_NAME:?error_message}` — required with custom error message
///
/// Nested interpolation is supported: `${OUTER_${INNER}}` resolves the inner
/// variable first, then uses the result as the outer variable name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvInterpolator {
    /// Custom environment variable overrides (for testing or explicit injection).
    pub env_overrides: HashMap<String, String>,
    /// Maximum recursion depth for nested interpolation to prevent infinite loops.
    pub max_depth: usize,
}

impl EnvInterpolator {
    /// Create a new interpolator with default settings.
    pub fn new() -> Self {
        Self {
            env_overrides: HashMap::new(),
            max_depth: 10,
        }
    }

    /// Create an interpolator with explicit environment overrides.
    pub fn with_env(env: HashMap<String, String>) -> Self {
        Self {
            env_overrides: env,
            max_depth: 10,
        }
    }

    /// Look up an environment variable: check overrides first, then process env.
    fn get_env(&self, key: &str) -> Option<String> {
        if let Some(val) = self.env_overrides.get(key) {
            Some(val.clone())
        } else {
            std::env::var(key).ok()
        }
    }

    /// Interpolate all environment variable references in a configuration value.
    pub fn interpolate(&self, value: &Value) -> InterpolationResult {
        let mut resolved_refs = Vec::new();
        let mut errors = Vec::new();
        let interpolated = self.interpolate_recursive(value, &mut resolved_refs, &mut errors, 0);
        let success = errors.is_empty();
        InterpolationResult {
            value: interpolated,
            resolved_refs,
            errors,
            success,
        }
    }

    /// Recursively interpolate environment variable references.
    fn interpolate_recursive(
        &self,
        value: &Value,
        resolved: &mut Vec<EnvRef>,
        errors: &mut Vec<String>,
        depth: usize,
    ) -> Value {
        if depth > self.max_depth {
            errors.push(format!(
                "maximum interpolation depth ({}) exceeded",
                self.max_depth
            ));
            return value.clone();
        }
        match value {
            Value::String(s) => self.interpolate_string(s, resolved, errors, depth),
            Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (k, v) in map {
                    let new_key_val = self.interpolate_string(k, resolved, errors, depth);
                    let new_key = new_key_val.as_str().unwrap_or(k).to_string();
                    let new_val = self.interpolate_recursive(v, resolved, errors, depth + 1);
                    new_map.insert(new_key, new_val);
                }
                Value::Object(new_map)
            }
            Value::Array(arr) => {
                let new_arr: Vec<Value> = arr
                    .iter()
                    .map(|v| self.interpolate_recursive(v, resolved, errors, depth + 1))
                    .collect();
                Value::Array(new_arr)
            }
            other => other.clone(),
        }
    }

    /// Interpolate a single string, resolving all `${...}` references.
    fn interpolate_string(
        &self,
        input: &str,
        resolved: &mut Vec<EnvRef>,
        errors: &mut Vec<String>,
        depth: usize,
    ) -> Value {
        let mut result = String::new();
        let mut chars = input.chars().peekable();
        let mut has_refs = false;

        while let Some(ch) = chars.next() {
            if ch == '$' && chars.peek() == Some(&'{') {
                chars.next(); // consume '{'
                has_refs = true;
                // Find the matching closing brace, handling nested ${}
                let inner = self.extract_braced_content(&mut chars, errors);
                // Parse the inner content as an EnvRef
                let env_ref = self.parse_env_ref(&inner);
                // For nested interpolation: check if var_name itself contains ${}
                let var_name = if env_ref.var_name.contains("${") {
                    // Recursively interpolate the variable name
                    let name_val =
                        self.interpolate_string(&env_ref.var_name, resolved, errors, depth + 1);
                    match name_val {
                        Value::String(s) => s,
                        other => format!("{}", other),
                    }
                } else {
                    env_ref.var_name.clone()
                };
                let resolved_ref = EnvRef {
                    var_name: var_name.clone(),
                    default_value: env_ref.default_value.clone(),
                    required_message: env_ref.required_message.clone(),
                    has_default: env_ref.has_default,
                    is_required: env_ref.is_required,
                };
                match self.get_env(&var_name) {
                    Some(val) => {
                        result.push_str(&val);
                        resolved.push(resolved_ref);
                    }
                    None if resolved_ref.has_default => {
                        result.push_str(resolved_ref.default_value.as_deref().unwrap_or(""));
                        resolved.push(resolved_ref);
                    }
                    None if resolved_ref.is_required => {
                        let msg = format!(
                            "required environment variable '{}' is not set: {}",
                            var_name,
                            resolved_ref
                                .required_message
                                .as_deref()
                                .unwrap_or("(no message)")
                        );
                        errors.push(msg.clone());
                        result.push_str(&format!("${{{}}}", inner));
                        resolved.push(resolved_ref);
                    }
                    None => {
                        let msg = format!("environment variable '{}' is not set", var_name);
                        errors.push(msg);
                        result.push_str(&format!("${{{}}}", inner));
                        resolved.push(resolved_ref);
                    }
                }
            } else {
                result.push(ch);
            }
        }

        if has_refs {
            // Attempt to parse the result as JSON; if it parses, return the typed value
            if let Ok(parsed) = serde_json::from_str::<Value>(&result) {
                return parsed;
            }
        }
        Value::String(result)
    }

    /// Extract content between matched braces, handling nesting.
    fn extract_braced_content(
        &self,
        chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
        errors: &mut Vec<String>,
    ) -> String {
        let mut content = String::new();
        let mut depth = 1usize;

        while let Some(ch) = chars.next() {
            match ch {
                '{' => {
                    depth += 1;
                    content.push(ch);
                }
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return content;
                    }
                    content.push(ch);
                }
                _ => {
                    content.push(ch);
                }
            }
        }

        errors.push("unmatched '${' — missing closing '}'".to_string());
        content
    }

    /// Parse the inner content of `${...}` into an EnvRef.
    fn parse_env_ref(&self, inner: &str) -> EnvRef {
        // Check for ${VAR:-default} syntax
        if let Some(idx) = inner.find(":-") {
            let var_name = inner[..idx].to_string();
            let default_val = inner[idx + 2..].to_string();
            return EnvRef {
                var_name,
                default_value: Some(default_val),
                required_message: None,
                has_default: true,
                is_required: false,
            };
        }

        // Check for ${VAR:?error} syntax
        if let Some(idx) = inner.find(":?") {
            let var_name = inner[..idx].to_string();
            let err_msg = inner[idx + 2..].to_string();
            return EnvRef {
                var_name,
                default_value: None,
                required_message: Some(err_msg),
                has_default: false,
                is_required: true,
            };
        }

        // Plain ${VAR} — treat as required
        EnvRef {
            var_name: inner.to_string(),
            default_value: None,
            required_message: None,
            has_default: false,
            is_required: false,
        }
    }

    /// Validate that all required environment variables referenced in a value are available.
    pub fn validate_required_vars(&self, value: &Value) -> Vec<EnvRef> {
        let mut required = Vec::new();
        self.collect_required_refs(value, &mut required, 0);
        required
    }

    /// Recursively collect all required env var references.
    fn collect_required_refs(&self, value: &Value, required: &mut Vec<EnvRef>, depth: usize) {
        if depth > self.max_depth {
            return;
        }
        match value {
            Value::String(s) => {
                let mut chars = s.chars().peekable();
                while let Some(ch) = chars.next() {
                    if ch == '$' && chars.peek() == Some(&'{') {
                        chars.next();
                        let mut errors = Vec::new();
                        let inner = self.extract_braced_content(&mut chars, &mut errors);
                        let env_ref = self.parse_env_ref(&inner);
                        let has_nested = env_ref.var_name.contains("${");
                        if env_ref.is_required || (!env_ref.has_default && !env_ref.is_required) {
                            required.push(env_ref);
                        }
                        // Recurse into var_name for nested refs
                        if has_nested {
                            let var_name = required
                                .last()
                                .map(|r| r.var_name.clone())
                                .unwrap_or_default();
                            self.collect_required_refs(
                                &Value::String(var_name),
                                required,
                                depth + 1,
                            );
                        }
                    }
                }
            }
            Value::Object(map) => {
                for (k, v) in map {
                    self.collect_required_refs(&Value::String(k.clone()), required, depth + 1);
                    self.collect_required_refs(v, required, depth + 1);
                }
            }
            Value::Array(arr) => {
                for v in arr {
                    self.collect_required_refs(v, required, depth + 1);
                }
            }
            _ => {}
        }
    }
}

impl Default for EnvInterpolator {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 4: Configuration Diffing
// ═══════════════════════════════════════════════════════════════

/// Classification of a configuration change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ChangeClassification {
    /// Breaking change: removed field, type change, tightened constraint.
    Breaking,
    /// Non-breaking change: added field, relaxed constraint.
    NonBreaking,
    /// Neutral change: value change within existing constraints.
    Neutral,
}

impl std::fmt::Display for ChangeClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangeClassification::Breaking => write!(f, "breaking"),
            ChangeClassification::NonBreaking => write!(f, "non-breaking"),
            ChangeClassification::Neutral => write!(f, "neutral"),
        }
    }
}

/// The kind of difference detected between two configuration versions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DiffKind {
    /// A field was added in the new version.
    FieldAdded,
    /// A field was removed in the new version.
    FieldRemoved,
    /// A field's value changed.
    ValueChanged,
    /// A field's type changed.
    TypeChanged,
    /// A constraint was tightened (e.g., new pattern, narrower range).
    ConstraintTightened,
    /// A constraint was relaxed (e.g., wider range, removed pattern).
    ConstraintRelaxed,
    /// A required field was added.
    RequiredAdded,
    /// A required field was removed.
    RequiredRemoved,
    /// A field was renamed (detected as remove + add).
    FieldRenamed,
}

/// A single diff entry describing one change between configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    /// Dot-separated path of the changed field.
    pub path: String,
    /// What kind of change occurred.
    pub kind: DiffKind,
    /// Classification of impact.
    pub classification: ChangeClassification,
    /// Old value (if applicable).
    pub old_value: Option<Value>,
    /// New value (if applicable).
    pub new_value: Option<Value>,
    /// Human-readable description.
    pub description: String,
}

/// Complete diff result between two configuration versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigDiff {
    /// All individual diff entries.
    pub entries: Vec<DiffEntry>,
    /// Whether any breaking changes were detected.
    pub has_breaking_changes: bool,
    /// Count of breaking changes.
    pub breaking_count: usize,
    /// Count of non-breaking changes.
    pub non_breaking_count: usize,
    /// Count of neutral changes.
    pub neutral_count: usize,
    /// Summary of the diff.
    pub summary: String,
}

impl ConfigDiff {
    /// Generate a human-readable summary string.
    pub fn generate_summary(&self) -> String {
        let parts = vec![
            format!("{} breaking", self.breaking_count),
            format!("{} non-breaking", self.non_breaking_count),
            format!("{} neutral", self.neutral_count),
        ];
        format!("changes: {}", parts.join(", "))
    }
}

/// Computes diffs between two configuration values, optionally classifying
/// changes against a pair of schemas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigDiffer {
    /// Old schema (for classifying constraint changes).
    pub old_schema: Option<SchemaNode>,
    /// New schema (for classifying constraint changes).
    pub new_schema: Option<SchemaNode>,
    /// Maximum depth for recursive diffing.
    pub max_depth: usize,
}

impl ConfigDiffer {
    /// Create a new differ without schema-based classification.
    pub fn new() -> Self {
        Self {
            old_schema: None,
            new_schema: None,
            max_depth: 50,
        }
    }

    /// Create a new differ with schema-based classification.
    pub fn with_schemas(old_schema: SchemaNode, new_schema: SchemaNode) -> Self {
        Self {
            old_schema: Some(old_schema),
            new_schema: Some(new_schema),
            max_depth: 50,
        }
    }

    /// Compute the diff between two configuration values.
    pub fn diff(&self, old: &Value, new: &Value) -> ConfigDiff {
        let mut entries = Vec::new();
        self.diff_recursive(old, new, "", &mut entries, 0);

        // Classify each entry
        for entry in &mut entries {
            self.classify_entry(entry);
        }

        let breaking_count = entries
            .iter()
            .filter(|e| e.classification == ChangeClassification::Breaking)
            .count();
        let non_breaking_count = entries
            .iter()
            .filter(|e| e.classification == ChangeClassification::NonBreaking)
            .count();
        let neutral_count = entries
            .iter()
            .filter(|e| e.classification == ChangeClassification::Neutral)
            .count();
        let has_breaking = breaking_count > 0;

        let summary = if has_breaking {
            format!(
                "BREAKING: {} breaking, {} non-breaking, {} neutral changes",
                breaking_count, non_breaking_count, neutral_count
            )
        } else {
            format!(
                "OK: {} non-breaking, {} neutral changes",
                non_breaking_count, neutral_count
            )
        };

        ConfigDiff {
            entries,
            has_breaking_changes: has_breaking,
            breaking_count,
            non_breaking_count,
            neutral_count,
            summary,
        }
    }

    /// Recursively diff two values, collecting entries.
    fn diff_recursive(
        &self,
        old: &Value,
        new: &Value,
        path: &str,
        entries: &mut Vec<DiffEntry>,
        depth: usize,
    ) {
        if depth > self.max_depth {
            return;
        }

        match (old, new) {
            (Value::Object(old_map), Value::Object(new_map)) => {
                // Find removed fields
                for key in old_map.keys() {
                    if !new_map.contains_key(key.as_str()) {
                        let field_path = self.join_path(path, key);
                        entries.push(DiffEntry {
                            path: field_path.clone(),
                            kind: DiffKind::FieldRemoved,
                            classification: ChangeClassification::Neutral, // will be classified below
                            old_value: Some(old_map.get(key).unwrap().clone()),
                            new_value: None,
                            description: format!("field '{}' was removed", field_path),
                        });
                    }
                }
                // Find added fields
                for key in new_map.keys() {
                    if !old_map.contains_key(key.as_str()) {
                        let field_path = self.join_path(path, key);
                        entries.push(DiffEntry {
                            path: field_path.clone(),
                            kind: DiffKind::FieldAdded,
                            classification: ChangeClassification::Neutral,
                            old_value: None,
                            new_value: Some(new_map.get(key).unwrap().clone()),
                            description: format!("field '{}' was added", field_path),
                        });
                    }
                }
                // Recurse into common fields
                for key in old_map.keys() {
                    if let Some(new_val) = new_map.get(key.as_str()) {
                        let field_path = self.join_path(path, key);
                        self.diff_recursive(
                            old_map.get(key.as_str()).unwrap(),
                            new_val,
                            &field_path,
                            entries,
                            depth + 1,
                        );
                    }
                }
            }
            (Value::Array(old_arr), Value::Array(new_arr)) => {
                let max_len = old_arr.len().max(new_arr.len());
                for i in 0..max_len {
                    let idx_path = format!("{}[{}]", path, i);
                    match (old_arr.get(i), new_arr.get(i)) {
                        (Some(o), Some(n)) => {
                            if o != n {
                                entries.push(DiffEntry {
                                    path: idx_path,
                                    kind: DiffKind::ValueChanged,
                                    classification: ChangeClassification::Neutral,
                                    old_value: Some(o.clone()),
                                    new_value: Some(n.clone()),
                                    description: format!("array element at index {} changed", i),
                                });
                            }
                        }
                        (Some(o), None) => {
                            entries.push(DiffEntry {
                                path: idx_path,
                                kind: DiffKind::FieldRemoved,
                                classification: ChangeClassification::Neutral,
                                old_value: Some(o.clone()),
                                new_value: None,
                                description: format!("array element at index {} removed", i),
                            });
                        }
                        (None, Some(n)) => {
                            entries.push(DiffEntry {
                                path: idx_path,
                                kind: DiffKind::FieldAdded,
                                classification: ChangeClassification::Neutral,
                                old_value: None,
                                new_value: Some(n.clone()),
                                description: format!("array element at index {} added", i),
                            });
                        }
                        (None, None) => {}
                    }
                }
            }
            (o, n) => {
                if o != n {
                    let kind = if self.values_have_different_type(o, n) {
                        DiffKind::TypeChanged
                    } else {
                        DiffKind::ValueChanged
                    };
                    entries.push(DiffEntry {
                        path: path.to_string(),
                        kind,
                        classification: ChangeClassification::Neutral,
                        old_value: Some(o.clone()),
                        new_value: Some(n.clone()),
                        description: format!("value at '{}' changed", path),
                    });
                }
            }
        }
    }

    /// Classify a diff entry based on its kind and schema context.
    fn classify_entry(&self, entry: &mut DiffEntry) {
        match entry.kind {
            DiffKind::FieldRemoved => {
                entry.classification = ChangeClassification::Breaking;
            }
            DiffKind::FieldAdded => {
                entry.classification = ChangeClassification::NonBreaking;
            }
            DiffKind::TypeChanged => {
                entry.classification = ChangeClassification::Breaking;
            }
            DiffKind::RequiredAdded => {
                entry.classification = ChangeClassification::Breaking;
            }
            DiffKind::RequiredRemoved => {
                entry.classification = ChangeClassification::NonBreaking;
            }
            DiffKind::ConstraintTightened => {
                entry.classification = ChangeClassification::Breaking;
            }
            DiffKind::ConstraintRelaxed => {
                entry.classification = ChangeClassification::NonBreaking;
            }
            DiffKind::ValueChanged => {
                entry.classification = ChangeClassification::Neutral;
            }
            DiffKind::FieldRenamed => {
                entry.classification = ChangeClassification::Breaking;
            }
        }

        // Schema-aware classification override
        if let (Some(old_schema), Some(new_schema)) =
            (self.old_schema.as_ref(), self.new_schema.as_ref())
        {
            self.schema_aware_classify(entry, old_schema, new_schema);
        }
    }

    /// Schema-aware classification: check if the field is required in old schema.
    fn schema_aware_classify(
        &self,
        entry: &mut DiffEntry,
        old_schema: &SchemaNode,
        new_schema: &SchemaNode,
    ) {
        if entry.kind == DiffKind::FieldRemoved {
            // Check if the removed field was optional in the old schema
            let parts: Vec<&str> = entry.path.split('.').collect();
            let mut current = old_schema;
            for (i, part) in parts.iter().enumerate() {
                if let Some(prop) = current.properties.get(*part) {
                    if i == parts.len() - 1 {
                        // Check if this field was required
                        let is_required = old_schema
                            .object_constraints
                            .as_ref()
                            .map_or(false, |oc| oc.required.contains(&part.to_string()));
                        if !is_required {
                            // Removing an optional field is non-breaking
                            entry.classification = ChangeClassification::NonBreaking;
                        }
                    } else {
                        current = prop;
                    }
                } else {
                    break;
                }
            }
        }

        if entry.kind == DiffKind::FieldAdded {
            // Adding a field that's not required is neutral
            let parts: Vec<&str> = entry.path.split('.').collect();
            let mut current = new_schema;
            for (i, part) in parts.iter().enumerate() {
                if let Some(prop) = current.properties.get(*part) {
                    if i == parts.len() - 1 {
                        let is_required = new_schema
                            .object_constraints
                            .as_ref()
                            .map_or(false, |oc| oc.required.contains(&part.to_string()));
                        if !is_required {
                            entry.classification = ChangeClassification::Neutral;
                        }
                    } else {
                        current = prop;
                    }
                } else {
                    break;
                }
            }
        }
    }

    /// Check if two values have different JSON types.
    fn values_have_different_type(&self, a: &Value, b: &Value) -> bool {
        match (a, b) {
            (Value::Null, Value::Null) => false,
            (Value::Bool(_), Value::Bool(_)) => false,
            (Value::Number(_), Value::Number(_)) => false,
            (Value::String(_), Value::String(_)) => false,
            (Value::Array(_), Value::Array(_)) => false,
            (Value::Object(_), Value::Object(_)) => false,
            _ => true,
        }
    }

    /// Join a parent path with a child segment.
    fn join_path(&self, parent: &str, child: &str) -> String {
        if parent.is_empty() {
            child.to_string()
        } else {
            format!("{}.{}", parent, child)
        }
    }

    /// Compute schema-level diffs (constraint changes between two schemas).
    pub fn diff_schemas(&self, old: &SchemaNode, new: &SchemaNode, path: &str) -> Vec<DiffEntry> {
        let mut entries = Vec::new();

        // Check type changes
        if old.schema_type != new.schema_type {
            entries.push(DiffEntry {
                path: path.to_string(),
                kind: DiffKind::TypeChanged,
                classification: ChangeClassification::Breaking,
                old_value: old
                    .schema_type
                    .as_ref()
                    .map(|t| Value::String(t.to_string())),
                new_value: new
                    .schema_type
                    .as_ref()
                    .map(|t| Value::String(t.to_string())),
                description: format!("type at '{}' changed", path),
            });
        }

        // Check number constraint changes
        if let (Some(old_nc), Some(new_nc)) = (&old.number_constraints, &new.number_constraints) {
            if old_nc.minimum != new_nc.minimum {
                let kind = if Self::is_tighter_min(old_nc.minimum, new_nc.minimum) {
                    DiffKind::ConstraintTightened
                } else {
                    DiffKind::ConstraintRelaxed
                };
                entries.push(DiffEntry {
                    path: format!("{}.minimum", path),
                    kind,
                    classification: ChangeClassification::Neutral,
                    old_value: old_nc.minimum.map(Value::from),
                    new_value: new_nc.minimum.map(Value::from),
                    description: format!("minimum constraint at '{}' changed", path),
                });
            }
            if old_nc.maximum != new_nc.maximum {
                let kind = if Self::is_tighter_max(old_nc.maximum, new_nc.maximum) {
                    DiffKind::ConstraintTightened
                } else {
                    DiffKind::ConstraintRelaxed
                };
                entries.push(DiffEntry {
                    path: format!("{}.maximum", path),
                    kind,
                    classification: ChangeClassification::Neutral,
                    old_value: old_nc.maximum.map(Value::from),
                    new_value: new_nc.maximum.map(Value::from),
                    description: format!("maximum constraint at '{}' changed", path),
                });
            }
        }

        // Check required field changes
        if let (Some(old_oc), Some(new_oc)) = (&old.object_constraints, &new.object_constraints) {
            let old_required: BTreeSet<&String> = old_oc.required.iter().collect();
            let new_required: BTreeSet<&String> = new_oc.required.iter().collect();

            for field in new_required.difference(&old_required) {
                entries.push(DiffEntry {
                    path: format!("{}.required.{}", path, field),
                    kind: DiffKind::RequiredAdded,
                    classification: ChangeClassification::Neutral,
                    old_value: None,
                    new_value: Some(Value::String(field.to_string())),
                    description: format!("field '{}' is now required", field),
                });
            }
            for field in old_required.difference(&new_required) {
                entries.push(DiffEntry {
                    path: format!("{}.required.{}", path, field),
                    kind: DiffKind::RequiredRemoved,
                    classification: ChangeClassification::Neutral,
                    old_value: Some(Value::String(field.to_string())),
                    new_value: None,
                    description: format!("field '{}' is no longer required", field),
                });
            }
        }

        // Recurse into properties
        for (key, new_prop) in &new.properties {
            let prop_path = self.join_path(path, key);
            if let Some(old_prop) = old.properties.get(key) {
                entries.extend(self.diff_schemas(old_prop, new_prop, &prop_path));
            }
        }

        // Classify all entries
        for entry in &mut entries {
            self.classify_entry(entry);
        }

        entries
    }

    /// Check if a new minimum is tighter than the old minimum.
    fn is_tighter_min(old: Option<f64>, new: Option<f64>) -> bool {
        match (old, new) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(o), Some(n)) => n > o,
        }
    }

    /// Check if a new maximum is tighter than the old maximum.
    fn is_tighter_max(old: Option<f64>, new: Option<f64>) -> bool {
        match (old, new) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(o), Some(n)) => n < o,
        }
    }
}

impl Default for ConfigDiffer {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 5: Configuration Templates
// ═══════════════════════════════════════════════════════════════

/// A configuration template with placeholder support.
///
/// Placeholders use the syntax `{{placeholder_name}}` and are replaced
/// during instantiation. Templates support inheritance: a template can
/// extend a base template and override specific values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigTemplate {
    /// Unique template identifier.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// The template body with `{{placeholder}}` markers.
    pub template: Value,
    /// Parent template name for inheritance.
    #[serde(default)]
    pub extends: Option<String>,
    /// Override values that replace fields in the parent template.
    #[serde(default)]
    pub overrides: BTreeMap<String, Value>,
    /// Expected placeholder keys with optional descriptions and defaults.
    #[serde(default)]
    pub placeholders: BTreeMap<String, PlaceholderDef>,
    /// Schema to validate the instantiated config against.
    #[serde(default)]
    pub validation_schema: Option<SchemaNode>,
    /// Tags for categorising templates.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Definition of a single template placeholder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaceholderDef {
    /// Description of what this placeholder represents.
    pub description: String,
    /// Default value if not provided during instantiation.
    #[serde(default)]
    pub default_value: Option<Value>,
    /// Whether this placeholder must be provided.
    #[serde(default = "default_true_obj")]
    pub required: bool,
    /// Expected type of the placeholder value.
    #[serde(default)]
    pub expected_type: Option<SchemaType>,
}

/// Result of instantiating a configuration template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInstanceResult {
    /// The instantiated configuration value.
    pub config: Value,
    /// The template that was used.
    pub template_name: String,
    /// Placeholder values that were provided.
    pub provided_values: BTreeMap<String, Value>,
    /// Validation result (if a schema was attached to the template).
    pub validation: Option<ValidationResult>,
    /// Whether instantiation and validation succeeded.
    pub success: bool,
    /// Any errors encountered.
    pub errors: Vec<String>,
}

/// Manages a collection of configuration templates and handles instantiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateEngine {
    /// All registered templates, keyed by name.
    pub templates: HashMap<String, ConfigTemplate>,
}

impl TemplateEngine {
    /// Create a new empty template engine.
    pub fn new() -> Self {
        Self {
            templates: HashMap::new(),
        }
    }

    /// Register a template.
    pub fn register(&mut self, template: ConfigTemplate) {
        self.templates.insert(template.name.clone(), template);
    }

    /// Resolve template inheritance: merge base template with overrides.
    fn resolve_inheritance(&self, template: &ConfigTemplate) -> Result<Value, String> {
        if let Some(ref base_name) = template.extends {
            let base = self
                .templates
                .get(base_name)
                .ok_or_else(|| format!("base template '{}' not found", base_name))?
                .clone();

            // Recursively resolve the base template first
            let mut base_value = self.resolve_inheritance(&base)?;

            // Apply overrides from the child template
            for (key, value) in &template.overrides {
                Self::deep_merge(&mut base_value, key, value.clone());
            }

            Ok(base_value)
        } else {
            Ok(template.template.clone())
        }
    }

    /// Deep-merge a value at a dot-separated path into the target.
    fn deep_merge(target: &mut Value, path: &str, value: Value) {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = target;
        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                match current {
                    Value::Object(map) => {
                        map.insert(part.to_string(), value);
                        return;
                    }
                    _ => {}
                }
            } else {
                match current {
                    Value::Object(map) => {
                        if !map.contains_key(*part) {
                            map.insert(part.to_string(), Value::Object(serde_json::Map::new()));
                        }
                        current = map.get_mut(*part).unwrap();
                    }
                    _ => return,
                }
            }
        }
    }

    /// Instantiate a template with the given placeholder values.
    pub fn instantiate(
        &self,
        template_name: &str,
        values: BTreeMap<String, Value>,
    ) -> TemplateInstanceResult {
        let template = match self.templates.get(template_name) {
            Some(t) => t.clone(),
            None => {
                return TemplateInstanceResult {
                    config: Value::Null,
                    template_name: template_name.to_string(),
                    provided_values: values,
                    validation: None,
                    success: false,
                    errors: vec![format!("template '{}' not found", template_name)],
                };
            }
        };

        let mut errors = Vec::new();

        // Check required placeholders
        for (name, def) in &template.placeholders {
            if def.required && !values.contains_key(name) && def.default_value.is_none() {
                errors.push(format!(
                    "required placeholder '{}' not provided for template '{}'",
                    name, template_name
                ));
            }
        }

        if !errors.is_empty() {
            return TemplateInstanceResult {
                config: Value::Null,
                template_name: template_name.to_string(),
                provided_values: values,
                validation: None,
                success: false,
                errors,
            };
        }

        // Resolve inheritance to get the effective template
        let resolved_template = match self.resolve_inheritance(&template) {
            Ok(v) => v,
            Err(e) => {
                return TemplateInstanceResult {
                    config: Value::Null,
                    template_name: template_name.to_string(),
                    provided_values: values,
                    validation: None,
                    success: false,
                    errors: vec![e],
                };
            }
        };

        // Replace placeholders in the resolved template
        let config = self.replace_placeholders(&resolved_template, &values);

        // Validate against schema if present
        let validation = if let Some(ref schema) = template.validation_schema {
            let validator = SchemaValidator::new(schema.clone());
            let result = validator.validate(&config);
            Some(result)
        } else {
            None
        };

        let success = errors.is_empty() && validation.as_ref().map_or(true, |v| v.is_valid);

        TemplateInstanceResult {
            config,
            template_name: template_name.to_string(),
            provided_values: values,
            validation,
            success,
            errors,
        }
    }

    /// Recursively replace all `{{placeholder}}` markers in a value.
    fn replace_placeholders(&self, value: &Value, values: &BTreeMap<String, Value>) -> Value {
        match value {
            Value::String(s) => {
                let mut result = String::new();
                let mut chars = s.chars().peekable();
                while let Some(ch) = chars.next() {
                    if ch == '{' && chars.peek() == Some(&'{') {
                        chars.next(); // consume second '{'
                        let placeholder = self.extract_placeholder_name(&mut chars);
                        if let Some(val) = self.resolve_placeholder(&placeholder, values) {
                            result.push_str(&val);
                        } else {
                            result.push_str(&format!("{{{{{}}}}}", placeholder));
                        }
                    } else {
                        result.push(ch);
                    }
                }
                // Try to parse as JSON
                if let Ok(parsed) = serde_json::from_str::<Value>(&result) {
                    parsed
                } else {
                    Value::String(result)
                }
            }
            Value::Object(map) => {
                let new_map: serde_json::Map<String, Value> = map
                    .iter()
                    .map(|(k, v)| {
                        let new_key = self.replace_placeholders(&Value::String(k.clone()), values);
                        let new_val = self.replace_placeholders(v, values);
                        (new_key.as_str().unwrap_or(k).to_string(), new_val)
                    })
                    .collect();
                Value::Object(new_map)
            }
            Value::Array(arr) => {
                let new_arr: Vec<Value> = arr
                    .iter()
                    .map(|v| self.replace_placeholders(v, values))
                    .collect();
                Value::Array(new_arr)
            }
            other => other.clone(),
        }
    }

    /// Extract a placeholder name between `{{` and `}}`.
    fn extract_placeholder_name(
        &self,
        chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    ) -> String {
        let mut name = String::new();
        while let Some(ch) = chars.next() {
            if ch == '}' && chars.peek() == Some(&'}') {
                chars.next(); // consume second '}'
                return name.trim().to_string();
            }
            name.push(ch);
        }
        name.trim().to_string()
    }

    /// Resolve a placeholder to its string representation.
    fn resolve_placeholder(&self, name: &str, values: &BTreeMap<String, Value>) -> Option<String> {
        if let Some(val) = values.get(name) {
            Some(format!("{}", val))
        } else {
            // Check if the template defines a default
            None
        }
    }

    /// List all available template names.
    pub fn list_templates(&self) -> Vec<&str> {
        self.templates.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for TemplateEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════
// Section 6: Hot Reload Support
// ═══════════════════════════════════════════════════════════════════════════

/// A subsystem that can be affected by configuration changes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SubsystemId {
    /// The Sentinel subsystem (drift detection, trust state updates).
    Sentinel,
    /// The Phoenix subsystem (recovery intelligence).
    Phoenix,
    /// The Anchor subsystem (root of trust, attestation).
    Anchor,
    /// The Adapter subsystem (adaptive orchestration).
    Adapter,
    /// The TrustProof subsystem.
    TrustProof,
    /// The Health subsystem.
    Health,
    /// The Audit subsystem.
    Audit,
    /// The Distributed subsystem (consensus, gossip).
    Distributed,
    /// The Crypto subsystem.
    Crypto,
    /// The Scheduler subsystem.
    Scheduler,
    /// The global ANANTA configuration.
    Global,
}

impl std::fmt::Display for SubsystemId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubsystemId::Sentinel => write!(f, "sentinel"),
            SubsystemId::Phoenix => write!(f, "phoenix"),
            SubsystemId::Anchor => write!(f, "anchor"),
            SubsystemId::Adapter => write!(f, "adapter"),
            SubsystemId::TrustProof => write!(f, "trust_proof"),
            SubsystemId::Health => write!(f, "health"),
            SubsystemId::Audit => write!(f, "audit"),
            SubsystemId::Distributed => write!(f, "distributed"),
            SubsystemId::Crypto => write!(f, "crypto"),
            SubsystemId::Scheduler => write!(f, "scheduler"),
            SubsystemId::Global => write!(f, "global"),
        }
    }
}

/// Strategy for reloading a subsystem after a configuration change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ReloadStrategy {
    /// No action needed — change does not affect this subsystem.
    NoAction,
    /// Apply changes live without restarting any loops.
    HotReload,
    /// Restart the subsystem's background loops.
    Restart,
    /// Full system restart required.
    FullRestart,
}

impl std::fmt::Display for ReloadStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReloadStrategy::NoAction => write!(f, "no_action"),
            ReloadStrategy::HotReload => write!(f, "hot_reload"),
            ReloadStrategy::Restart => write!(f, "restart"),
            ReloadStrategy::FullRestart => write!(f, "full_restart"),
        }
    }
}

/// A single action in a reload plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadAction {
    /// The subsystem to reload.
    pub subsystem: SubsystemId,
    /// The reload strategy for this subsystem.
    pub strategy: ReloadStrategy,
    /// The configuration fields that changed for this subsystem.
    pub changed_fields: Vec<String>,
    /// Human-readable reason for the reload.
    pub reason: String,
    /// Order in which this action should be applied (lower = first).
    pub priority: u32,
}

/// A complete reload plan generated from a configuration diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadPlan {
    /// All reload actions, ordered by priority.
    pub actions: Vec<ReloadAction>,
    /// Whether any action requires a full restart.
    pub requires_full_restart: bool,
    /// Whether any action requires a subsystem restart.
    pub requires_restart: bool,
    /// Whether hot-reload is sufficient for all changes.
    pub hot_reload_sufficient: bool,
    /// Timestamp when this plan was generated.
    pub generated_at: DateTime<Utc>,
    /// Summary of the plan.
    pub summary: String,
}

impl ReloadPlan {
    /// Generate a human-readable summary.
    pub fn generate_summary(&self) -> String {
        let restart_count = self
            .actions
            .iter()
            .filter(|a| a.strategy == ReloadStrategy::Restart)
            .count();
        let hot_count = self
            .actions
            .iter()
            .filter(|a| a.strategy == ReloadStrategy::HotReload)
            .count();
        let no_action_count = self
            .actions
            .iter()
            .filter(|a| a.strategy == ReloadStrategy::NoAction)
            .count();
        format!(
            "reload plan: {} restart(s), {} hot-reload(s), {} no-action(s)",
            restart_count, hot_count, no_action_count
        )
    }
}

/// Mapping from configuration path prefixes to subsystems and their reload characteristics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubsystemMapping {
    /// Path prefix (e.g. "sentinel") mapped to subsystem ID.
    pub path_prefix: String,
    /// The subsystem this path belongs to.
    pub subsystem: SubsystemId,
    /// Default reload strategy for changes under this path.
    pub default_strategy: ReloadStrategy,
    /// Specific fields that require a restart (overriding the default strategy).
    #[serde(default)]
    pub restart_fields: Vec<String>,
    /// Specific fields that can be hot-reloaded (overriding the default strategy).
    #[serde(default)]
    pub hot_reload_fields: Vec<String>,
}

/// Detects configuration changes and generates reload plans.
///
/// The hot-reload manager analyses diffs between old and new configuration,
/// determines which subsystems are affected, and produces an ordered
/// reload plan that minimises disruption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotReloadManager {
    /// Subsystem path mappings.
    pub subsystem_mappings: Vec<SubsystemMapping>,
    /// The differ used to compute configuration diffs.
    pub differ: ConfigDiffer,
}

impl HotReloadManager {
    /// Create a new hot-reload manager with default subsystem mappings.
    pub fn new() -> Self {
        let mappings = vec![
            SubsystemMapping {
                path_prefix: "sentinel".to_string(),
                subsystem: SubsystemId::Sentinel,
                default_strategy: ReloadStrategy::HotReload,
                restart_fields: vec!["sentinel.enable_full_drift_detection".to_string()],
                hot_reload_fields: vec![
                    "sentinel.check_interval_ms".to_string(),
                    "sentinel.drift_window_size".to_string(),
                    "sentinel.drift_sigma_threshold".to_string(),
                ],
            },
            SubsystemMapping {
                path_prefix: "phoenix".to_string(),
                subsystem: SubsystemId::Phoenix,
                default_strategy: ReloadStrategy::HotReload,
                restart_fields: vec!["phoenix.autonomous".to_string()],
                hot_reload_fields: vec![
                    "phoenix.max_recovery_actions_per_hour".to_string(),
                    "phoenix.recovery_cooldown_ms".to_string(),
                    "phoenix.action_confidence_threshold".to_string(),
                ],
            },
            SubsystemMapping {
                path_prefix: "anchor".to_string(),
                subsystem: SubsystemId::Anchor,
                default_strategy: ReloadStrategy::Restart,
                restart_fields: vec![
                    "anchor.enable_hardware_root".to_string(),
                    "anchor.manifest_path".to_string(),
                ],
                hot_reload_fields: vec!["anchor.key_rotation_hours".to_string()],
            },
            SubsystemMapping {
                path_prefix: "adapter".to_string(),
                subsystem: SubsystemId::Adapter,
                default_strategy: ReloadStrategy::Restart,
                restart_fields: vec!["adapter.enabled".to_string()],
                hot_reload_fields: vec![
                    "adapter.max_reconfigurations_per_hour".to_string(),
                    "adapter.adaptation_grace_period_ms".to_string(),
                ],
            },
            SubsystemMapping {
                path_prefix: "trust_proof".to_string(),
                subsystem: SubsystemId::TrustProof,
                default_strategy: ReloadStrategy::HotReload,
                restart_fields: vec!["trust_proof.enabled".to_string()],
                hot_reload_fields: vec![
                    "trust_proof.generation_interval_ms".to_string(),
                    "trust_proof.retention_count".to_string(),
                ],
            },
            SubsystemMapping {
                path_prefix: "health".to_string(),
                subsystem: SubsystemId::Health,
                default_strategy: ReloadStrategy::HotReload,
                restart_fields: vec![],
                hot_reload_fields: vec![
                    "health.computation_interval_ms".to_string(),
                    "health.prediction_window_secs".to_string(),
                ],
            },
            SubsystemMapping {
                path_prefix: "audit".to_string(),
                subsystem: SubsystemId::Audit,
                default_strategy: ReloadStrategy::HotReload,
                restart_fields: vec!["audit.chained_entries".to_string()],
                hot_reload_fields: vec!["audit.max_entries_before_compaction".to_string()],
            },
            SubsystemMapping {
                path_prefix: "distributed".to_string(),
                subsystem: SubsystemId::Distributed,
                default_strategy: ReloadStrategy::Restart,
                restart_fields: vec![
                    "distributed.enabled".to_string(),
                    "distributed.quorum_size".to_string(),
                    "distributed.peers".to_string(),
                ],
                hot_reload_fields: vec![],
            },
            SubsystemMapping {
                path_prefix: "crypto".to_string(),
                subsystem: SubsystemId::Crypto,
                default_strategy: ReloadStrategy::Restart,
                restart_fields: vec!["crypto.hash_algorithm".to_string()],
                hot_reload_fields: vec!["crypto.kdf_iterations".to_string()],
            },
            SubsystemMapping {
                path_prefix: "".to_string(),
                subsystem: SubsystemId::Global,
                default_strategy: ReloadStrategy::Restart,
                restart_fields: vec!["enabled".to_string(), "state_path".to_string()],
                hot_reload_fields: vec![],
            },
        ];

        Self {
            subsystem_mappings: mappings,
            differ: ConfigDiffer::new(),
        }
    }

    /// Create a hot-reload manager with custom subsystem mappings.
    pub fn with_mappings(mappings: Vec<SubsystemMapping>) -> Self {
        Self {
            subsystem_mappings: mappings,
            differ: ConfigDiffer::new(),
        }
    }

    /// Detect changes between two configurations and generate a reload plan.
    pub fn detect_changes(&self, old_config: &Value, new_config: &Value) -> ReloadPlan {
        let config_diff = self.differ.diff(old_config, new_config);

        // Group changes by subsystem
        let mut subsystem_changes: HashMap<SubsystemId, Vec<&DiffEntry>> = HashMap::new();

        for entry in &config_diff.entries {
            let subsystem = self.resolve_subsystem(&entry.path);
            subsystem_changes.entry(subsystem).or_default().push(entry);
        }

        // Generate reload actions
        let mut actions = Vec::new();
        let mut priority_counter = 0u32;

        for (subsystem, changes) in &subsystem_changes {
            let mapping = self
                .subsystem_mappings
                .iter()
                .find(|m| m.subsystem == *subsystem);

            let strategy = self.determine_strategy(&changes, mapping);
            let changed_fields: Vec<String> = changes.iter().map(|c| c.path.clone()).collect();
            let reason = self.generate_reason(&changes);

            // Global changes get highest priority
            let priority = if *subsystem == SubsystemId::Global {
                0
            } else {
                priority_counter += 1;
                priority_counter
            };

            actions.push(ReloadAction {
                subsystem: subsystem.clone(),
                strategy,
                changed_fields,
                reason,
                priority,
            });
        }

        // Sort by priority
        actions.sort_by_key(|a| a.priority);

        let requires_full_restart = actions
            .iter()
            .any(|a| a.strategy == ReloadStrategy::FullRestart);
        let requires_restart = actions
            .iter()
            .any(|a| a.strategy == ReloadStrategy::Restart);
        let hot_reload_sufficient = !requires_full_restart && !requires_restart;

        let summary = if requires_full_restart {
            "FULL RESTART REQUIRED".to_string()
        } else if requires_restart {
            format!(
                "restart required for {} subsystem(s)",
                actions
                    .iter()
                    .filter(|a| a.strategy == ReloadStrategy::Restart)
                    .count()
            )
        } else if actions.is_empty() {
            "no changes detected".to_string()
        } else {
            "hot-reload sufficient".to_string()
        };

        ReloadPlan {
            actions,
            requires_full_restart,
            requires_restart,
            hot_reload_sufficient,
            generated_at: Utc::now(),
            summary,
        }
    }

    /// Resolve a configuration path to its owning subsystem.
    fn resolve_subsystem(&self, path: &str) -> SubsystemId {
        // Find the longest matching prefix
        let mut best_match = SubsystemId::Global;
        let mut best_len = 0usize;

        for mapping in &self.subsystem_mappings {
            if !mapping.path_prefix.is_empty()
                && path.starts_with(&mapping.path_prefix)
                && mapping.path_prefix.len() > best_len
            {
                best_match = mapping.subsystem.clone();
                best_len = mapping.path_prefix.len();
            }
        }

        best_match
    }

    /// Determine the reload strategy for a set of changes within a subsystem.
    fn determine_strategy(
        &self,
        changes: &[&DiffEntry],
        mapping: Option<&SubsystemMapping>,
    ) -> ReloadStrategy {
        let mapping = match mapping {
            Some(m) => m,
            None => return ReloadStrategy::Restart,
        };

        // Check if any change is a breaking change
        let has_breaking = changes
            .iter()
            .any(|c| c.classification == ChangeClassification::Breaking);
        if has_breaking {
            return ReloadStrategy::Restart;
        }

        // Check individual field overrides
        let mut max_strategy = mapping.default_strategy.clone();

        for change in changes {
            if mapping.restart_fields.contains(&change.path) {
                max_strategy = ReloadStrategy::Restart;
            }
            if mapping.hot_reload_fields.contains(&change.path) {
                if max_strategy != ReloadStrategy::Restart {
                    max_strategy = ReloadStrategy::HotReload;
                }
            }
        }

        max_strategy
    }

    /// Generate a human-readable reason for a set of changes.
    fn generate_reason(&self, changes: &[&DiffEntry]) -> String {
        if changes.is_empty() {
            return "no changes".to_string();
        }
        let kinds: HashSet<&DiffKind> = changes.iter().map(|c| &c.kind).collect();
        let descriptions: Vec<String> = kinds
            .iter()
            .map(|k| match k {
                DiffKind::FieldAdded => "fields added".to_string(),
                DiffKind::FieldRemoved => "fields removed".to_string(),
                DiffKind::ValueChanged => "values changed".to_string(),
                DiffKind::TypeChanged => "type changed".to_string(),
                DiffKind::ConstraintTightened => "constraints tightened".to_string(),
                DiffKind::ConstraintRelaxed => "constraints relaxed".to_string(),
                DiffKind::RequiredAdded => "new required fields".to_string(),
                DiffKind::RequiredRemoved => "required fields removed".to_string(),
                DiffKind::FieldRenamed => "fields renamed".to_string(),
            })
            .collect();
        descriptions.join(", ")
    }
}

impl Default for HotReloadManager {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Schema Validation Tests ──

    #[test]
    fn test_validate_string_type() {
        let schema = SchemaNode::new().typed(SchemaType::String);
        let validator = SchemaValidator::new(schema);
        let result = validator.validate(&Value::String("hello".into()));
        assert!(result.is_valid);
    }

    #[test]
    fn test_validate_type_mismatch() {
        let schema = SchemaNode::new().typed(SchemaType::Integer);
        let validator = SchemaValidator::new(schema);
        let result = validator.validate(&Value::String("not an int".into()));
        assert!(!result.is_valid);
        assert_eq!(result.errors[0].code, ValidationErrorCode::TypeMismatch);
    }

    #[test]
    fn test_validate_required_fields() {
        let schema = SchemaNode::new()
            .typed(SchemaType::Object)
            .property("name", SchemaNode::new().typed(SchemaType::String))
            .required(&["name"]);
        let validator = SchemaValidator::new(schema);
        let result = validator.validate(&Value::Object(serde_json::Map::new()));
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.code == ValidationErrorCode::RequiredFieldMissing));
    }

    #[test]
    fn test_validate_number_range() {
        let schema = SchemaNode::new()
            .typed(SchemaType::Integer)
            .number_constraints(NumberConstraints::new().minimum(1.0).maximum(100.0));
        let validator = SchemaValidator::new(schema);

        let valid = validator.validate(&Value::from(50));
        assert!(valid.is_valid);

        let too_low = validator.validate(&Value::from(0));
        assert!(!too_low.is_valid);

        let too_high = validator.validate(&Value::from(101));
        assert!(!too_high.is_valid);
    }

    #[test]
    fn test_validate_string_pattern() {
        let schema = SchemaNode::new()
            .typed(SchemaType::String)
            .string_constraints(StringConstraints::new().pattern(r"^[a-z]+$").unwrap());
        let validator = SchemaValidator::new(schema);

        let valid = validator.validate(&Value::String("hello".into()));
        assert!(valid.is_valid);

        let invalid = validator.validate(&Value::String("Hello123".into()));
        assert!(!invalid.is_valid);
    }

    #[test]
    fn test_validate_enum_values() {
        let schema = SchemaNode::new()
            .typed(SchemaType::String)
            .enum_values(vec![Value::from("sha256"), Value::from("sha512")]);
        let validator = SchemaValidator::new(schema);

        assert!(validator.validate(&Value::String("sha256".into())).is_valid);
        assert!(!validator.validate(&Value::String("md5".into())).is_valid);
    }

    #[test]
    fn test_validate_nested_object() {
        let schema = SchemaNode::new()
            .typed(SchemaType::Object)
            .property(
                "server",
                SchemaNode::new()
                    .typed(SchemaType::Object)
                    .property("host", SchemaNode::new().typed(SchemaType::String))
                    .property(
                        "port",
                        SchemaNode::new()
                            .typed(SchemaType::Integer)
                            .number_constraints(
                                NumberConstraints::new().minimum(1.0).maximum(65535.0),
                            ),
                    )
                    .required(&["host", "port"]),
            )
            .required(&["server"]);

        let validator = SchemaValidator::new(schema);
        let good_config = serde_json::json!({
            "server": {
                "host": "localhost",
                "port": 8080
            }
        });
        assert!(validator.validate(&good_config).is_valid);

        let bad_port = serde_json::json!({
            "server": {
                "host": "localhost",
                "port": 99999
            }
        });
        assert!(!validator.validate(&bad_port).is_valid);
    }

    #[test]
    fn test_validate_array_with_items_schema() {
        let schema = SchemaNode::new()
            .typed(SchemaType::Array)
            .array_constraints(ArrayConstraints {
                min_items: Some(1),
                max_items: Some(5),
                unique_items: true,
                items_schema: Some(Box::new(SchemaNode::new().typed(SchemaType::String))),
            });
        let validator = SchemaValidator::new(schema);

        let valid = validator.validate(&serde_json::json!(["a"]));
        assert!(valid.is_valid);

        let duplicate = validator.validate(&serde_json::json!(["a", "a"]));
        assert!(!duplicate.is_valid);

        let too_many = validator.validate(&serde_json::json!(["a", "b", "c", "d", "e", "f"]));
        assert!(!too_many.is_valid);
    }

    #[test]
    fn test_validate_additional_properties_disallowed() {
        let schema = SchemaNode::new()
            .typed(SchemaType::Object)
            .property("name", SchemaNode::new().typed(SchemaType::String))
            .no_additional_properties();
        let validator = SchemaValidator::new(schema);

        let valid = validator.validate(&serde_json::json!({"name": "test"}));
        assert!(valid.is_valid);

        let extra = validator.validate(&serde_json::json!({"name": "test", "extra": true}));
        assert!(!extra.is_valid);
        assert!(extra
            .errors
            .iter()
            .any(|e| e.code == ValidationErrorCode::AdditionalPropertyNotAllowed));
    }

    #[test]
    fn test_validate_string_length_constraints() {
        let schema = SchemaNode::new()
            .typed(SchemaType::String)
            .string_constraints(StringConstraints::new().min_length(3).max_length(10));
        let validator = SchemaValidator::new(schema);

        assert!(validator.validate(&Value::String("abc".into())).is_valid);
        assert!(
            validator
                .validate(&Value::String("abcdefghij".into()))
                .is_valid
        );
        assert!(!validator.validate(&Value::String("ab".into())).is_valid);
        assert!(
            !validator
                .validate(&Value::String("abcdefghijk".into()))
                .is_valid
        );
    }

    #[test]
    fn test_validate_number_multiple_of() {
        let schema = SchemaNode::new()
            .typed(SchemaType::Integer)
            .number_constraints(NumberConstraints::new().multiple_of(5.0));
        let validator = SchemaValidator::new(schema);

        assert!(validator.validate(&Value::from(10)).is_valid);
        assert!(validator.validate(&Value::from(15)).is_valid);
        assert!(!validator.validate(&Value::from(7)).is_valid);
    }

    #[test]
    fn test_apply_defaults() {
        let schema = SchemaNode::new()
            .typed(SchemaType::Object)
            .property(
                "name",
                SchemaNode::new()
                    .typed(SchemaType::String)
                    .default_value(Value::String("default".into())),
            )
            .property(
                "count",
                SchemaNode::new()
                    .typed(SchemaType::Integer)
                    .default_value(Value::from(42)),
            );
        let validator = SchemaValidator::new(schema.clone());
        let input = serde_json::json!({"name": "custom"});
        let result = validator.apply_defaults_to_value(&input, &schema);
        assert_eq!(result["name"], Value::String("custom".into()));
        assert_eq!(result["count"], Value::from(42));
    }

    // ── Migration Tests ──

    #[test]
    fn test_migration_add_field() {
        let mut migrator = ConfigMigrator::new();
        let plan = MigrationPlan::new(
            "v1",
            "v2",
            vec![MigrationStep::AddField {
                path: "new_field".into(),
                default_value: Value::String("default".into()),
            }],
        );
        migrator.register_plan(plan);

        let config = serde_json::json!({"existing": true});
        let result = migrator.migrate(&config, "v1", "v2");
        assert!(result.success);
        assert_eq!(result.config["new_field"], Value::String("default".into()));
        assert_eq!(result.config["existing"], Value::Bool(true));
    }

    #[test]
    fn test_migration_rename_field() {
        let mut migrator = ConfigMigrator::new();
        let plan = MigrationPlan::new(
            "v1",
            "v2",
            vec![MigrationStep::RenameField {
                old_path: "old_name".into(),
                new_path: "new_name".into(),
            }],
        );
        migrator.register_plan(plan);

        let config = serde_json::json!({"old_name": "value"});
        let result = migrator.migrate(&config, "v1", "v2");
        assert!(result.success);
        assert_eq!(result.config["new_name"], Value::String("value".into()));
        assert!(result.config.get("old_name").is_none());
    }

    #[test]
    fn test_migration_transform_value() {
        let mut migrator = ConfigMigrator::new();
        let plan = MigrationPlan::new(
            "v1",
            "v2",
            vec![MigrationStep::TransformValue {
                path: "interval_ms".into(),
                transformation: ValueTransformation::MsToSeconds,
            }],
        );
        migrator.register_plan(plan);

        let config = serde_json::json!({"interval_ms": 5000});
        let result = migrator.migrate(&config, "v1", "v2");
        assert!(result.success);
        assert_eq!(result.config["interval_ms"], Value::from(5.0));
    }

    #[test]
    fn test_migration_chain() {
        let mut migrator = ConfigMigrator::new();
        migrator.set_version_chain(vec!["v1".into(), "v2".into(), "v3".into()]);
        migrator.register_plan(MigrationPlan::new(
            "v1",
            "v2",
            vec![MigrationStep::AddField {
                path: "v2_field".into(),
                default_value: Value::from(true),
            }],
        ));
        migrator.register_plan(MigrationPlan::new(
            "v2",
            "v3",
            vec![MigrationStep::AddField {
                path: "v3_field".into(),
                default_value: Value::from(42),
            }],
        ));

        let config = serde_json::json!({"original": "data"});
        let result = migrator.migrate(&config, "v1", "v3");
        assert!(result.success);
        assert_eq!(result.config["v2_field"], Value::Bool(true));
        assert_eq!(result.config["v3_field"], Value::from(42));
        assert_eq!(result.config["original"], Value::String("data".into()));
    }

    #[test]
    fn test_migration_remove_field() {
        let mut migrator = ConfigMigrator::new();
        let plan = MigrationPlan::new(
            "v1",
            "v2",
            vec![MigrationStep::RemoveField {
                path: "deprecated".into(),
            }],
        );
        migrator.register_plan(plan);

        let config = serde_json::json!({"deprecated": "old", "keep": "this"});
        let result = migrator.migrate(&config, "v1", "v2");
        assert!(result.success);
        assert!(result.config.get("deprecated").is_none());
        assert_eq!(result.config["keep"], Value::String("this".into()));
    }

    // ── Environment Variable Interpolation Tests ──

    #[test]
    fn test_env_interpolation_simple() {
        let mut env = HashMap::new();
        env.insert("DATABASE_URL".into(), "postgres://localhost/db".into());
        let interpolator = EnvInterpolator::with_env(env);
        let value = Value::String("${DATABASE_URL}".into());
        let result = interpolator.interpolate(&value);
        assert!(result.success);
        assert_eq!(
            result.value,
            Value::String("postgres://localhost/db".into())
        );
    }

    #[test]
    fn test_env_interpolation_with_default() {
        let interpolator = EnvInterpolator::with_env(HashMap::new());
        let value = Value::String("${MISSING_VAR:-fallback_value}".into());
        let result = interpolator.interpolate(&value);
        assert!(result.success);
        assert_eq!(result.value, Value::String("fallback_value".into()));
    }

    #[test]
    fn test_env_interpolation_required_error() {
        let interpolator = EnvInterpolator::with_env(HashMap::new());
        let value = Value::String("${CRITICAL_VAR:?this is required}".into());
        let result = interpolator.interpolate(&value);
        assert!(!result.success);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_env_interpolation_in_object() {
        let mut env = HashMap::new();
        env.insert("HOST".into(), "example.com".into());
        env.insert("PORT".into(), "8443".into());
        let interpolator = EnvInterpolator::with_env(env);
        let value = serde_json::json!({
            "server": {
                "host": "${HOST}",
                "port": "${PORT}"
            }
        });
        let result = interpolator.interpolate(&value);
        assert!(result.success);
        assert_eq!(
            result.value["server"]["host"],
            Value::String("example.com".into())
        );
        assert_eq!(
            result.value["server"]["port"],
            Value::Number(serde_json::Number::from(8443))
        );
    }

    #[test]
    fn test_env_interpolation_inline_default_overrides_absent() {
        let interpolator = EnvInterpolator::with_env(HashMap::new());
        let value = Value::String("${LOG_LEVEL:-info}".into());
        let result = interpolator.interpolate(&value);
        assert!(result.success);
        assert_eq!(result.value, Value::String("info".into()));
    }

    // ── Diffing Tests ──

    #[test]
    fn test_diff_field_added() {
        let differ = ConfigDiffer::new();
        let old = serde_json::json!({"a": 1});
        let new = serde_json::json!({"a": 1, "b": 2});
        let diff = differ.diff(&old, &new);
        assert!(!diff.has_breaking_changes);
        assert_eq!(diff.non_breaking_count, 1);
        assert_eq!(diff.entries[0].kind, DiffKind::FieldAdded);
    }

    #[test]
    fn test_diff_field_removed() {
        let differ = ConfigDiffer::new();
        let old = serde_json::json!({"a": 1, "b": 2});
        let new = serde_json::json!({"a": 1});
        let diff = differ.diff(&old, &new);
        assert!(diff.has_breaking_changes);
        assert_eq!(diff.breaking_count, 1);
        assert_eq!(diff.entries[0].kind, DiffKind::FieldRemoved);
    }

    #[test]
    fn test_diff_value_changed_neutral() {
        let differ = ConfigDiffer::new();
        let old = serde_json::json!({"count": 5});
        let new = serde_json::json!({"count": 10});
        let diff = differ.diff(&old, &new);
        assert!(!diff.has_breaking_changes);
        assert_eq!(diff.neutral_count, 1);
    }

    #[test]
    fn test_diff_type_change_breaking() {
        let differ = ConfigDiffer::new();
        let old = serde_json::json!({"port": "8080"});
        let new = serde_json::json!({"port": 8080});
        let diff = differ.diff(&old, &new);
        assert!(diff.has_breaking_changes);
        assert!(diff.entries.iter().any(|e| e.kind == DiffKind::TypeChanged));
    }

    #[test]
    fn test_diff_no_changes() {
        let differ = ConfigDiffer::new();
        let config = serde_json::json!({"a": 1, "b": [1, 2, 3]});
        let diff = differ.diff(&config, &config);
        assert!(diff.entries.is_empty());
        assert!(!diff.has_breaking_changes);
    }

    // ── Template Tests ──

    #[test]
    fn test_template_instantiate_simple() {
        let mut engine = TemplateEngine::new();
        engine.register(ConfigTemplate {
            name: "basic".into(),
            description: "basic template".into(),
            template: serde_json::json!({
                "host": "{{host}}",
                "port": "{{port}}"
            }),
            extends: None,
            overrides: BTreeMap::new(),
            placeholders: {
                let mut m = BTreeMap::new();
                m.insert(
                    "host".into(),
                    PlaceholderDef {
                        description: "server host".into(),
                        default_value: None,
                        required: true,
                        expected_type: Some(SchemaType::String),
                    },
                );
                m.insert(
                    "port".into(),
                    PlaceholderDef {
                        description: "server port".into(),
                        default_value: None,
                        required: true,
                        expected_type: Some(SchemaType::Integer),
                    },
                );
                m
            },
            validation_schema: None,
            tags: vec![],
        });

        let mut values = BTreeMap::new();
        values.insert("host".into(), Value::String("localhost".into()));
        values.insert("port".into(), Value::from(8080));

        let result = engine.instantiate("basic", values);
        assert!(result.success);
        assert_eq!(result.config["host"], Value::String("localhost".into()));
        assert_eq!(result.config["port"], Value::from(8080));
    }

    #[test]
    fn test_template_inheritance() {
        let mut engine = TemplateEngine::new();
        engine.register(ConfigTemplate {
            name: "base".into(),
            description: "base template".into(),
            template: serde_json::json!({
                "log_level": "info",
                "max_retries": 3
            }),
            extends: None,
            overrides: BTreeMap::new(),
            placeholders: BTreeMap::new(),
            validation_schema: None,
            tags: vec![],
        });
        engine.register(ConfigTemplate {
            name: "production".into(),
            description: "production override".into(),
            template: serde_json::json!({}),
            extends: Some("base".into()),
            overrides: {
                let mut m = BTreeMap::new();
                m.insert("log_level".into(), Value::String("warn".into()));
                m
            },
            placeholders: BTreeMap::new(),
            validation_schema: None,
            tags: vec!["production".into()],
        });

        let result = engine.instantiate("production", BTreeMap::new());
        assert!(result.success);
        assert_eq!(result.config["log_level"], Value::String("warn".into()));
        assert_eq!(result.config["max_retries"], Value::from(3));
    }

    #[test]
    fn test_template_missing_required_placeholder() {
        let mut engine = TemplateEngine::new();
        engine.register(ConfigTemplate {
            name: "needs_host".into(),
            description: "needs host".into(),
            template: serde_json::json!({"host": "{{host}}"}),
            extends: None,
            overrides: BTreeMap::new(),
            placeholders: {
                let mut m = BTreeMap::new();
                m.insert(
                    "host".into(),
                    PlaceholderDef {
                        description: "host".into(),
                        default_value: None,
                        required: true,
                        expected_type: Some(SchemaType::String),
                    },
                );
                m
            },
            validation_schema: None,
            tags: vec![],
        });

        let result = engine.instantiate("needs_host", BTreeMap::new());
        assert!(!result.success);
    }

    // ── Hot Reload Tests ──

    #[test]
    fn test_hot_reload_no_changes() {
        let manager = HotReloadManager::new();
        let config = serde_json::json!({"enabled": true, "sentinel": {"check_interval_ms": 1000}});
        let plan = manager.detect_changes(&config, &config);
        assert!(plan.actions.is_empty());
        assert!(plan.hot_reload_sufficient);
    }

    #[test]
    fn test_hot_reload_sentinel_interval_change() {
        let manager = HotReloadManager::new();
        let old = serde_json::json!({"sentinel": {"check_interval_ms": 1000}});
        let new = serde_json::json!({"sentinel": {"check_interval_ms": 500}});
        let plan = manager.detect_changes(&old, &new);
        assert!(!plan.requires_full_restart);
        assert_eq!(plan.actions.len(), 1);
        assert_eq!(plan.actions[0].subsystem, SubsystemId::Sentinel);
        assert_eq!(plan.actions[0].strategy, ReloadStrategy::HotReload);
    }

    #[test]
    fn test_hot_reload_global_enabled_change() {
        let manager = HotReloadManager::new();
        let old = serde_json::json!({"enabled": true});
        let new = serde_json::json!({"enabled": false});
        let plan = manager.detect_changes(&old, &new);
        assert!(plan.requires_restart);
    }

    #[test]
    fn test_hot_reload_distributed_peer_change() {
        let manager = HotReloadManager::new();
        let old = serde_json::json!({"distributed": {"peers": ["a", "b"]}});
        let new = serde_json::json!({"distributed": {"peers": ["a", "b", "c"]}});
        let plan = manager.detect_changes(&old, &new);
        assert!(plan.requires_restart);
        assert_eq!(plan.actions[0].subsystem, SubsystemId::Distributed);
    }

    #[test]
    fn test_reload_plan_summary() {
        let plan = ReloadPlan {
            actions: vec![ReloadAction {
                subsystem: SubsystemId::Sentinel,
                strategy: ReloadStrategy::HotReload,
                changed_fields: vec!["sentinel.check_interval_ms".into()],
                reason: "values changed".into(),
                priority: 1,
            }],
            requires_full_restart: false,
            requires_restart: false,
            hot_reload_sufficient: true,
            generated_at: Utc::now(),
            summary: String::new(),
        };
        let summary = plan.generate_summary();
        assert!(summary.contains("1 hot-reload"));
    }
}
