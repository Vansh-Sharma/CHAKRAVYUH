//! Fuzz harness for the Execution Ring Parameter Validator.
//!
//! Feeds arbitrary JSON bodies as tool call parameters.
//! Targets:
//!   - Panics on deeply nested or unusual JSON structures
//!   - Type checking edge cases
//!   - min/max boundary violations
//!   - Enum value matching correctness

#![no_main]

use chakravyuh::execution::parameter_validator::{
    ParameterValidator, ParameterValidatorConfig, PropertySpec, PropertyType,
    ParameterSchema, ToolParameterSchema,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parse as JSON parameters.
    let params: serde_json::Value = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Build a simple schema to validate against.
    let config = ParameterValidatorConfig {
        enabled: true,
        tool_schemas: vec![
            ToolParameterSchema {
                tool_name: "test_tool".into(),
                schema: ParameterSchema {
                    required_fields: vec!["query".into()],
                    properties: {
                        let mut m = std::collections::HashMap::new();
                        m.insert("query".into(), PropertySpec {
                            prop_type: PropertyType::String,
                            max_length: Some(1000),
                            min_length: Some(1),
                            minimum: None,
                            maximum: None,
                            enum_values: vec![],
                        });
                        m.insert("count".into(), PropertySpec {
                            prop_type: PropertyType::Integer,
                            max_length: None,
                            min_length: None,
                            minimum: Some(0),
                            maximum: Some(1000),
                            enum_values: vec![],
                        });
                        m.insert("flag".into(), PropertySpec {
                            prop_type: PropertyType::Boolean,
                            max_length: None,
                            min_length: None,
                            minimum: None,
                            maximum: None,
                            enum_values: vec![],
                        });
                        m.insert("mode".into(), PropertySpec {
                            prop_type: PropertyType::String,
                            max_length: None,
                            min_length: None,
                            minimum: None,
                            maximum: None,
                            enum_values: vec!["safe".into(), "aggressive".into()],
                        });
                        m
                    },
                },
            },
        ],
    };

    let validator = ParameterValidator::new(&config).expect("init");

    // Must not panic.
    let _result = validator.evaluate("test_tool", &params);
});