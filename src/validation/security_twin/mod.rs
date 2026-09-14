// Security Twin Validation — D3
//
// The Security Twin becomes one of CHAKRAVYUH's signature technologies.
// This module provides the validation layer on top of the existing
// twin engine (src/twin/) to create the full predict→run→compare→learn loop.
//
// Flow:
//   Attack → Security Twin (Predict) → Real System (Run)
//        → Compare (Prediction vs Reality) → Learn (Update Model)

pub mod predictor;
pub mod comparator;
pub mod learner;
pub mod twin_runner;

pub use comparator::{ComparisonResult, ComparisonSummary, TwinDiscrepancy};
pub use learner::{LearningRecord, LearningStore};
pub use predictor::{Prediction, PredictionConfidence, TwinPredictor};
pub use twin_runner::{TwinValidationConfig, TwinValidationResult, TwinValidationRunner};

use serde::{Deserialize, Serialize};

/// The type of prediction.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PredictionType {
    /// The twin predicts the attack will be blocked.
    Blocked,
    /// The twin predicts the attack will be allowed (missed).
    Allowed,
    /// The twin predicts the attack will be escalated.
    Escalated,
    /// The twin cannot make a confident prediction.
    Uncertain,
}

impl std::fmt::Display for PredictionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PredictionType::Blocked => write!(f, "BLOCKED"),
            PredictionType::Allowed => write!(f, "ALLOWED"),
            PredictionType::Escalated => write!(f, "ESCALATED"),
            PredictionType::Uncertain => write!(f, "UNCERTAIN"),
        }
    }
}

/// A single prediction-vs-reality record for the learning loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictionRecord {
    /// Unique record ID.
    pub id: String,
    /// The attack payload that was tested.
    pub attack_payload: String,
    /// What the twin predicted.
    pub predicted: PredictionType,
    /// What actually happened.
    pub actual: PredictionType,
    /// Whether the prediction was correct.
    pub correct: bool,
    /// The confidence the twin had in its prediction.
    pub confidence: f64,
    /// Which rings were involved.
    pub rings: Vec<String>,
    /// RFC 3339 timestamp.
    pub timestamp: String,
    /// The category of attack.
    pub attack_category: String,
}

impl PredictionRecord {
    pub fn new(
        attack_payload: &str,
        predicted: PredictionType,
        actual: PredictionType,
        confidence: f64,
        rings: Vec<String>,
        attack_category: &str,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            attack_payload: attack_payload.to_string(),
            predicted,
            actual,
            correct: predicted == actual,
            confidence,
            rings,
            timestamp: chrono::Utc::now().to_rfc3339(),
            attack_category: attack_category.to_string(),
        }
    }
}
