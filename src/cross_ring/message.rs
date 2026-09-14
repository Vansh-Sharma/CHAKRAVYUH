// Cross Ring Message — Common message type for all 5 cross rings.
//
// Messages are strongly typed with directional semantics enforced
// by the ring that sends/receives them.

use serde::{Deserialize, Serialize};

/// The type of cross ring.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CrossRingType {
    /// Command Ring — Keshav → Rings (top-down)
    Command,
    /// Intel Ring — Ring ↔ Ring (peer-to-peer)
    Intel,
    /// Control Ring — Rings → Keshav (arbitration)
    Control,
    /// Communication Ring — System-wide broadcast
    Communication,
    /// Recovery Ring — Independent path (Phase 5)
    Recovery,
}

/// Message priority level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MessagePriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

impl Default for MessagePriority {
    fn default() -> Self {
        MessagePriority::Normal
    }
}

/// A Cross Ring message.
///
/// Every message carries: source, destination, type, payload, and metadata.
/// The type determines which ring channel it uses (see P4: directional semantics).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossRingMessage {
    /// Unique message ID (UUID v4).
    pub message_id: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Source ring name or "keshav".
    pub source: String,
    /// Destination ring name, "keshav", or "broadcast".
    pub destination: String,
    /// Cross ring type (Command, Intel, Control, Communication, Recovery).
    pub cross_ring_type: CrossRingType,
    /// Message type identifier (e.g., "policy_update", "attack_pattern").
    pub msg_type: String,
    /// Payload (JSON-serializable).
    pub payload: serde_json::Value,
    /// Message priority.
    #[serde(default)]
    pub priority: MessagePriority,
    /// Keshav version that created this message.
    #[serde(default)]
    pub version: String,
}

impl CrossRingMessage {
    /// Create a new cross ring message.
    pub fn new(
        cross_ring_type: CrossRingType,
        source: &str,
        destination: &str,
        msg_type: &str,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            message_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            source: source.into(),
            destination: destination.into(),
            cross_ring_type,
            msg_type: msg_type.into(),
            payload,
            priority: MessagePriority::default(),
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }

    /// Create a message with high priority.
    pub fn high_priority(
        cross_ring_type: CrossRingType,
        source: &str,
        destination: &str,
        msg_type: &str,
        payload: serde_json::Value,
    ) -> Self {
        let mut msg = Self::new(cross_ring_type, source, destination, msg_type, payload);
        msg.priority = MessagePriority::High;
        msg
    }

    /// Validate the message's directional semantics.
    ///
    /// Returns Ok(()) if the message follows the directional rules:
    ///   - Command: source must be "keshav"
    ///   - Control: destination must be "keshav"
    ///   - Intel: source must NOT be "keshav" (Keshav subscribes but doesn't publish)
    ///   - Communication: destination must be "broadcast"
    pub fn validate_direction(&self) -> Result<(), String> {
        match self.cross_ring_type {
            CrossRingType::Command => {
                if self.source != "keshav" {
                    return Err(format!(
                        "Command message source must be 'keshav', got '{}'",
                        self.source
                    ));
                }
            }
            CrossRingType::Control => {
                if self.destination != "keshav" {
                    return Err(format!(
                        "Control message destination must be 'keshav', got '{}'",
                        self.destination
                    ));
                }
            }
            CrossRingType::Intel => {
                if self.source == "keshav" {
                    return Err(
                        "Intel messages cannot originate from Keshav (Keshav subscribes only)"
                            .into(),
                    );
                }
            }
            CrossRingType::Communication => {
                if self.destination != "broadcast" {
                    return Err(format!(
                        "Communication messages must have destination 'broadcast', got '{}'",
                        self.destination
                    ));
                }
            }
            CrossRingType::Recovery => {
                // Recovery has no directional restrictions (independent path).
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_command_from_keshav() {
        let msg = CrossRingMessage::new(
            CrossRingType::Command,
            "keshav",
            "shield",
            "policy_update",
            serde_json::json!({}),
        );
        assert!(msg.validate_direction().is_ok());
    }

    #[test]
    fn invalid_command_from_ring() {
        let msg = CrossRingMessage::new(
            CrossRingType::Command,
            "shield",
            "threat",
            "some_command",
            serde_json::json!({}),
        );
        assert!(msg.validate_direction().is_err());
    }

    #[test]
    fn invalid_intel_from_keshav() {
        let msg = CrossRingMessage::new(
            CrossRingType::Intel,
            "keshav",
            "broadcast",
            "observation",
            serde_json::json!({}),
        );
        assert!(msg.validate_direction().is_err());
    }

    #[test]
    fn valid_intel_from_ring() {
        let msg = CrossRingMessage::new(
            CrossRingType::Intel,
            "shield",
            "broadcast",
            "attack_pattern",
            serde_json::json!({}),
        );
        assert!(msg.validate_direction().is_ok());
    }
}
