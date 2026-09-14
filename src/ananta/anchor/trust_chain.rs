// Trust Chain — a cryptographically chained sequence of trust events.
//
// Each event hashes the previous event, creating a tamper-evident chain.
// Similar to a blockchain but simpler: no consensus, no mining.
// Just: H(prev_hash || event_data || timestamp).
//
// Used by:
//   - Audit: chaining audit entries
//   - Phoenix: chaining recovery actions
//   - Anchor: chaining attestation reports

use crate::ananta::crypto::hashing::hash_combined;
use crate::ananta::config::HashAlgorithm;
use serde::{Deserialize, Serialize};

/// A single link in the trust chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustChainLink {
    /// Sequence number (monotonically increasing).
    pub sequence: u64,
    /// Hash of the previous link (genesis = all zeros).
    pub prev_hash: String,
    /// The event type.
    pub event_type: String,
    /// The event data (JSON).
    pub data: serde_json::Value,
    /// Hash of this link's content.
    pub hash: String,
    /// Timestamp.
    pub timestamp: String,
}

impl TrustChainLink {
    /// Compute the hash for this link.
    fn compute_hash(algorithm: &HashAlgorithm, prev_hash: &str, event_type: &str, data: &serde_json::Value, timestamp: &str) -> String {
        let data_json = serde_json::to_string(data).unwrap_or_default();
        let digest = hash_combined(
            &[
                prev_hash.as_bytes(),
                event_type.as_bytes(),
                data_json.as_bytes(),
                timestamp.as_bytes(),
            ],
            algorithm,
        );
        digest.hex
    }
}

/// A cryptographically chained trust log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustChain {
    algorithm: HashAlgorithm,
    chain: Vec<TrustChainLink>,
}

impl TrustChain {
    /// Create an empty trust chain.
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm,
            chain: vec![],
        }
    }

    /// Append an event to the chain.
    pub fn append(&mut self, event_type: &str, data: serde_json::Value) -> &TrustChainLink {
        let sequence = self.chain.len() as u64;
        let prev_hash = self.chain.last()
            .map(|l| l.hash.clone())
            .unwrap_or_else(|| "0".repeat(64)); // Genesis.
        let timestamp = chrono::Utc::now().to_rfc3339();

        let hash = TrustChainLink::compute_hash(
            &self.algorithm, &prev_hash, event_type, &data, &timestamp,
        );

        let link = TrustChainLink {
            sequence,
            prev_hash,
            event_type: event_type.into(),
            data,
            hash,
            timestamp,
        };

        self.chain.push(link);
        self.chain.last().unwrap()
    }

    /// Verify the entire chain's integrity.
    /// Returns the index of the first broken link, or None if valid.
    pub fn verify(&self) -> Option<usize> {
        for i in 0..self.chain.len() {
            let link = &self.chain[i];
            let prev_hash = if i == 0 {
                "0".repeat(64)
            } else {
                self.chain[i - 1].hash.clone()
            };

            let expected = TrustChainLink::compute_hash(
                &self.algorithm, &prev_hash, &link.event_type, &link.data, &link.timestamp,
            );

            if link.hash != expected {
                return Some(i);
            }
        }
        None
    }

    /// Get the latest link.
    pub fn latest(&self) -> Option<&TrustChainLink> {
        self.chain.last()
    }

    /// Get the current chain length.
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Iterate over links.
    pub fn links(&self) -> &[TrustChainLink] {
        &self.chain
    }

    /// Export as JSON.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("trust_chain: {}", e))
    }

    /// Import from JSON.
    pub fn from_json(json: &str, _algorithm: HashAlgorithm) -> Result<Self, String> {
        let chain: TrustChain = serde_json::from_str(json)
            .map_err(|e| format!("trust_chain parse: {}", e))?;
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_chain_verifies() {
        let chain = TrustChain::new(HashAlgorithm::Sha256);
        assert!(chain.verify().is_none());
    }

    #[test]
    fn single_link_verifies() {
        let mut chain = TrustChain::new(HashAlgorithm::Sha256);
        chain.append("test", serde_json::json!({"key": "value"}));
        assert!(chain.verify().is_none());
    }

    #[test]
    fn multi_link_chain_verifies() {
        let mut chain = TrustChain::new(HashAlgorithm::Sha256);
        for i in 0..10 {
            chain.append("event", serde_json::json!({"i": i}));
        }
        assert!(chain.verify().is_none());
        assert_eq!(chain.len(), 10);
    }

    #[test]
    fn tampered_link_detected() {
        let mut chain = TrustChain::new(HashAlgorithm::Sha256);
        chain.append("a", serde_json::json!(1));
        chain.append("b", serde_json::json!(2));
        chain.append("c", serde_json::json!(3));

        // Tamper with middle link.
        chain.chain[1].data = serde_json::json!(999);

        let broken = chain.verify();
        assert_eq!(broken, Some(1));
    }

    #[test]
    fn chain_deterministic_from_same_inputs() {
        let mut c1 = TrustChain::new(HashAlgorithm::Sha256);
        c1.append("type", serde_json::json!("data"));

        // Can't create identical chain (different timestamps),
        // but verify the hash computation is deterministic.
        let link = &c1.chain[0];
        let expected = TrustChainLink::compute_hash(
            &HashAlgorithm::Sha256,
            &"0".repeat(64),
            "type",
            &serde_json::json!("data"),
            &link.timestamp,
        );
        assert_eq!(link.hash, expected);
    }

    #[test]
    fn json_roundtrip() {
        let mut chain = TrustChain::new(HashAlgorithm::Sha256);
        chain.append("attestation", serde_json::json!({"trust": 0.95}));
        chain.append("recovery", serde_json::json!({"action": "reset"}));

        let json = chain.to_json().unwrap();
        let restored = TrustChain::from_json(&json, HashAlgorithm::Sha256).unwrap();
        assert!(restored.verify().is_none());
        assert_eq!(restored.len(), 2);
    }
}