// Threat Signature Synchronization for Federated Learning
//
// Synchronizes threat detection signatures across federated peers.
// Handles deduplication, conflict resolution, TTL-based expiration,
// and SHA-256 hash-based verification.
//
// No unsafe code.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use sha2::{Digest, Sha256};

// ── Configuration ──────────────────────────────────────────────────

/// Configuration for threat signature synchronization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSyncConfig {
    /// Interval between sync rounds in milliseconds.
    #[serde(default = "default_sync_interval")]
    pub sync_interval_ms: u64,
    /// Maximum signatures per sync exchange.
    #[serde(default = "default_max_sigs")]
    pub max_signatures_per_sync: usize,
    /// Time-to-live for signatures in seconds.
    #[serde(default = "default_ttl")]
    pub signature_ttl: u64,
    /// Whether SHA-256 hash verification is required.
    #[serde(default = "default_true")]
    pub verification_required: bool,
}

fn default_sync_interval() -> u64 {
    60_000
}
fn default_max_sigs() -> usize {
    1000
}
fn default_ttl() -> u64 {
    86_400
}
fn default_true() -> bool {
    true
}

impl Default for ThreatSyncConfig {
    fn default() -> Self {
        Self {
            sync_interval_ms: default_sync_interval(),
            max_signatures_per_sync: default_max_sigs(),
            signature_ttl: default_ttl(),
            verification_required: true,
        }
    }
}

// ── Threat Signature ──────────────────────────────────────────────

/// A threat detection signature shared across the federation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSignature {
    /// Unique identifier for this signature.
    pub id: String,
    /// The detection pattern (regex, keyword, or semantic rule).
    pub pattern: String,
    /// Type of attack this signature detects (as string).
    pub attack_type: String,
    /// Severity score (0.0 = benign, 10.0 = critical).
    pub severity: f64,
    /// Confidence of detection (0.0–1.0).
    pub confidence: f64,
    /// Peer that contributed this signature.
    pub source_peer: String,
    /// Unix timestamp when this signature was created.
    pub created_at: u64,
    /// Unix timestamp when this signature expires.
    pub expires_at: u64,
    /// SHA-256 hash for integrity verification.
    pub signature_hash: String,
}

impl ThreatSignature {
    /// Create a new threat signature, computing the hash automatically.
    pub fn new(
        id: String,
        pattern: String,
        attack_type: String,
        severity: f64,
        confidence: f64,
        source_peer: String,
        ttl_secs: u64,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let hash = Self::compute_hash(&pattern, &attack_type, &source_peer);

        Self {
            id,
            pattern,
            attack_type,
            severity: severity.clamp(0.0, 10.0),
            confidence: confidence.clamp(0.0, 1.0),
            source_peer,
            created_at: now,
            expires_at: now + ttl_secs,
            signature_hash: hash,
        }
    }

    /// Compute SHA-256 hash of pattern + attack_type + source_peer.
    pub fn compute_hash(pattern: &str, attack_type: &str, source_peer: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(pattern.as_bytes());
        hasher.update(b"|");
        hasher.update(attack_type.as_bytes());
        hasher.update(b"|");
        hasher.update(source_peer.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify that this signature's stored hash matches the computed hash.
    pub fn verify_hash(&self) -> bool {
        let expected = Self::compute_hash(&self.pattern, &self.attack_type, &self.source_peer);
        self.signature_hash == expected
    }

    /// Check whether this signature has expired.
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

// ── Signature Diff ────────────────────────────────────────────────

/// Summary of changes between two sets of signatures.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SignatureDiff {
    /// Number of newly added signatures.
    pub added: usize,
    /// Number of removed (expired or retracted) signatures.
    pub removed: usize,
    /// Number of signatures with updated fields.
    pub updated: usize,
    /// Number of unchanged signatures.
    pub unchanged: usize,
}

impl SignatureDiff {
    /// Total number of changes.
    pub fn total_changes(&self) -> usize {
        self.added + self.removed + self.updated
    }
}

// ── Global Threat Model ───────────────────────────────────────────

/// The global threat model maintained by the sync engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalThreatModel {
    /// Current version of the global model.
    pub version: String,
    /// All active threat signatures.
    pub signatures: Vec<ThreatSignature>,
    /// Unix timestamp of the last sync.
    pub last_sync: u64,
    /// Per-peer contribution counts.
    pub peer_contributions: HashMap<String, usize>,
}

impl Default for GlobalThreatModel {
    fn default() -> Self {
        Self {
            version: "0.0.0".to_string(),
            signatures: vec![],
            last_sync: 0,
            peer_contributions: HashMap::new(),
        }
    }
}

// ── Sync Protocol ─────────────────────────────────────────────────

/// A sync request sent by a peer to initiate signature exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    /// Peer ID of the requester.
    pub peer_id: String,
    /// Local model version.
    pub local_model_version: String,
    /// Number of signatures the requester has locally.
    pub local_signature_count: usize,
}

/// A sync response returned to the requester.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    /// Signatures to be sent (new or updated).
    pub signatures: Vec<ThreatSignature>,
    /// The responder's model version.
    pub model_version: String,
    /// Diff summary between the requester's and responder's models.
    pub diff: SignatureDiff,
}

// ── Threat Signature Sync Engine ──────────────────────────────────

/// Synchronizes threat signatures across federated peers.
///
/// Handles:
///   - Deduplication by signature hash
///   - Conflict resolution (higher confidence wins, then newer timestamp)
///   - TTL-based expiration filtering
///   - SHA-256 hash-based verification
///   - Peer contribution tracking
pub struct ThreatSignatureSync {
    config: ThreatSyncConfig,
    global_model: std::sync::RwLock<GlobalThreatModel>,
}

impl ThreatSignatureSync {
    /// Create a new sync engine.
    pub fn new(config: ThreatSyncConfig) -> Self {
        Self {
            config,
            global_model: std::sync::RwLock::new(GlobalThreatModel::default()),
        }
    }

    /// Merge local and remote signatures into a unified set.
    ///
    /// Deduplication: signatures with the same hash are considered duplicates.
    /// Conflict resolution: higher confidence wins; ties broken by newer timestamp.
    /// TTL filtering: expired signatures are removed.
    pub fn merge_signatures(
        &self,
        local: &[ThreatSignature],
        remote: &[ThreatSignature],
    ) -> Vec<ThreatSignature> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Collect all signatures indexed by hash.
        let mut by_hash: HashMap<String, ThreatSignature> = HashMap::new();

        // Insert local signatures.
        for sig in local {
            if !sig.is_expired(now) {
                by_hash.insert(sig.signature_hash.clone(), sig.clone());
            }
        }

        // Merge remote signatures with conflict resolution.
        for sig in remote {
            if sig.is_expired(now) {
                continue;
            }
            // If verification is required and the hash is invalid, skip.
            if self.config.verification_required && !sig.verify_hash() {
                continue;
            }

            match by_hash.get(&sig.signature_hash) {
                Some(existing) => {
                    // Conflict resolution: higher confidence wins.
                    // Ties broken by newer timestamp (higher created_at).
                    if sig.confidence > existing.confidence
                        || (sig.confidence == existing.confidence && sig.created_at > existing.created_at)
                    {
                        by_hash.insert(sig.signature_hash.clone(), sig.clone());
                    }
                }
                None => {
                    by_hash.insert(sig.signature_hash.clone(), sig.clone());
                }
            }
        }

        let merged: Vec<ThreatSignature> = by_hash.into_values().collect();

        // Update the global model.
        {
            let mut model = self.global_model.write().unwrap();
            model.signatures = merged.clone();
            model.last_sync = now;
            // Track peer contributions.
            for sig in &merged {
                *model
                    .peer_contributions
                    .entry(sig.source_peer.clone())
                    .or_insert(0) += 1;
            }
        }

        merged
    }

    /// Verify a signature's integrity hash.
    pub fn verify_signature(&self, sig: &ThreatSignature) -> bool {
        sig.verify_hash()
    }

    /// Compute the diff between two signature sets.
    pub fn compute_signature_diff(
        &self,
        before: &[ThreatSignature],
        after: &[ThreatSignature],
    ) -> SignatureDiff {
        let before_hashes: std::collections::HashSet<&str> =
            before.iter().map(|s| s.signature_hash.as_str()).collect();
        let after_hashes: std::collections::HashSet<&str> =
            after.iter().map(|s| s.signature_hash.as_str()).collect();

        let added = after_hashes.difference(&before_hashes).count();
        let removed = before_hashes.difference(&after_hashes).count();

        // Updated = hashes present in both but with different content.
        // For simplicity, we count signatures with the same hash as unchanged,
        // and those with different data (different id for same pattern) as updated.
        // Here we use a content-based comparison: if a hash exists in both
        // but the full signature differs, it's an update.
        let before_map: HashMap<&str, &ThreatSignature> =
            before.iter().map(|s| (s.signature_hash.as_str(), s)).collect();
        let after_map: HashMap<&str, &ThreatSignature> =
            after.iter().map(|s| (s.signature_hash.as_str(), s)).collect();

        let mut updated = 0usize;
        let mut unchanged = 0usize;
        for hash in after_hashes.intersection(&before_hashes) {
            match (before_map.get(hash), after_map.get(hash)) {
                (Some(b), Some(a)) => {
                    if a.confidence != b.confidence || a.severity != b.severity {
                        updated += 1;
                    } else {
                        unchanged += 1;
                    }
                }
                _ => unreachable!(),
            }
        }

        SignatureDiff {
            added,
            removed,
            updated,
            unchanged,
        }
    }

    /// Handle an incoming sync request from a peer.
    pub fn handle_sync_request(&self, _request: &SyncRequest) -> SyncResponse {
        let model = self.global_model.read().unwrap();
        let local_sigs: Vec<ThreatSignature> = model
            .signatures
            .iter()
            .take(self.config.max_signatures_per_sync)
            .cloned()
            .collect();

        // Compute diff: everything we have is "new" from the requester's perspective.
        let diff = SignatureDiff {
            added: local_sigs.len().min(self.config.max_signatures_per_sync),
            removed: 0,
            updated: 0,
            unchanged: 0,
        };

        SyncResponse {
            signatures: local_sigs,
            model_version: model.version.clone(),
            diff,
        }
    }

    /// Process a sync response from a remote peer.
    ///
    /// Merges the received signatures with the local global model.
    pub fn process_sync_response(&self, response: &SyncResponse) -> SignatureDiff {
        let model = self.global_model.read().unwrap();
        let local = model.signatures.clone();
        drop(model);

        let merged = self.merge_signatures(&local, &response.signatures);
        let before_hashes: std::collections::HashSet<&str> =
            local.iter().map(|s| s.signature_hash.as_str()).collect();
        let after_hashes: std::collections::HashSet<&str> =
            merged.iter().map(|s| s.signature_hash.as_str()).collect();

        let added = after_hashes.difference(&before_hashes).count();
        SignatureDiff {
            added,
            removed: 0,
            updated: 0,
            unchanged: after_hashes.intersection(&before_hashes).count(),
        }
    }

    /// Get a reference to the current global threat model.
    pub fn global_model(&self) -> std::sync::RwLockReadGuard<'_, GlobalThreatModel> {
        self.global_model.read().unwrap()
    }

    /// Get the number of active signatures.
    pub fn signature_count(&self) -> usize {
        self.global_model.read().unwrap().signatures.len()
    }

    /// Add a single signature directly to the global model.
    pub fn add_signature(&self, sig: ThreatSignature) {
        let mut model = self.global_model.write().unwrap();
        // Don't add duplicates.
        let hash = sig.signature_hash.clone();
        let exists = model.signatures.iter().any(|s| s.signature_hash == hash);
        if !exists {
            let peer = sig.source_peer.clone();
            model.signatures.push(sig);
            *model.peer_contributions.entry(peer).or_insert(0) += 1;
        }
    }

    /// Get the config.
    pub fn config(&self) -> &ThreatSyncConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sig(
        id: &str,
        pattern: &str,
        attack_type: &str,
        severity: f64,
        confidence: f64,
        peer: &str,
    ) -> ThreatSignature {
        ThreatSignature::new(
            id.to_string(),
            pattern.to_string(),
            attack_type.to_string(),
            severity,
            confidence,
            peer.to_string(),
            86400,
        )
    }

    #[test]
    fn test_signature_creation() {
        let sig = make_sig("s1", "ignore all.*instructions", "prompt_injection", 8.0, 0.95, "peer-a");
        assert_eq!(sig.pattern, "ignore all.*instructions");
        assert!((sig.severity - 8.0).abs() < 1e-9);
        assert!((sig.confidence - 0.95).abs() < 1e-9);
        assert!(!sig.signature_hash.is_empty());
        assert!(sig.expires_at > sig.created_at);
    }

    #[test]
    fn test_hash_verification() {
        let sig = make_sig("s1", "test pattern", "xss", 5.0, 0.9, "peer-1");
        assert!(sig.verify_hash());

        // Tamper with the pattern — hash should no longer match.
        let mut tampered = sig.clone();
        tampered.pattern = "tampered".to_string();
        assert!(!tampered.verify_hash());
    }

    #[test]
    fn test_deduplication_by_hash() {
        let sync = ThreatSignatureSync::new(ThreatSyncConfig::default());

        let sig1 = make_sig("s1", "pattern-a", "xss", 7.0, 0.9, "peer-1");
        let sig2 = make_sig("s2", "pattern-a", "xss", 7.0, 0.9, "peer-1");
        // Same pattern + attack_type + source → same hash.
        assert_eq!(sig1.signature_hash, sig2.signature_hash);

        let merged = sync.merge_signatures(&[sig1], &[sig2]);
        assert_eq!(merged.len(), 1, "Duplicate hash should be deduplicated");
    }

    #[test]
    fn test_conflict_resolution_higher_confidence_wins() {
        let sync = ThreatSignatureSync::new(ThreatSyncConfig {
            verification_required: false,
            ..Default::default()
        });

        // Same pattern+type+source → same hash, but different confidence.
        let sig_low = make_sig("s1", "pattern-x", "xss", 5.0, 0.6, "peer-1");
        let mut sig_high = make_sig("s1", "pattern-x", "xss", 5.0, 0.9, "peer-1");
        // Same hash since pattern, type, and source are identical.
        assert_eq!(sig_low.signature_hash, sig_high.signature_hash);

        // Make the high-confidence one newer.
        sig_high.created_at = sig_low.created_at + 100;

        let merged = sync.merge_signatures(&[sig_low], &[sig_high]);
        assert_eq!(merged.len(), 1);
        assert!(
            (merged[0].confidence - 0.9).abs() < 1e-9,
            "Higher confidence should win"
        );
    }

    #[test]
    fn test_conflict_resolution_newer_timestamp_tiebreak() {
        let sync = ThreatSignatureSync::new(ThreatSyncConfig {
            verification_required: false,
            ..Default::default()
        });

        // Same confidence, different timestamps.
        let sig_old = make_sig("s1", "pattern-y", "sqli", 5.0, 0.8, "peer-1");
        let mut sig_new = make_sig("s1", "pattern-y", "sqli", 5.0, 0.8, "peer-1");
        sig_new.created_at = sig_old.created_at + 1000;
        let new_created_at = sig_new.created_at;

        let merged = sync.merge_signatures(&[sig_old], &[sig_new]);
        assert_eq!(merged[0].created_at, new_created_at);
    }

    #[test]
    fn test_ttl_expiration_filtering() {
        let sync = ThreatSignatureSync::new(ThreatSyncConfig::default());

        let mut expired_sig = make_sig("s1", "old-pattern", "xss", 5.0, 0.9, "peer-1");
        expired_sig.created_at = 100;
        expired_sig.expires_at = 200; // Long expired.

        let fresh_sig = make_sig("s2", "new-pattern", "sqli", 5.0, 0.9, "peer-1");

        // Set current time far in the future.
        let _now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let merged = sync.merge_signatures(&[expired_sig, fresh_sig], &[]);
        // The expired one should be filtered out.
        assert!(merged.iter().any(|s| s.id == "s2"));
        assert!(!merged.iter().any(|s| s.id == "s1"));
    }

    #[test]
    fn test_diff_computation() {
        let sync = ThreatSignatureSync::new(ThreatSyncConfig::default());

        let sig1 = make_sig("s1", "pattern-1", "xss", 5.0, 0.9, "peer-1");
        let sig2 = make_sig("s2", "pattern-2", "sqli", 6.0, 0.8, "peer-1");
        let sig3 = make_sig("s3", "pattern-3", "rce", 7.0, 0.7, "peer-2");

        // before has s1, s2; after has s2, s3.
        let diff = sync.compute_signature_diff(&[sig1, sig2.clone()], &[sig2, sig3]);
        assert_eq!(diff.added, 1);   // s3 is new
        assert_eq!(diff.removed, 1); // s1 was removed
        assert_eq!(diff.unchanged, 1); // s2 unchanged
    }

    #[test]
    fn test_sync_protocol_handshake() {
        let sync = ThreatSignatureSync::new(ThreatSyncConfig::default());

        // Add some signatures to the global model.
        sync.add_signature(make_sig("s1", "p1", "xss", 5.0, 0.9, "peer-a"));
        sync.add_signature(make_sig("s2", "p2", "sqli", 6.0, 0.8, "peer-b"));

        // Peer sends a sync request.
        let request = SyncRequest {
            peer_id: "peer-c".to_string(),
            local_model_version: "0.0.0".to_string(),
            local_signature_count: 0,
        };

        let response = sync.handle_sync_request(&request);
        assert_eq!(response.signatures.len(), 2);
        assert_eq!(response.diff.added, 2);
    }

    #[test]
    fn test_merge_with_empty_local() {
        let sync = ThreatSignatureSync::new(ThreatSyncConfig {
            verification_required: false,
            ..Default::default()
        });

        let remote = vec![
            make_sig("s1", "p1", "xss", 5.0, 0.9, "peer-a"),
            make_sig("s2", "p2", "sqli", 6.0, 0.8, "peer-b"),
        ];

        let merged = sync.merge_signatures(&[], &remote);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_merge_with_empty_remote() {
        let sync = ThreatSignatureSync::new(ThreatSyncConfig::default());
        let local = vec![make_sig("s1", "p1", "xss", 5.0, 0.9, "peer-a")];
        let merged = sync.merge_signatures(&local, &[]);
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn test_large_batch_merging() {
        let sync = ThreatSignatureSync::new(ThreatSyncConfig::default());

        // Generate 500 local + 500 remote unique signatures.
        let local: Vec<ThreatSignature> = (0..500)
            .map(|i| make_sig(&format!("l-{}", i), &format!("lp-{}", i), "xss", 5.0, 0.9, "peer-local"))
            .collect();
        let remote: Vec<ThreatSignature> = (0..500)
            .map(|i| make_sig(&format!("r-{}", i), &format!("rp-{}", i), "sqli", 6.0, 0.8, "peer-remote"))
            .collect();

        let merged = sync.merge_signatures(&local, &remote);
        assert_eq!(merged.len(), 1000, "All unique signatures should be merged");
    }

    #[test]
    fn test_peer_contribution_tracking() {
        let sync = ThreatSignatureSync::new(ThreatSyncConfig::default());

        sync.add_signature(make_sig("s1", "p1", "xss", 5.0, 0.9, "peer-a"));
        sync.add_signature(make_sig("s2", "p2", "sqli", 6.0, 0.8, "peer-a"));
        sync.add_signature(make_sig("s3", "p3", "rce", 7.0, 0.7, "peer-b"));

        let model = sync.global_model();
        assert_eq!(*model.peer_contributions.get("peer-a").unwrap_or(&0), 2);
        assert_eq!(*model.peer_contributions.get("peer-b").unwrap_or(&0), 1);
    }

    #[test]
    fn test_verification_skips_invalid_signatures() {
        let sync = ThreatSignatureSync::new(ThreatSyncConfig {
            verification_required: true,
            ..Default::default()
        });

        let mut tampered = make_sig("s1", "original", "xss", 5.0, 0.9, "peer-1");
        tampered.pattern = "tampered".to_string();
        // Hash no longer matches.
        assert!(!tampered.verify_hash());

        let valid = make_sig("s2", "valid", "sqli", 6.0, 0.8, "peer-2");

        let merged = sync.merge_signatures(&[], &[tampered, valid]);
        assert_eq!(merged.len(), 1, "Tampered signature should be rejected");
        assert_eq!(merged[0].id, "s2");
    }

    #[test]
    fn test_signature_count() {
        let sync = ThreatSignatureSync::new(ThreatSyncConfig::default());
        assert_eq!(sync.signature_count(), 0);
        sync.add_signature(make_sig("s1", "p1", "xss", 5.0, 0.9, "peer-a"));
        assert_eq!(sync.signature_count(), 1);
    }

    #[test]
    fn test_severity_clamping() {
        let sig = ThreatSignature::new(
            "s1".into(),
            "p1".into(),
            "xss".into(),
            15.0,  // Above max of 10.0
            2.0,   // Above max of 1.0
            "peer-1".into(),
            86400,
        );
        assert!((sig.severity - 10.0).abs() < 1e-9);
        assert!((sig.confidence - 1.0).abs() < 1e-9);
    }
}
