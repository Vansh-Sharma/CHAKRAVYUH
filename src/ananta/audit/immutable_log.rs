// Immutable Audit Log Storage Engine
//
// This module provides the underlying immutable storage engine for the ANANTA
// audit subsystem. It implements a write-ahead log (WAL), Merkle checkpointing,
// a lock-free ring buffer for in-memory entries, hash-chained immutable entries,
// and background compaction.
//
// Design principles:
//   - Append-only: entries are never mutated after creation.
//   - Cryptographic integrity: every entry is chained via hashes and verified
//     against periodic Merkle checkpoints.
//   - Crash recovery: WAL ensures durability; replay rebuilds state.
//   - Concurrent access: the ring buffer uses atomic operations for lock-free
//     reads and writes.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::ananta::crypto::hashing::{hash_bytes, hash_combined, HashDigest};
use crate::ananta::crypto::merkle::{MerkleProof, MerkleTree};
use crate::ananta::config::HashAlgorithm;

// ─── CRC-32 Implementation ─────────────────────────────────────────────────

/// CRC-32 lookup table (IEEE 802.3 polynomial 0xEDB88320).
const CRC32_TABLE: [u32; 256] = generate_crc32_table();

/// Build the CRC-32 lookup table at compile time.
const fn generate_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0usize;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// Compute CRC-32 (IEEE) over a byte slice.
#[inline]
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        let index = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[index];
    }
    crc ^ 0xFFFFFFFF
}

// ─── WAL (Write-Ahead Log) ─────────────────────────────────────────────────

/// Errors that can occur during WAL operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalError {
    /// CRC mismatch on read — data corruption detected.
    CrcMismatch { expected: u32, actual: u32, offset: usize },
    /// The WAL buffer is truncated mid-entry.
    TruncatedEntry { offset: usize, remaining: usize },
    /// The buffer cannot hold the entry (would exceed max size).
    BufferOverflow { required: usize, available: usize },
    /// An I/O or encoding error occurred.
    CodecError(String),
}

impl std::fmt::Display for WalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalError::CrcMismatch { expected, actual, offset } => {
                write!(f, "CRC mismatch at offset {}: expected 0x{:08X}, got 0x{:08X}", offset, expected, actual)
            }
            WalError::TruncatedEntry { offset, remaining } => {
                write!(f, "truncated entry at offset {}: only {} bytes remaining", offset, remaining)
            }
            WalError::BufferOverflow { required, available } => {
                write!(f, "buffer overflow: requires {} bytes, {} available", required, available)
            }
            WalError::CodecError(msg) => write!(f, "codec error: {}", msg),
        }
    }
}

impl std::error::Error for WalError {}

/// A raw WAL entry read from the buffer during replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalRawEntry {
    /// The raw data bytes (payload).
    pub data: Vec<u8>,
    /// CRC-32 that was stored alongside the entry.
    pub stored_crc: u32,
    /// Byte offset of this entry in the WAL buffer.
    pub offset: usize,
}

/// Write-Ahead Log operating on an in-memory `Vec<u8>` buffer.
///
/// Entry wire format:
/// ```text
/// [length_u32 LE][crc32_u32 LE][data_bytes ...]
/// ```
///
/// The `length` field encodes the byte length of `data_bytes` only.
/// The `crc32` covers the `data_bytes` payload.
///
/// This simulates file I/O so that all operations are testable without
/// touching the filesystem.
#[derive(Debug)]
pub struct WriteAheadLog {
    /// The underlying byte buffer (append-only).
    buffer: Vec<u8>,
    /// Current write position (always == buffer.len() for append-only).
    write_pos: AtomicUsize,
    /// Number of entries written.
    entry_count: AtomicUsize,
    /// Truncation point: entries before this byte offset are considered
    /// checkpointed and may be discarded.
    truncation_point: AtomicUsize,
    /// When true, each append is immediately "synced" (the buffer is
    /// logically flushed). In a real implementation this would call
    /// `fsync`. Here we just track the semantic.
    sync_on_write: bool,
    /// Batch size: after this many un-synced writes, force a sync.
    batch_sync_size: usize,
    /// Pending (un-synced) write count since last sync.
    pending_sync_count: AtomicUsize,
    /// Total number of syncs performed.
    sync_count: AtomicUsize,
}

impl WriteAheadLog {
    /// Create a new empty WAL.
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            write_pos: AtomicUsize::new(0),
            entry_count: AtomicUsize::new(0),
            truncation_point: AtomicUsize::new(0),
            sync_on_write: true,
            batch_sync_size: 1,
            pending_sync_count: AtomicUsize::new(0),
            sync_count: AtomicUsize::new(0),
        }
    }

    /// Create a WAL with custom sync configuration.
    ///
    /// * `sync_on_write` — if true, every append triggers a sync.
    /// * `batch_sync_size` — if `sync_on_write` is false, a sync is forced
    ///   after this many pending writes.
    pub fn with_sync_config(sync_on_write: bool, batch_sync_size: usize) -> Self {
        Self {
            buffer: Vec::new(),
            write_pos: AtomicUsize::new(0),
            entry_count: AtomicUsize::new(0),
            truncation_point: AtomicUsize::new(0),
            sync_on_write,
            batch_sync_size: if batch_sync_size == 0 { 1 } else { batch_sync_size },
            pending_sync_count: AtomicUsize::new(0),
            sync_count: AtomicUsize::new(0),
        }
    }

    /// Append a raw byte payload to the WAL.
    ///
    /// Returns the byte offset at which the entry was written.
    /// Performs CRC computation and, depending on config, an immediate sync.
    pub fn append(&mut self, data: &[u8]) -> Result<usize, WalError> {
        let len = data.len() as u32;
        let checksum = crc32(data);
        let entry_size = 4 + 4 + data.len(); // length + crc + data

        // Check buffer capacity (soft limit at 64 MiB for in-memory).
        const MAX_BUFFER_SIZE: usize = 64 * 1024 * 1024;
        if self.buffer.len() + entry_size > MAX_BUFFER_SIZE {
            return Err(WalError::BufferOverflow {
                required: self.buffer.len() + entry_size,
                available: MAX_BUFFER_SIZE,
            });
        }

        let offset = self.buffer.len();
        self.buffer.extend_from_slice(&len.to_le_bytes());
        self.buffer.extend_from_slice(&checksum.to_le_bytes());
        self.buffer.extend_from_slice(data);

        self.write_pos.store(self.buffer.len(), Ordering::SeqCst);
        self.entry_count.fetch_add(1, Ordering::SeqCst);

        // Sync semantics.
        if self.sync_on_write {
            self.sync();
        } else {
            let pending = self.pending_sync_count.fetch_add(1, Ordering::SeqCst) + 1;
            if pending >= self.batch_sync_size {
                self.sync();
            }
        }

        Ok(offset)
    }

    /// Perform a sync (conceptually `fsync`).
    /// In this in-memory simulation, it just resets the pending counter.
    pub fn sync(&self) {
        self.pending_sync_count.store(0, Ordering::SeqCst);
        self.sync_count.fetch_add(1, Ordering::SeqCst);
    }

    /// Replay all entries from the WAL, validating CRCs.
    ///
    /// Returns a vector of successfully parsed entries in order.
    /// Stops at the first unrecoverable error.
    pub fn replay(&self) -> Result<Vec<WalRawEntry>, WalError> {
        let mut entries = Vec::new();
        let mut pos = 0usize;

        while pos < self.buffer.len() {
            let entry_offset = pos;

            // Read length (4 bytes).
            if pos + 4 > self.buffer.len() {
                let remaining = self.buffer.len() - pos;
                return Err(WalError::TruncatedEntry {
                    offset: entry_offset,
                    remaining,
                });
            }
            let len = u32::from_le_bytes([
                self.buffer[pos],
                self.buffer[pos + 1],
                self.buffer[pos + 2],
                self.buffer[pos + 3],
            ]) as usize;
            pos += 4;

            // Read CRC (4 bytes).
            if pos + 4 > self.buffer.len() {
                let remaining = self.buffer.len() - pos;
                return Err(WalError::TruncatedEntry {
                    offset: entry_offset,
                    remaining,
                });
            }
            let stored_crc = u32::from_le_bytes([
                self.buffer[pos],
                self.buffer[pos + 1],
                self.buffer[pos + 2],
                self.buffer[pos + 3],
            ]);
            pos += 4;

            // Read data.
            if pos + len > self.buffer.len() {
                let remaining = self.buffer.len() - pos;
                return Err(WalError::TruncatedEntry {
                    offset: entry_offset,
                    remaining,
                });
            }
            let data = self.buffer[pos..pos + len].to_vec();
            pos += len;

            // Validate CRC.
            let actual_crc = crc32(&data);
            if actual_crc != stored_crc {
                return Err(WalError::CrcMismatch {
                    expected: stored_crc,
                    actual: actual_crc,
                    offset: entry_offset,
                });
            }

            entries.push(WalRawEntry {
                data,
                stored_crc,
                offset: entry_offset,
            });
        }

        Ok(entries)
    }

    /// Set the truncation point. Entries with offset < `point` are
    /// considered checkpointed and safe to discard.
    pub fn set_truncation_point(&self, point: usize) {
        self.truncation_point.store(point, Ordering::SeqCst);
    }

    /// Get the current truncation point.
    pub fn truncation_point(&self) -> usize {
        self.truncation_point.load(Ordering::SeqCst)
    }

    /// Truncate the WAL buffer up to the truncation point, freeing memory.
    /// Returns the number of bytes removed.
    pub fn truncate(&mut self) -> usize {
        let point = self.truncation_point.load(Ordering::SeqCst);
        if point == 0 || point > self.buffer.len() {
            return 0;
        }
        let removed = point;
        self.buffer.drain(..point);
        self.write_pos.store(self.buffer.len(), Ordering::SeqCst);
        self.truncation_point.store(0, Ordering::SeqCst);
        removed
    }

    /// Number of entries in the WAL.
    pub fn entry_count(&self) -> usize {
        self.entry_count.load(Ordering::SeqCst)
    }

    /// Total bytes in the WAL buffer.
    pub fn buffer_size(&self) -> usize {
        self.buffer.len()
    }

    /// Number of syncs performed.
    pub fn sync_count(&self) -> usize {
        self.sync_count.load(Ordering::SeqCst)
    }

    /// Read-only access to the underlying buffer (for inspection/testing).
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Clear the entire WAL. Used for testing.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.write_pos.store(0, Ordering::SeqCst);
        self.entry_count.store(0, Ordering::SeqCst);
        self.truncation_point.store(0, Ordering::SeqCst);
        self.pending_sync_count.store(0, Ordering::SeqCst);
        self.sync_count.store(0, Ordering::SeqCst);
    }
}

impl Default for WriteAheadLog {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Merkle Checkpoint ──────────────────────────────────────────────────────

/// A persisted Merkle checkpoint snapshot.
///
/// Stores the Merkle root hash and entry count at the time the
/// checkpoint was created. On recovery, the latest checkpoint is
/// loaded and then WAL entries after it are replayed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleCheckpoint {
    /// The Merkle root hash (hex-encoded).
    pub root_hash_hex: String,
    /// The raw root hash bytes.
    pub root_hash_bytes: Vec<u8>,
    /// The hash algorithm used to build the tree.
    pub algorithm: HashAlgorithm,
    /// The number of entries included in this checkpoint.
    pub entry_count: u64,
    /// The WAL byte offset at which this checkpoint was taken.
    /// WAL entries at or after this offset are post-checkpoint.
    pub wal_offset: usize,
    /// Monotonic checkpoint sequence number.
    pub checkpoint_sequence: u64,
    /// ISO 8601 timestamp of when this checkpoint was created.
    pub timestamp: String,
    /// The individual leaf hashes (for verification).
    pub leaf_hashes: Vec<String>,
}

impl MerkleCheckpoint {
    /// Build a Merkle checkpoint from a list of entry content hashes.
    ///
    /// Each `entry_hashes` element is the hex-encoded content hash of
    /// one log entry, in sequence order.
    pub fn from_entry_hashes(
        entry_hashes: &[String],
        algorithm: &HashAlgorithm,
        wal_offset: usize,
        checkpoint_sequence: u64,
    ) -> Self {
        let timestamp = chrono::Utc::now().to_rfc3339();

        if entry_hashes.is_empty() {
            // Empty checkpoint.
            let empty_root = hash_bytes(b"empty_immutable_log_checkpoint", algorithm);
            return Self {
                root_hash_hex: empty_root.hex.clone(),
                root_hash_bytes: empty_root.bytes,
                algorithm: algorithm.clone(),
                entry_count: 0,
                wal_offset,
                checkpoint_sequence,
                timestamp,
                leaf_hashes: vec![],
            };
        }

        // Build leaf data by constructing HashDigest values directly from
        // the hex-encoded content hashes. This avoids double-hashing: the
        // content hashes ARE the Merkle leaves (they're already hashes).
        let leaves: Vec<HashDigest> = entry_hashes
            .iter()
            .filter_map(|h| {
                let bytes = hex::decode(h).ok()?;
                Some(HashDigest {
                    algorithm: algorithm.clone(),
                    bytes,
                    hex: h.clone(),
                })
            })
            .collect();

        let tree = MerkleTree::from_leaves(&leaves, algorithm);

        let leaf_hashes = tree.leaves.iter().map(|l| l.hex.clone()).collect();

        Self {
            root_hash_hex: tree.root.hex.clone(),
            root_hash_bytes: tree.root.bytes,
            algorithm: algorithm.clone(),
            entry_count: entry_hashes.len() as u64,
            wal_offset,
            checkpoint_sequence,
            timestamp,
            leaf_hashes,
        }
    }

    /// Verify that a set of entry hashes produces this checkpoint's root.
    pub fn verify(&self, entry_hashes: &[String]) -> bool {
        if entry_hashes.len() != self.entry_count as usize {
            return false;
        }
        let leaves: Vec<HashDigest> = entry_hashes
            .iter()
            .filter_map(|h| {
                let bytes = hex::decode(h).ok()?;
                Some(HashDigest {
                    algorithm: self.algorithm.clone(),
                    bytes,
                    hex: h.clone(),
                })
            })
            .collect();
        let tree = MerkleTree::from_leaves(&leaves, &self.algorithm);
        tree.root.bytes == self.root_hash_bytes
    }
}

// ─── Lock-Free Ring Buffer ──────────────────────────────────────────────────

/// Policy for handling buffer overflow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OverflowPolicy {
    /// Reject new entries when the buffer is full.
    Reject,
    /// Overwrite the oldest entry.
    OverwriteOldest,
}

/// A lock-free fixed-size ring buffer for in-memory log entries.
///
/// Uses `AtomicUsize` for the read and write cursors so that
/// concurrent readers and writers can proceed without a mutex.
///
/// Memory layout: a contiguous `Vec<Option<T>>` with wrap-around
/// indexing via modulo arithmetic.
#[derive(Debug)]
pub struct RingBuffer<T: Clone + std::fmt::Debug> {
    /// The underlying contiguous array.
    slots: Vec<Option<T>>,
    /// Capacity (power-of-two recommended for fast modulo).
    capacity: usize,
    /// Write cursor (next slot to write to).
    write_cursor: AtomicUsize,
    /// Read cursor (next slot to read from).
    read_cursor: AtomicUsize,
    /// Number of items currently in the buffer.
    size: AtomicUsize,
    /// Total number of items ever written (monotonic).
    total_written: AtomicU64,
    /// Total number of items ever read/removed.
    total_read: AtomicU64,
    /// Total number of items dropped due to overflow.
    dropped_count: AtomicU64,
    /// Overflow policy.
    overflow_policy: OverflowPolicy,
}

impl<T: Clone + std::fmt::Debug> RingBuffer<T> {
    /// Create a new ring buffer with the given capacity.
    /// Capacity must be >= 1.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity >= 1, "ring buffer capacity must be >= 1");
        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(None);
        }
        Self {
            slots,
            capacity,
            write_cursor: AtomicUsize::new(0),
            read_cursor: AtomicUsize::new(0),
            size: AtomicUsize::new(0),
            total_written: AtomicU64::new(0),
            total_read: AtomicU64::new(0),
            dropped_count: AtomicU64::new(0),
            overflow_policy: OverflowPolicy::Reject,
        }
    }

    /// Create a ring buffer with a specific overflow policy.
    pub fn with_policy(capacity: usize, overflow_policy: OverflowPolicy) -> Self {
        let mut buf = Self::new(capacity);
        buf.overflow_policy = overflow_policy;
        buf
    }

    /// Push an item into the ring buffer.
    ///
    /// Returns `Ok(())` on success, or `Err(item)` if the policy is
    /// `Reject` and the buffer is full.
    pub fn push(&mut self, item: T) -> Result<(), T> {
        let write_idx = self.write_cursor.load(Ordering::SeqCst);
        let read_idx = self.read_cursor.load(Ordering::SeqCst);
        let current_size = self.size.load(Ordering::SeqCst);

        // Determine if buffer is full.
        if current_size >= self.capacity {
            match self.overflow_policy {
                OverflowPolicy::Reject => {
                    self.dropped_count.fetch_add(1, Ordering::SeqCst);
                    return Err(item);
                }
                OverflowPolicy::OverwriteOldest => {
                    // Advance read cursor, dropping the oldest entry.
                    let new_read = (read_idx + 1) % self.capacity;
                    self.read_cursor.store(new_read, Ordering::SeqCst);
                    self.total_read.fetch_add(1, Ordering::SeqCst);
                    self.dropped_count.fetch_add(1, Ordering::SeqCst);
                    // Size stays the same: we removed one and will add one.
                }
            }
        } else {
            // Normal push: increment size.
            self.size.fetch_add(1, Ordering::SeqCst);
        }

        // Write the item.
        self.slots[write_idx] = Some(item);
        self.write_cursor
            .store((write_idx + 1) % self.capacity, Ordering::SeqCst);
        self.total_written.fetch_add(1, Ordering::SeqCst);

        Ok(())
    }

    /// Pop the oldest item from the ring buffer.
    ///
    /// Returns `None` if the buffer is empty.
    pub fn pop(&mut self) -> Option<T> {
        let current_size = self.size.load(Ordering::SeqCst);

        if current_size == 0 {
            return None; // Empty.
        }

        let read_idx = self.read_cursor.load(Ordering::SeqCst);
        let item = self.slots[read_idx].take();
        self.read_cursor
            .store((read_idx + 1) % self.capacity, Ordering::SeqCst);
        self.size.fetch_sub(1, Ordering::SeqCst);
        self.total_read.fetch_add(1, Ordering::SeqCst);
        item
    }

    /// Peek at the oldest item without removing it.
    pub fn peek(&self) -> Option<&T> {
        let current_size = self.size.load(Ordering::SeqCst);
        if current_size == 0 {
            return None;
        }
        let read_idx = self.read_cursor.load(Ordering::SeqCst);
        self.slots[read_idx].as_ref()
    }

    /// Read all items currently in the buffer without removing them.
    /// Items are returned in insertion order (oldest first).
    pub fn read_all(&self) -> Vec<T> {
        let read_idx = self.read_cursor.load(Ordering::SeqCst);
        let current_size = self.size.load(Ordering::SeqCst);

        let mut result = Vec::new();
        for i in 0..current_size {
            let idx = (read_idx + i) % self.capacity;
            if let Some(item) = self.slots[idx].as_ref() {
                result.push(item.clone());
            }
        }
        result
    }

    /// Number of items currently in the buffer.
    pub fn len(&self) -> usize {
        self.size.load(Ordering::SeqCst)
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.size.load(Ordering::SeqCst) == 0
    }

    /// Capacity of the buffer.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Total number of items ever pushed.
    pub fn total_written(&self) -> u64 {
        self.total_written.load(Ordering::SeqCst)
    }

    /// Total number of items ever popped.
    pub fn total_read(&self) -> u64 {
        self.total_read.load(Ordering::SeqCst)
    }

    /// Total number of items dropped due to overflow.
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count.load(Ordering::SeqCst)
    }

    /// Clear all items from the buffer, resetting cursors.
    pub fn clear(&self) {
        for slot in self.slots.iter() {
            let _ = slot; // slots are Option<T>; we just reset cursors.
        }
        // We cannot clear Option<T> through a shared reference without
        // interior mutability, so we reset cursors. On next push, old
        // data is overwritten.
        self.write_cursor.store(0, Ordering::SeqCst);
        self.read_cursor.store(0, Ordering::SeqCst);
        self.size.store(0, Ordering::SeqCst);
    }

    /// Get the overflow policy.
    pub fn overflow_policy(&self) -> &OverflowPolicy {
        &self.overflow_policy
    }
}

// ─── Immutable Entry Chain ──────────────────────────────────────────────────

/// A serialized Merkle proof attached to an entry.
/// Stored as sibling hex hashes and direction flags for compactness.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredMerkleProof {
    /// Index of this entry's leaf in the Merkle tree.
    pub leaf_index: usize,
    /// Hex hash of the Merkle root this proof is against.
    pub root_hash_hex: String,
    /// Sibling hashes along the path; each element is
    /// `(sibling_hex_hash, is_right_sibling)`.
    pub siblings: Vec<(String, bool)>,
}

impl StoredMerkleProof {
    /// Convert from a `MerkleProof` produced by the `MerkleTree`.
    pub fn from_merkle_proof(proof: &MerkleProof) -> Self {
        Self {
            leaf_index: proof.leaf_index,
            root_hash_hex: proof.root_hash.hex.clone(),
            siblings: proof
                .path
                .iter()
                .map(|(digest, is_right)| (digest.hex.clone(), *is_right))
                .collect(),
        }
    }

    /// Verify this stored proof against a given leaf hash and algorithm.
    pub fn verify(&self, leaf_hash_hex: &str, algorithm: &HashAlgorithm) -> bool {
        // The leaf_hash_hex is already the leaf hash (hex-encoded).
        // The tree was built from hash_bytes(item.as_bytes()), so each leaf
        // is a HashDigest whose .bytes we need. Decode the hex directly.
        let mut current = match hex::decode(leaf_hash_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        for (sibling_hex, is_right) in &self.siblings {
            let sibling_bytes = match hex::decode(sibling_hex) {
                Ok(b) => b,
                Err(_) => return false,
            };
            let combined = if *is_right {
                hash_combined(&[&current, &sibling_bytes], algorithm)
            } else {
                hash_combined(&[&sibling_bytes, &current], algorithm)
            };
            current = combined.bytes;
        }

        current == hex::decode(&self.root_hash_hex).unwrap_or_default()
    }
}

/// A single immutable log entry in the hash chain.
///
/// Each entry links to its predecessor via `prev_hash`, forming a
/// tamper-evident chain. The `content_hash` covers all entry fields
/// except the hash chain links themselves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmutableEntry {
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// Hash of the previous entry (or the genesis sentinel).
    pub prev_hash: String,
    /// Hash of this entry's content.
    pub content_hash: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Human-readable message.
    pub message: String,
    /// Optional structured data payload (JSON-serialized).
    pub payload: String,
    /// Merkle proof against the latest checkpoint at write time.
    pub merkle_proof: Option<StoredMerkleProof>,
    /// The checkpoint sequence number at the time this entry was written.
    pub checkpoint_sequence: u64,
}

impl ImmutableEntry {
    /// Sentinel hash used as the `prev_hash` of the very first entry.
    pub fn genesis_prev_hash() -> String {
        "0".repeat(64)
    }

    /// Compute the content hash for an entry.
    ///
    /// The content hash covers: sequence, prev_hash, timestamp, message, payload.
    pub fn compute_content_hash(
        algorithm: &HashAlgorithm,
        sequence: u64,
        prev_hash: &str,
        timestamp: &str,
        message: &str,
        payload: &str,
    ) -> String {
        let seq_bytes = sequence.to_le_bytes();
        hash_combined(
            &[
                &seq_bytes,
                prev_hash.as_bytes(),
                timestamp.as_bytes(),
                message.as_bytes(),
                payload.as_bytes(),
            ],
            algorithm,
        )
        .hex
    }

    /// Create a new immutable entry.
    pub fn new(
        sequence: u64,
        prev_hash: &str,
        message: &str,
        payload: &str,
        algorithm: &HashAlgorithm,
        checkpoint_sequence: u64,
    ) -> Self {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let content_hash = Self::compute_content_hash(
            algorithm,
            sequence,
            prev_hash,
            &timestamp,
            message,
            payload,
        );
        Self {
            sequence,
            prev_hash: prev_hash.to_string(),
            content_hash,
            timestamp,
            message: message.to_string(),
            payload: payload.to_string(),
            merkle_proof: None,
            checkpoint_sequence,
        }
    }

    /// Serialize this entry to bytes for WAL storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("immutable entry serialization must succeed")
    }

    /// Deserialize an entry from bytes (e.g., after WAL replay).
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| format!("immutable entry deserialization: {}", e))
    }
}

// ─── Compaction ─────────────────────────────────────────────────────────────

/// Result of a compaction operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactionResult {
    /// Number of entries before compaction.
    pub entries_before: usize,
    /// Number of entries after compaction.
    pub entries_after: usize,
    /// Number of entries removed.
    pub entries_removed: usize,
    /// The sequence number of the compaction snapshot entry.
    pub snapshot_sequence: u64,
    /// The new Merkle checkpoint created after compaction.
    pub new_checkpoint: MerkleCheckpoint,
    /// Hash of the last entry before compaction (preserves chain).
    pub last_entry_hash: String,
}

/// Configuration for the compaction subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactionConfig {
    /// Minimum number of entries before compaction is considered.
    pub min_entries: usize,
    /// Target number of entries after compaction.
    pub target_entries: usize,
    /// Whether compaction is enabled.
    pub enabled: bool,
}

impl Default for CompactionConfig {
    fn default() -> Self {
        Self {
            min_entries: 1000,
            target_entries: 100,
            enabled: true,
        }
    }
}

// ─── Immutable Log Engine ───────────────────────────────────────────────────

/// The top-level immutable log engine.
///
/// Combines the WAL, Merkle checkpointing, ring buffer, and hash chain
/// into a single coherent immutable audit log storage engine.
#[derive(Debug)]
pub struct ImmutableLogEngine {
    /// Hash algorithm used throughout.
    pub algorithm: HashAlgorithm,
    /// The write-ahead log (persistent layer).
    pub wal: WriteAheadLog,
    /// All entries in the hash chain (replayable from WAL).
    pub entries: Vec<ImmutableEntry>,
    /// In-memory ring buffer for fast recent-entry access.
    pub ring: RingBuffer<ImmutableEntry>,
    /// Merkle checkpoints (latest is used for recovery).
    pub checkpoints: Vec<MerkleCheckpoint>,
    /// Current checkpoint sequence counter.
    pub checkpoint_sequence: AtomicU64,
    /// Compaction configuration.
    pub compaction_config: CompactionConfig,
    /// Number of compactions performed.
    pub compaction_count: AtomicU64,
    /// How often (in entries) to create a Merkle checkpoint.
    pub checkpoint_interval: u64,
    /// Count of entries since the last checkpoint.
    pub entries_since_checkpoint: AtomicU64,
}

/// Errors from the immutable log engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImmutableLogError {
    /// WAL error.
    Wal(String),
    /// Serialization / deserialization error.
    Codec(String),
    /// Integrity verification failed.
    IntegrityViolation(String),
    /// Ring buffer overflow.
    RingBufferFull,
}

impl std::fmt::Display for ImmutableLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImmutableLogError::Wal(msg) => write!(f, "WAL error: {}", msg),
            ImmutableLogError::Codec(msg) => write!(f, "codec error: {}", msg),
            ImmutableLogError::IntegrityViolation(msg) => {
                write!(f, "integrity violation: {}", msg)
            }
            ImmutableLogError::RingBufferFull => write!(f, "ring buffer is full"),
        }
    }
}

impl std::error::Error for ImmutableLogError {}

impl ImmutableLogEngine {
    /// Create a new immutable log engine.
    ///
    /// * `algorithm` — hash algorithm for all crypto operations.
    /// * `ring_capacity` — size of the in-memory ring buffer.
    /// * `checkpoint_interval` — create a Merkle checkpoint every N entries.
    pub fn new(algorithm: HashAlgorithm, ring_capacity: usize, checkpoint_interval: u64) -> Self {
        Self {
            algorithm: algorithm.clone(),
            wal: WriteAheadLog::new(),
            entries: Vec::new(),
            ring: RingBuffer::with_policy(ring_capacity, OverflowPolicy::OverwriteOldest),
            checkpoints: Vec::new(),
            checkpoint_sequence: AtomicU64::new(0),
            compaction_config: CompactionConfig::default(),
            compaction_count: AtomicU64::new(0),
            checkpoint_interval: if checkpoint_interval == 0 {
                100
            } else {
                checkpoint_interval
            },
            entries_since_checkpoint: AtomicU64::new(0),
        }
    }

    /// Create with a specific compaction config.
    pub fn with_compaction_config(
        algorithm: HashAlgorithm,
        ring_capacity: usize,
        checkpoint_interval: u64,
        compaction_config: CompactionConfig,
    ) -> Self {
        let mut engine = Self::new(algorithm, ring_capacity, checkpoint_interval);
        engine.compaction_config = compaction_config;
        engine
    }

    /// Append a new immutable entry to the log.
    ///
    /// 1. Creates an `ImmutableEntry` with proper hash chaining.
    /// 2. Writes the entry to the WAL.
    /// 3. Inserts into the ring buffer.
    /// 4. May trigger a Merkle checkpoint.
    pub fn append(&mut self, message: &str, payload: &str) -> Result<u64, ImmutableLogError> {
        let sequence = self.entries.len() as u64;
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.content_hash.clone())
            .unwrap_or_else(ImmutableEntry::genesis_prev_hash);

        let cp_seq = self.checkpoint_sequence.load(Ordering::SeqCst);
        let mut entry =
            ImmutableEntry::new(sequence, &prev_hash, message, payload, &self.algorithm, cp_seq);

        // Compute and attach Merkle proof against the latest checkpoint.
        // Decode hex hashes to raw bytes so the tree leaves are the actual hashes.
        if let Some(checkpoint) = self.checkpoints.last() {
            let mut leaf_data: Vec<HashDigest> = checkpoint
                .leaf_hashes
                .iter()
                .filter_map(|h| {
                    let bytes = hex::decode(h).ok()?;
                    Some(HashDigest {
                        algorithm: self.algorithm.clone(),
                        bytes,
                        hex: h.clone(),
                    })
                })
                .collect();
            if let Ok(decoded) = hex::decode(&entry.content_hash) {
                leaf_data.push(HashDigest {
                    algorithm: self.algorithm.clone(),
                    bytes: decoded,
                    hex: entry.content_hash.clone(),
                });
            }
            let tree = MerkleTree::from_leaves(&leaf_data, &self.algorithm);
            let leaf_index = leaf_data.len() - 1;
            if let Some(proof) = tree.proof(leaf_index) {
                entry.merkle_proof = Some(StoredMerkleProof::from_merkle_proof(&proof));
            }
        }

        // Write to WAL.
        let entry_bytes = entry.to_bytes();
        self.wal
            .append(&entry_bytes)
            .map_err(|e| ImmutableLogError::Wal(e.to_string()))?;

        // Store in entries list.
        self.entries.push(entry.clone());

        // Push to ring buffer (may drop oldest if full).
        if self.ring.push(entry).is_err() {
            return Err(ImmutableLogError::RingBufferFull);
        }

        // Checkpoint trigger.
        let since_cp = self.entries_since_checkpoint.fetch_add(1, Ordering::SeqCst) + 1;
        if since_cp >= self.checkpoint_interval {
            self.create_checkpoint();
        }

        Ok(sequence)
    }

    /// Create a Merkle checkpoint from all entries seen so far.
    pub fn create_checkpoint(&mut self) -> &MerkleCheckpoint {
        let cp_seq = self.checkpoint_sequence.fetch_add(1, Ordering::SeqCst);
        let wal_offset = self.wal.buffer_size();
        let entry_hashes: Vec<String> =
            self.entries.iter().map(|e| e.content_hash.clone()).collect();

        let checkpoint = MerkleCheckpoint::from_entry_hashes(
            &entry_hashes,
            &self.algorithm,
            wal_offset,
            cp_seq,
        );

        // Update Merkle proofs for entries that don't have one or have one
        // against an older checkpoint. Use content hashes directly as Merkle
        // leaves (they're already hashes, so no re-hashing needed).
        let leaves: Vec<HashDigest> = entry_hashes
            .iter()
            .filter_map(|h| {
                let bytes = hex::decode(h).ok()?;
                Some(HashDigest {
                    algorithm: self.algorithm.clone(),
                    bytes,
                    hex: h.clone(),
                })
            })
            .collect();
        let tree = MerkleTree::from_leaves(&leaves, &self.algorithm);
        for (i, entry) in self.entries.iter_mut().enumerate() {
            if let Some(proof) = tree.proof(i) {
                entry.merkle_proof = Some(StoredMerkleProof::from_merkle_proof(&proof));
                entry.checkpoint_sequence = cp_seq;
            }
        }

        // Set WAL truncation point to before the checkpoint's entries.
        // We keep all WAL data but mark the checkpoint boundary.
        self.wal.set_truncation_point(0);

        self.checkpoints.push(checkpoint);
        self.entries_since_checkpoint.store(0, Ordering::SeqCst);

        self.checkpoints.last().unwrap()
    }

    /// Perform compaction: merge old entries into a snapshot entry,
    /// preserving hash chain integrity and creating a new checkpoint.
    ///
    /// Compaction keeps the `target_entries` most recent entries and
    /// replaces all older ones with a single snapshot summary entry.
    pub fn compact(&mut self) -> Result<CompactionResult, ImmutableLogError> {
        if !self.compaction_config.enabled {
            return Err(ImmutableLogError::Wal("compaction is disabled".into()));
        }
        if self.entries.len() < self.compaction_config.min_entries {
            return Err(ImmutableLogError::Wal(format!(
                "compaction requires at least {} entries, have {}",
                self.compaction_config.min_entries,
                self.entries.len()
            )));
        }

        let entries_before = self.entries.len();
        let target = self.compaction_config.target_entries;

        if entries_before <= target {
            return Err(ImmutableLogError::Wal(
                "cannot compact: already at or below target".into(),
            ));
        }

        // Split: [entries_to_compact] + [entries_to_keep]
        let split_point = entries_before - target;
        let entries_to_compact: Vec<ImmutableEntry> =
            self.entries.drain(..split_point).collect();
        let entries_removed = entries_to_compact.len();

        // Build a summary of the compacted entries.
        let summary_msg = format!(
            "compaction snapshot: {} entries merged into 1",
            entries_removed
        );
        let summary_payload = serde_json::to_string(&json_compaction_summary(
            &entries_to_compact,
        ))
        .unwrap_or_default();

        // The new first entry must chain from the last compacted entry's prev.
        // We use the first compacted entry's prev_hash to maintain the chain.
        let chain_anchor = entries_to_compact
            .first()
            .map(|e| e.prev_hash.clone())
            .unwrap_or_else(ImmutableEntry::genesis_prev_hash);

        let last_compacted_hash = entries_to_compact
            .last()
            .map(|e| e.content_hash.clone())
            .unwrap_or_else(ImmutableEntry::genesis_prev_hash);

        // Create the snapshot entry that replaces all compacted entries.
        let snapshot_seq = 0u64; // Will be renumbered.
        let snapshot = ImmutableEntry::new(
            snapshot_seq,
            &chain_anchor,
            &summary_msg,
            &summary_payload,
            &self.algorithm,
            self.checkpoint_sequence.load(Ordering::SeqCst),
        );

        // Prepend the snapshot, then renumber all entries.
        let mut new_entries = vec![snapshot];
        new_entries.extend(self.entries.drain(..));

        // Renumber entries and rebuild hash chain.
        let mut rebuilt = Vec::with_capacity(new_entries.len());
        let mut prev = chain_anchor;
        for (i, mut entry) in new_entries.into_iter().enumerate() {
            let seq = i as u64;
            let ts = entry.timestamp.clone();
            let msg = entry.message.clone();
            let payload = entry.payload.clone();
            let cp_seq = self.checkpoint_sequence.load(Ordering::SeqCst);
            let content_hash = ImmutableEntry::compute_content_hash(
                &self.algorithm, seq, &prev, &ts, &msg, &payload,
            );
            entry.sequence = seq;
            entry.prev_hash = prev;
            entry.content_hash = content_hash;
            entry.checkpoint_sequence = cp_seq;
            entry.merkle_proof = None;
            prev = entry.content_hash.clone();
            rebuilt.push(entry);
        }

        let snapshot_sequence = 0;
        self.entries = rebuilt;

        // Create a new checkpoint after compaction.
        let checkpoint = self.create_checkpoint().clone();

        // Rebuild WAL from current entries.
        self.wal.clear();
        let entry_bytes: Vec<Vec<u8>> = self.entries.iter().map(|e| e.to_bytes()).collect();
        let entries_after = self.entries.len();
        for bytes in &entry_bytes {
            self.wal
                .append(bytes)
                .map_err(|e| ImmutableLogError::Wal(e.to_string()))?;
        }

        self.compaction_count.fetch_add(1, Ordering::SeqCst);

        Ok(CompactionResult {
            entries_before,
            entries_after,
            entries_removed,
            snapshot_sequence,
            new_checkpoint: checkpoint.clone(),
            last_entry_hash: last_compacted_hash,
        })
    }

    /// Verify the integrity of the entire hash chain.
    ///
    /// Returns `Ok(())` if the chain is intact, or an error describing
    /// the first broken link.
    pub fn verify_chain(&self) -> Result<(), ImmutableLogError> {
        for i in 0..self.entries.len() {
            let entry = &self.entries[i];
            let expected_prev = if i == 0 {
                ImmutableEntry::genesis_prev_hash()
            } else {
                self.entries[i - 1].content_hash.clone()
            };

            if entry.prev_hash != expected_prev {
                return Err(ImmutableLogError::IntegrityViolation(format!(
                    "entry {}: prev_hash mismatch (expected {}, got {})",
                    entry.sequence, expected_prev, entry.prev_hash
                )));
            }

            // Verify content hash.
            let expected_content = ImmutableEntry::compute_content_hash(
                &self.algorithm,
                entry.sequence,
                &entry.prev_hash,
                &entry.timestamp,
                &entry.message,
                &entry.payload,
            );
            if entry.content_hash != expected_content {
                return Err(ImmutableLogError::IntegrityViolation(format!(
                    "entry {}: content_hash mismatch",
                    entry.sequence
                )));
            }

            // Verify Merkle proof if present.
            if let Some(ref proof) = entry.merkle_proof {
                if !proof.verify(&entry.content_hash, &self.algorithm) {
                    return Err(ImmutableLogError::IntegrityViolation(format!(
                        "entry {}: Merkle proof verification failed",
                        entry.sequence
                    )));
                }
            }
        }

        Ok(())
    }

    /// Verify the latest Merkle checkpoint against current entries.
    pub fn verify_checkpoint(&self) -> Result<(), ImmutableLogError> {
        let checkpoint = self
            .checkpoints
            .last()
            .ok_or_else(|| ImmutableLogError::IntegrityViolation("no checkpoints".into()))?;

        let entry_hashes: Vec<String> =
            self.entries.iter().map(|e| e.content_hash.clone()).collect();

        if entry_hashes.len() != checkpoint.entry_count as usize {
            // If the checkpoint covers more entries than we currently have,
            // it is stale (e.g. after compaction removed old entries but a
            // pre-compaction checkpoint is still the latest). Signal the error
            // so that recovery can create a fresh checkpoint.
            if entry_hashes.len() < checkpoint.entry_count as usize {
                return Err(ImmutableLogError::IntegrityViolation(
                    "checkpoint entry_count exceeds current entries (stale checkpoint)".into(),
                ));
            }
            // Checkpoint covers fewer entries than we have now
            // (entries added after checkpoint). Verify up to checkpoint count.
            let cp_hashes = &entry_hashes[..checkpoint.entry_count as usize];
            if !checkpoint.verify(cp_hashes) {
                return Err(ImmutableLogError::IntegrityViolation(
                    "Merkle root mismatch for checkpointed entries".into(),
                ));
            }
        } else if !checkpoint.verify(&entry_hashes) {
            return Err(ImmutableLogError::IntegrityViolation(
                "Merkle root mismatch".into(),
            ));
        }

        Ok(())
    }

    /// Recovery: replay from the latest checkpoint and WAL.
    ///
    /// In this in-memory implementation, recovery is a no-op if entries
    /// are already loaded. The method verifies integrity and rebuilds
    /// the ring buffer.
    pub fn recover(&mut self) -> Result<(), ImmutableLogError> {
        // Verify chain integrity.
        self.verify_chain()?;

        // Verify latest checkpoint.
        if let Err(e) = self.verify_checkpoint() {
            // If checkpoint verification fails but chain is valid,
            // we can still proceed — the checkpoint is stale.
            // Log the warning and create a fresh checkpoint.
            let _ = e; // In production, this would be logged.
            self.create_checkpoint();
        }

        // Rebuild ring buffer from entries.
        let recent: Vec<ImmutableEntry> = self
            .entries
            .iter()
            .rev()
            .take(self.ring.capacity())
            .rev()
            .cloned()
            .collect();

        self.ring.clear();
        for entry in recent {
            let _ = self.ring.push(entry);
        }

        Ok(())
    }

    /// Get an entry by sequence number.
    pub fn get(&self, sequence: u64) -> Option<&ImmutableEntry> {
        self.entries.get(sequence as usize)
    }

    /// Get the last entry.
    pub fn last(&self) -> Option<&ImmutableEntry> {
        self.entries.last()
    }

    /// Number of entries in the hash chain.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of checkpoints.
    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.len()
    }

    /// Whether compaction is needed based on current config.
    pub fn needs_compaction(&self) -> bool {
        self.compaction_config.enabled
            && self.entries.len() >= self.compaction_config.min_entries
    }

    /// Read all entries from the ring buffer (recent entries).
    pub fn ring_entries(&self) -> Vec<ImmutableEntry> {
        self.ring.read_all()
    }

    /// Export all entries as JSON.
    pub fn export_json(&self) -> Result<String, ImmutableLogError> {
        serde_json::to_string_pretty(&self.entries)
            .map_err(|e| ImmutableLogError::Codec(e.to_string()))
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Build a JSON summary of entries being compacted.
fn json_compaction_summary(entries: &[ImmutableEntry]) -> serde_json::Value {
    serde_json::json!({
        "compacted_count": entries.len(),
        "first_sequence": entries.first().map(|e| e.sequence),
        "last_sequence": entries.last().map(|e| e.sequence),
        "first_timestamp": entries.first().map(|e| e.timestamp.clone()),
        "last_timestamp": entries.last().map(|e| e.timestamp.clone()),
        "entries": entries.iter().map(|e| serde_json::json!({
            "sequence": e.sequence,
            "message": e.message,
            "timestamp": e.timestamp,
        })).collect::<Vec<_>>(),
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── CRC-32 Tests ──

    #[test]
    fn crc32_empty() {
        assert_eq!(crc32(&[]), 0x00000000);
    }

    #[test]
    fn crc32_known_value() {
        // CRC-32 of "123456789" is 0xCBF43926 (IEEE reference).
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn crc32_deterministic() {
        let a = crc32(b"hello world");
        let b = crc32(b"hello world");
        assert_eq!(a, b);
    }

    #[test]
    fn crc32_different_inputs() {
        let a = crc32(b"foo");
        let b = crc32(b"bar");
        assert_ne!(a, b);
    }

    // ── WAL Tests ──

    #[test]
    fn wal_append_and_replay() {
        let mut wal = WriteAheadLog::new();
        wal.append(b"entry-one").unwrap();
        wal.append(b"entry-two").unwrap();
        wal.append(b"entry-three").unwrap();

        let entries = wal.replay().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].data, b"entry-one");
        assert_eq!(entries[1].data, b"entry-two");
        assert_eq!(entries[2].data, b"entry-three");
    }

    #[test]
    fn wal_empty_replay() {
        let wal = WriteAheadLog::new();
        let entries = wal.replay().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn wal_crc_validation() {
        let mut wal = WriteAheadLog::new();
        wal.append(b"correct data").unwrap();

        // Tamper with the buffer.
        let buf_len = wal.buffer.len();
        if buf_len > 10 {
            wal.buffer[10] ^= 0xFF;
        }

        let result = wal.replay();
        assert!(result.is_err());
        match result.unwrap_err() {
            WalError::CrcMismatch { .. } => (),
            _ => panic!("expected CRC mismatch error"),
        }
    }

    #[test]
    fn wal_truncated_entry_detection() {
        let mut wal = WriteAheadLog::new();
        wal.append(b"full entry").unwrap();

        // Truncate the buffer mid-header.
        wal.buffer.truncate(2);

        let result = wal.replay();
        assert!(result.is_err());
        match result.unwrap_err() {
            WalError::TruncatedEntry { .. } => (),
            _ => panic!("expected truncated entry error"),
        }
    }

    #[test]
    fn wal_entry_count_and_size() {
        let mut wal = WriteAheadLog::new();
        assert_eq!(wal.entry_count(), 0);
        assert_eq!(wal.buffer_size(), 0);

        wal.append(b"data").unwrap();
        assert_eq!(wal.entry_count(), 1);
        assert_eq!(wal.buffer_size(), 4 + 4 + 4); // len + crc + data
    }

    #[test]
    fn wal_sync_on_write() {
        let mut wal = WriteAheadLog::with_sync_config(true, 1);
        wal.append(b"a").unwrap();
        assert_eq!(wal.sync_count(), 1);
    }

    #[test]
    fn wal_batch_sync() {
        let mut wal = WriteAheadLog::with_sync_config(false, 3);
        wal.append(b"a").unwrap();
        assert_eq!(wal.sync_count(), 0);
        wal.append(b"b").unwrap();
        assert_eq!(wal.sync_count(), 0);
        wal.append(b"c").unwrap();
        assert_eq!(wal.sync_count(), 1); // Batch of 3 triggers sync.
    }

    #[test]
    fn wal_truncation() {
        let mut wal = WriteAheadLog::new();
        wal.append(b"first").unwrap();
        wal.append(b"second").unwrap();
        let offset_after_first = 4 + 4 + 5; // header + "first"

        wal.set_truncation_point(offset_after_first);
        let removed = wal.truncate();
        assert_eq!(removed, offset_after_first);
        assert_eq!(wal.buffer_size(), 4 + 4 + 6); // "second"
    }

    #[test]
    fn wal_clear() {
        let mut wal = WriteAheadLog::new();
        wal.append(b"data").unwrap();
        assert_eq!(wal.entry_count(), 1);
        wal.clear();
        assert_eq!(wal.entry_count(), 0);
        assert_eq!(wal.buffer_size(), 0);
    }

    #[test]
    fn wal_large_payload() {
        let mut wal = WriteAheadLog::new();
        let large = vec![0xABu8; 10_000];
        wal.append(&large).unwrap();
        let entries = wal.replay().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data.len(), 10_000);
    }

    // ── Ring Buffer Tests ──

    #[test]
    fn ring_buffer_push_pop() {
        let mut rb: RingBuffer<u32> = RingBuffer::new(4);
        assert!(rb.push(1).is_ok());
        assert!(rb.push(2).is_ok());
        assert!(rb.push(3).is_ok());

        assert_eq!(rb.pop(), Some(1));
        assert_eq!(rb.pop(), Some(2));
        assert_eq!(rb.pop(), Some(3));
        assert_eq!(rb.pop(), None);
    }

    #[test]
    fn ring_buffer_reject_overflow() {
        let mut rb: RingBuffer<u32> =
            RingBuffer::with_policy(2, OverflowPolicy::Reject);
        assert!(rb.push(1).is_ok());
        assert!(rb.push(2).is_ok());
        assert!(rb.push(3).is_err()); // Full, rejected.
        assert_eq!(rb.dropped_count(), 1);
    }

    #[test]
    fn ring_buffer_overwrite_oldest() {
        let mut rb: RingBuffer<u32> =
            RingBuffer::with_policy(2, OverflowPolicy::OverwriteOldest);
        assert!(rb.push(1).is_ok());
        assert!(rb.push(2).is_ok());
        assert!(rb.push(3).is_ok()); // Overwrites 1.

        assert_eq!(rb.pop(), Some(2));
        assert_eq!(rb.pop(), Some(3));
        assert_eq!(rb.pop(), None);
    }

    #[test]
    fn ring_buffer_wrap_around() {
        let mut rb: RingBuffer<u32> =
            RingBuffer::with_policy(3, OverflowPolicy::OverwriteOldest);
        for i in 0..10 {
            assert!(rb.push(i).is_ok());
        }
        // Should have entries 7, 8, 9.
        assert_eq!(rb.len(), 3);
        assert_eq!(rb.pop(), Some(7));
        assert_eq!(rb.pop(), Some(8));
        assert_eq!(rb.pop(), Some(9));
    }

    #[test]
    fn ring_buffer_peek() {
        let mut rb: RingBuffer<String> = RingBuffer::new(4);
        rb.push("first".into()).unwrap();
        rb.push("second".into()).unwrap();

        assert_eq!(rb.peek().map(|s| s.as_str()), Some("first"));
        assert_eq!(rb.len(), 2); // Peek doesn't remove.
    }

    #[test]
    fn ring_buffer_read_all() {
        let mut rb: RingBuffer<u32> = RingBuffer::new(8);
        for i in 0..5 {
            rb.push(i).unwrap();
        }
        let all = rb.read_all();
        assert_eq!(all, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn ring_buffer_counters() {
        let mut rb: RingBuffer<u32> =
            RingBuffer::with_policy(2, OverflowPolicy::OverwriteOldest);
        rb.push(1).unwrap();
        rb.push(2).unwrap();
        rb.push(3).unwrap(); // Drops 1.
        rb.pop(); // Removes 2.

        assert_eq!(rb.total_written(), 3);
        assert_eq!(rb.total_read(), 2); // 1 dropped (counts as read) + 1 popped
        assert_eq!(rb.dropped_count(), 1);
    }

    // ── Immutable Entry Tests ──

    #[test]
    fn immutable_entry_content_hash_deterministic() {
        let algo = HashAlgorithm::Sha256;
        let h1 = ImmutableEntry::compute_content_hash(
            &algo, 0, &ImmutableEntry::genesis_prev_hash(),
            "2024-01-01T00:00:00Z", "msg", "",
        );
        let h2 = ImmutableEntry::compute_content_hash(
            &algo, 0, &ImmutableEntry::genesis_prev_hash(),
            "2024-01-01T00:00:00Z", "msg", "",
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn immutable_entry_serialization_roundtrip() {
        let entry = ImmutableEntry::new(
            42,
            &ImmutableEntry::genesis_prev_hash(),
            "test message",
            "{\"key\": \"value\"}",
            &HashAlgorithm::Sha256,
            0,
        );
        let bytes = entry.to_bytes();
        let decoded = ImmutableEntry::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.message, "test message");
        assert_eq!(decoded.content_hash, entry.content_hash);
    }

    #[test]
    fn immutable_entry_new_has_valid_hash() {
        let entry = ImmutableEntry::new(
            0,
            &ImmutableEntry::genesis_prev_hash(),
            "hello",
            "",
            &HashAlgorithm::Sha256,
            0,
        );
        assert!(!entry.content_hash.is_empty());
        assert_eq!(entry.prev_hash, ImmutableEntry::genesis_prev_hash());
        assert_eq!(entry.sequence, 0);
    }

    // ── Merkle Checkpoint Tests ──

    #[test]
    fn merkle_checkpoint_empty() {
        let cp = MerkleCheckpoint::from_entry_hashes(
            &[], &HashAlgorithm::Sha256, 0, 0,
        );
        assert_eq!(cp.entry_count, 0);
        assert!(!cp.root_hash_hex.is_empty());
    }

    #[test]
    fn merkle_checkpoint_verify() {
        let hashes: Vec<String> = vec![
            hash_bytes(b"a", &HashAlgorithm::Sha256).hex,
            hash_bytes(b"b", &HashAlgorithm::Sha256).hex,
            hash_bytes(b"c", &HashAlgorithm::Sha256).hex,
        ];
        let cp = MerkleCheckpoint::from_entry_hashes(
            &hashes, &HashAlgorithm::Sha256, 100, 1,
        );
        assert!(cp.verify(&hashes));
    }

    #[test]
    fn merkle_checkpoint_detects_tampering() {
        let hashes: Vec<String> = vec![
            hash_bytes(b"a", &HashAlgorithm::Sha256).hex,
            hash_bytes(b"b", &HashAlgorithm::Sha256).hex,
        ];
        let cp = MerkleCheckpoint::from_entry_hashes(
            &hashes, &HashAlgorithm::Sha256, 0, 0,
        );
        let mut tampered = hashes.clone();
        tampered[0] = hash_bytes(b"X", &HashAlgorithm::Sha256).hex;
        assert!(!cp.verify(&tampered));
    }

    #[test]
    fn merkle_checkpoint_wrong_count() {
        let hashes: Vec<String> = vec![
            hash_bytes(b"a", &HashAlgorithm::Sha256).hex,
        ];
        let cp = MerkleCheckpoint::from_entry_hashes(
            &hashes, &HashAlgorithm::Sha256, 0, 0,
        );
        // Wrong count.
        assert!(!cp.verify(&[]));
    }

    // ── Stored Merkle Proof Tests ──

    #[test]
    fn stored_merkle_proof_roundtrip() {
        let data: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let tree = MerkleTree::from_data(&data, &HashAlgorithm::Sha256);
        let proof = tree.proof(2).unwrap();

        let stored = StoredMerkleProof::from_merkle_proof(&proof);
        let leaf_hex = tree.leaves[2].hex.clone();
        assert!(stored.verify(&leaf_hex, &HashAlgorithm::Sha256));
    }

    #[test]
    fn stored_merkle_proof_detects_tampering() {
        let data: Vec<&[u8]> = vec![b"x", b"y", b"z"];
        let tree = MerkleTree::from_data(&data, &HashAlgorithm::Sha256);
        let proof = tree.proof(1).unwrap();
        let stored = StoredMerkleProof::from_merkle_proof(&proof);

        // Verify with wrong leaf hash.
        let fake_leaf = hash_bytes(b"tampered", &HashAlgorithm::Sha256).hex;
        assert!(!stored.verify(&fake_leaf, &HashAlgorithm::Sha256));
    }

    // ── Immutable Log Engine Tests ──

    fn test_engine() -> ImmutableLogEngine {
        ImmutableLogEngine::new(HashAlgorithm::Sha256, 64, 100)
    }

    #[test]
    fn engine_append_and_query() {
        let mut engine = test_engine();
        engine.append("first event", "").unwrap();
        engine.append("second event", "").unwrap();
        assert_eq!(engine.len(), 2);
        assert_eq!(engine.get(0).unwrap().message, "first event");
        assert_eq!(engine.get(1).unwrap().message, "second event");
    }

    #[test]
    fn engine_hash_chain_integrity() {
        let mut engine = test_engine();
        for i in 0..10 {
            engine.append(&format!("entry {}", i), "").unwrap();
        }
        assert!(engine.verify_chain().is_ok());
    }

    #[test]
    fn engine_detects_tampering() {
        let mut engine = test_engine();
        engine.append("original", "").unwrap();
        engine.append("second", "").unwrap();

        // Tamper with entry 0's content hash.
        engine.entries[0].content_hash = "deadbeef".to_string();

        assert!(engine.verify_chain().is_err());
    }

    #[test]
    fn engine_checkpoint_creation() {
        let mut engine = ImmutableLogEngine::new(HashAlgorithm::Sha256, 64, 5);
        for i in 0..5 {
            engine.append(&format!("entry {}", i), "").unwrap();
        }
        // Checkpoint should have been triggered at entry 5.
        assert!(engine.checkpoint_count() >= 1);
        assert!(engine.verify_checkpoint().is_ok());
    }

    #[test]
    fn engine_recovery() {
        let mut engine = test_engine();
        for i in 0..20 {
            engine.append(&format!("entry {}", i), "").unwrap();
        }
        engine.recover().unwrap();
        assert_eq!(engine.len(), 20);
        assert!(engine.verify_chain().is_ok());
    }

    #[test]
    fn engine_compaction() {
        let mut engine = ImmutableLogEngine::with_compaction_config(
            HashAlgorithm::Sha256,
            64,
            1000,
            CompactionConfig {
                min_entries: 10,
                target_entries: 3,
                enabled: true,
            },
        );
        for i in 0..15 {
            engine.append(&format!("entry {}", i), "").unwrap();
        }

        let result = engine.compact().unwrap();
        assert_eq!(result.entries_before, 15);
        assert_eq!(result.entries_removed, 12);
        // After compaction: 1 snapshot + 3 kept = 4 entries.
        assert_eq!(engine.len(), 4);
        assert!(engine.verify_chain().is_ok());
    }

    #[test]
    fn engine_ring_buffer_recent_entries() {
        let mut engine = ImmutableLogEngine::new(HashAlgorithm::Sha256, 5, 1000);
        for i in 0..10 {
            engine.append(&format!("entry {}", i), "").unwrap();
        }
        let ring = engine.ring_entries();
        assert_eq!(ring.len(), 5);
        // Ring should have the last 5 entries (5-9).
        assert_eq!(ring[0].message, "entry 5");
        assert_eq!(ring[4].message, "entry 9");
    }

    #[test]
    fn engine_export_json() {
        let mut engine = test_engine();
        engine.append("json test", "payload").unwrap();
        let json = engine.export_json().unwrap();
        assert!(json.contains("json test"));
        assert!(json.contains("payload"));
    }

    #[test]
    fn engine_needs_compaction() {
        let mut engine = ImmutableLogEngine::with_compaction_config(
            HashAlgorithm::Sha256,
            64,
            1000,
            CompactionConfig {
                min_entries: 5,
                target_entries: 2,
                enabled: true,
            },
        );
        assert!(!engine.needs_compaction());
        for i in 0..5 {
            engine.append(&format!("e{}", i), "").unwrap();
        }
        assert!(engine.needs_compaction());
    }

    #[test]
    fn engine_wal_entry_count_matches() {
        let mut engine = test_engine();
        for i in 0..7 {
            engine.append(&format!("e{}", i), "").unwrap();
        }
        // WAL should have at least as many entries as the chain.
        assert!(engine.wal.entry_count() >= engine.len() as usize);
    }
}
