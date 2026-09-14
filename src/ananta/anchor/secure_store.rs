// Secure Store — encrypted on-disk storage for ANANTA secrets.
//
// Stores:
//   - Signing keys
//   - Recovery keys
//   - Sensitive attestation data
//   - Recovery state snapshots
//
// DESIGN: Uses ANANTA's own encryption (AES-256-GCM),
// NOT Keshav's storage. This is a first-class constraint.

use crate::ananta::crypto::encryption::{self, EncryptedPayload};
use std::collections::HashMap;
use std::path::PathBuf;

/// A secure key-value store backed by encrypted files.
pub struct SecureStore {
    password: String,
    base_path: PathBuf,
    /// In-memory cache of decrypted values.
    cache: HashMap<String, Vec<u8>>,
}

impl SecureStore {
    /// Create a new SecureStore. Creates the base directory if needed.
    pub fn new(password: &str, base_path: &str) -> Result<Self, String> {
        let path = PathBuf::from(base_path);
        if !path.exists() {
            std::fs::create_dir_all(&path).map_err(|e| format!("secure_store mkdir: {}", e))?;
        }
        Ok(Self {
            password: password.into(),
            base_path: path,
            cache: HashMap::new(),
        })
    }

    /// Store a value (encrypted on disk).
    pub fn put(&mut self, key: &str, value: &[u8]) -> Result<(), String> {
        let encrypted = encryption::encrypt(&self.password, value)
            .map_err(|e| format!("secure_store encrypt: {}", e))?;
        let json = serde_json::to_string(&encrypted)
            .map_err(|e| format!("secure_store serialize: {}", e))?;
        // Ensure base_path exists (handles TOCTOU: directory may have been
        // removed between new() and this put() call, e.g. by recovery/rotation).
        std::fs::create_dir_all(&self.base_path)
            .map_err(|e| format!("secure_store ensure_dir: {}", e))?;
        let file_path = self.file_path(key);
        std::fs::write(&file_path, json).map_err(|e| format!("secure_store write: {}", e))?;
        self.cache.insert(key.into(), value.to_vec());
        Ok(())
    }

    /// Store a string value.
    pub fn put_string(&mut self, key: &str, value: &str) -> Result<(), String> {
        self.put(key, value.as_bytes())
    }

    /// Retrieve a value (decrypted from disk or cache).
    pub fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>, String> {
        if let Some(cached) = self.cache.get(key) {
            return Ok(Some(cached.clone()));
        }
        let file_path = self.file_path(key);
        if !file_path.exists() {
            return Ok(None);
        }
        let json =
            std::fs::read_to_string(&file_path).map_err(|e| format!("secure_store read: {}", e))?;
        let encrypted: EncryptedPayload =
            serde_json::from_str(&json).map_err(|e| format!("secure_store deserialize: {}", e))?;
        let value = encryption::decrypt(&self.password, &encrypted)
            .map_err(|e| format!("secure_store decrypt: {}", e))?;
        self.cache.insert(key.into(), value.clone());
        Ok(Some(value))
    }

    /// Retrieve a string value.
    pub fn get_string(&mut self, key: &str) -> Result<Option<String>, String> {
        match self.get(key)? {
            Some(bytes) => Ok(Some(
                String::from_utf8(bytes).map_err(|e| format!("secure_store utf8: {}", e))?,
            )),
            None => Ok(None),
        }
    }

    /// Delete a value.
    pub fn delete(&mut self, key: &str) -> Result<(), String> {
        let file_path = self.file_path(key);
        if file_path.exists() {
            std::fs::remove_file(&file_path).map_err(|e| format!("secure_store delete: {}", e))?;
        }
        self.cache.remove(key);
        Ok(())
    }

    /// List all stored keys.
    pub fn list_keys(&self) -> Vec<String> {
        let mut keys = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.base_path) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".enc") {
                        keys.push(name.trim_end_matches(".enc").to_string());
                    }
                }
            }
        }
        keys.sort();
        keys
    }

    fn file_path(&self, key: &str) -> PathBuf {
        // Defense-in-depth path traversal prevention:
        // 1. Reject null bytes, path separators, and traversal sequences entirely
        // 2. Extract only the last safe filename component
        // 3. Strip any remaining non-alphanumeric chars (except _ and -)
        // 4. Verify the resolved path stays within base_path (canonicalize check)
        let is_dangerous =
            key.contains('\0') || key.contains('/') || key.contains('\\') || key.contains("..");

        let safe_key = if is_dangerous {
            // Take only the last path component, filtering out traversal segments
            let safe = key
                .split(|c: char| c == '/' || c == '\\')
                .filter(|s| !s.is_empty() && *s != ".." && *s != ".")
                .last()
                .unwrap_or("invalid");
            // Strip any remaining unsafe characters
            safe.replace(|c: char| !c.is_alphanumeric() && c != '_' && c != '-', "_")
        } else {
            key.to_string()
        };

        let candidate = self.base_path.join(format!("{}.enc", safe_key));

        // Final safety net: canonicalize check ensures path stays within base_path
        if let Ok(resolved) = candidate.canonicalize() {
            if let Ok(base_resolved) = self.base_path.canonicalize() {
                if !resolved.starts_with(&base_resolved) {
                    // Path escapes base_path — use fully sanitized fallback
                    let clean =
                        key.replace(|c: char| !c.is_alphanumeric() && c != '_' && c != '-', "_");
                    return self.base_path.join(format!("{}.enc", clean));
                }
            }
        }
        candidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_store() -> (SecureStore, String) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ananta_test_{}_{}", std::process::id(), id));
        let dir_str = dir.to_string_lossy().to_string();
        let _ = fs::remove_dir_all(&dir);
        let store = SecureStore::new("test-password", &dir_str).unwrap();
        (store, dir_str)
    }

    #[test]
    fn put_get_roundtrip() {
        let (mut store, dir) = temp_store();
        store.put_string("secret", "trust proof data").unwrap();
        let val = store.get_string("secret").unwrap();
        assert_eq!(val, Some("trust proof data".to_string()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_key_returns_none() {
        let (mut store, dir) = temp_store();
        let val = store.get_string("nonexistent").unwrap();
        assert!(val.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_removes_key() {
        let (mut store, dir) = temp_store();
        store.put_string("temp", "data").unwrap();
        store.delete("temp").unwrap();
        assert!(store.get_string("temp").unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_keys() {
        let (mut store, dir) = temp_store();
        store.put_string("a", "1").unwrap();
        store.put_string("b", "2").unwrap();
        let keys = store.list_keys();
        assert_eq!(keys, vec!["a", "b"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_password_fails() {
        let (mut store, dir) = temp_store();
        store.put_string("secret", "data").unwrap();
        // Create a new store with wrong password.
        let mut bad_store = SecureStore::new("wrong-password", &dir).unwrap();
        let result = bad_store.get_string("secret");
        assert!(result.is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_traversal_prevented() {
        let (mut store, dir) = temp_store();
        store
            .put_string("../../etc/passwd", "hack attempt")
            .unwrap();
        let keys = store.list_keys();
        // The key should be sanitized.
        assert!(!keys.iter().any(|k| k.contains("..")));
        let _ = fs::remove_dir_all(&dir);
    }
}
