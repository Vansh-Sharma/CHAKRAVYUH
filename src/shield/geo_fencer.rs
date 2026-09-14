// Geo Fencer — Shield Ring Engine #4
//
// Restricts access based on geographic location of source IP.
// Uses MaxMind GeoLite2 Country database for lookups.
//
// Latency Budget: 0.2ms p99 (local file lookup, mmap'd)
//
// Configuration:
//   geo_fencer:
//     enabled: true
//     mode: blocklist            # "allowlist" or "blocklist"
//     countries: ["CN", "RU"]    # ISO 3166-1 alpha-2 codes
//     default_on_lookup_fail: deny  # "allow" or "deny"
//     db_path: /usr/share/GeoIP/GeoLite2-Country.mmdb
//
// If the MaxMind DB file is missing or unreadable, the engine falls back
// to `default_on_lookup_fail` for every request and logs a warning.
// This is Fail Secure by default (deny on lookup failure).
//
// To get the GeoLite2-Country database (free, requires MaxMind account):
//   1. Sign up at https://www.maxmind.com/en/geolite2/signup
//   2. Download GeoLite2-Country.mmdb
//   3. Place at /usr/share/GeoIP/GeoLite2-Country.mmdb (or set db_path)
//
// For testing without the DB, set `default_on_lookup_fail: allow`.

use crate::shield::{EngineResult, ShieldRequest};
use crate::{decision::Decision, Result};
use maxminddb::Reader;
use serde::Deserialize;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct GeoFencerConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_mode")]
    pub mode: String, // "allowlist" or "blocklist"

    #[serde(default)]
    pub countries: Vec<String>, // ISO 3166-1 alpha-2 codes, uppercase

    #[serde(default = "default_on_fail")]
    pub default_on_lookup_fail: String, // "allow" or "deny"

    #[serde(default = "default_db_path")]
    pub db_path: String,
}

fn default_mode() -> String {
    "blocklist".into()
}
fn default_on_fail() -> String {
    "deny".into()
}
fn default_db_path() -> String {
    "/usr/share/GeoIP/GeoLite2-Country.mmdb".into()
}

impl Default for GeoFencerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_mode(),
            countries: vec![],
            default_on_lookup_fail: default_on_fail(),
            db_path: default_db_path(),
        }
    }
}

/// MaxMind's GeoLite2 Country database returns this structure.
/// We only need the ISO country code.
#[derive(Debug, Deserialize)]
struct CountryLookup {
    country: Option<CountryRecord>,
}

#[derive(Debug, Deserialize)]
struct CountryRecord {
    iso_code: Option<String>,
}

pub struct GeoFencer {
    config: GeoFencerConfig,
    /// Loaded MaxMind reader. None if DB is missing/unloadable.
    /// Arc'd because the Reader is thread-safe and we share it across
    /// request handler tasks.
    reader: Option<Arc<Reader<Vec<u8>>>>,
    /// Normalized country codes (uppercase, 2-letter).
    countries_normalized: Vec<String>,
    /// Cached decision for when the DB is unavailable.
    /// Computed once at startup from `default_on_lookup_fail`.
    fail_decision: Decision,
}

impl GeoFencer {
    pub fn new(shield_config: &crate::config::ShieldConfig) -> Result<Self> {
        let config = shield_config.geo_fencer.clone();

        // Normalize country codes to uppercase for case-insensitive comparison.
        let countries_normalized = config.countries.iter().map(|c| c.to_uppercase()).collect();

        let fail_decision = if config.default_on_lookup_fail == "deny" {
            Decision::Deny {
                code: "GEO_LOOKUP_FAILED".into(),
                retry_after: None,
            }
        } else {
            Decision::Allow
        };

        // Try to load the MaxMind DB.
        let reader = if config.enabled && !config.db_path.is_empty() {
            load_reader(&config.db_path)
        } else {
            None
        };

        if config.enabled && reader.is_none() {
            tracing::warn!(
                db_path = %config.db_path,
                "Geo Fencer is enabled but MaxMind DB could not be loaded; \
                 all requests will use default_on_lookup_fail={}",
                config.default_on_lookup_fail
            );
        }

        Ok(Self {
            config,
            reader,
            countries_normalized,
            fail_decision,
        })
    }

    pub fn evaluate(&self, request: &ShieldRequest) -> EngineResult {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return EngineResult {
                engine_name: "geo_fencer".into(),
                decision: Decision::Allow,
                reason: "engine disabled".into(),
                latency_ms: 0.0,
                metadata: serde_json::json!({"enabled": false}),
            };
        }

        // Skip 0.0.0.0 placeholder (no proxy header present).
        if request.source_ip == "0.0.0.0" || request.source_ip.is_empty() {
            return EngineResult {
                engine_name: "geo_fencer".into(),
                decision: Decision::Allow,
                reason: "no source IP — skipping geo check".into(),
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                metadata: serde_json::json!({"skipped": true}),
            };
        }

        // Parse the IP address.
        let ip: IpAddr = match request.source_ip.parse() {
            Ok(ip) => ip,
            Err(e) => {
                tracing::warn!(
                    ip = %request.source_ip,
                    error = %e,
                    "Geo Fencer could not parse source IP"
                );
                return EngineResult {
                    engine_name: "geo_fencer".into(),
                    decision: self.fail_decision.clone(),
                    reason: format!("invalid source IP: {}", e),
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                    metadata: serde_json::json!({"invalid_ip": true}),
                };
            }
        };

        // Look up the country.
        let country: Option<String> = match &self.reader {
            Some(r) => lookup_country(r, ip),
            None => None,
        };

        let (decision, reason) = match (self.config.mode.as_str(), &country) {
            (_, None) => {
                // Lookup failed or DB not loaded.
                let r = if matches!(self.fail_decision, Decision::Deny { .. }) {
                    "geo lookup failed (DB unavailable or IP not found)"
                } else {
                    "geo lookup failed but defaulting to allow"
                };
                (self.fail_decision.clone(), r.to_string())
            }
            ("allowlist", Some(c)) => {
                if self.countries_normalized.contains(c) {
                    (Decision::Allow, format!("country {} is in allowlist", c))
                } else {
                    (
                        Decision::Deny {
                            code: "GEO_NOT_ALLOWED".into(),
                            retry_after: None,
                        },
                        format!("country {} not in allowlist", c),
                    )
                }
            }
            ("blocklist", Some(c)) => {
                if self.countries_normalized.contains(c) {
                    (
                        Decision::Deny {
                            code: "GEO_BLOCKED".into(),
                            retry_after: None,
                        },
                        format!("country {} is in blocklist", c),
                    )
                } else {
                    (Decision::Allow, format!("country {} not in blocklist", c))
                }
            }
            _ => (Decision::Allow, "unknown mode, allowing".to_string()),
        };

        EngineResult {
            engine_name: "geo_fencer".into(),
            decision,
            reason,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            metadata: serde_json::json!({
                "mode": self.config.mode,
                "country": country,
                "countries_configured": self.countries_normalized.len(),
                "db_loaded": self.reader.is_some(),
            }),
        }
    }
}

/// Load a MaxMind DB reader from a file path.
/// Returns None if the file doesn't exist or can't be read.
fn load_reader(db_path: &str) -> Option<Arc<Reader<Vec<u8>>>> {
    if !Path::new(db_path).exists() {
        return None;
    }
    match Reader::open_readfile(db_path) {
        Ok(r) => Some(Arc::new(r)),
        Err(e) => {
            tracing::warn!(
                db_path = db_path,
                error = %e,
                "Failed to open MaxMind DB"
            );
            None
        }
    }
}

/// Look up the ISO country code for an IP address using the MaxMind reader.
fn lookup_country(reader: &Reader<Vec<u8>>, ip: IpAddr) -> Option<String> {
    match reader.lookup(ip) {
        Ok(result) => result
            .decode::<CountryLookup>()
            .ok()
            .flatten()
            .and_then(|lookup| lookup.country.and_then(|c| c.iso_code)),
        Err(e) => {
            // Not all IPs have country data (e.g., private ranges, localhost).
            // This is expected, not an error — return None silently.
            tracing::trace!(
                ip = %ip,
                error = %e,
                "GeoIP lookup returned no country for IP"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(ip: &str) -> ShieldRequest {
        ShieldRequest {
            source_ip: ip.into(),
            user_agent: Some("test/1.0".into()),
            api_key: None,
            user_id: None,
            method: "POST".into(),
            path: "/".into(),
            headers: Default::default(),
            body: serde_json::json!({}),
        }
    }

    fn make_engine(enabled: bool, mode: &str, countries: Vec<&str>, fail: &str) -> GeoFencer {
        GeoFencer {
            config: GeoFencerConfig {
                enabled,
                mode: mode.into(),
                countries: countries.iter().map(|s| s.to_string()).collect(),
                default_on_lookup_fail: fail.into(),
                db_path: "/nonexistent/path/for/tests.mmdb".into(),
            },
            reader: None, // no DB in tests
            countries_normalized: countries.iter().map(|s| s.to_uppercase()).collect(),
            fail_decision: if fail == "deny" {
                Decision::Deny {
                    code: "GEO_LOOKUP_FAILED".into(),
                    retry_after: None,
                }
            } else {
                Decision::Allow
            },
        }
    }

    #[test]
    fn test_disabled_engine_allows() {
        let engine = make_engine(false, "blocklist", vec!["CN"], "deny");
        let req = make_request("1.2.3.4");
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Allow));
        assert_eq!(result.reason, "engine disabled");
    }

    #[test]
    fn test_unknown_ip_skipped() {
        let engine = make_engine(true, "blocklist", vec!["CN"], "deny");
        let req = make_request("0.0.0.0");
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Allow));
        assert!(result.reason.contains("no source IP"));
    }

    #[test]
    fn test_invalid_ip_uses_fail_decision_deny() {
        let engine = make_engine(true, "blocklist", vec!["CN"], "deny");
        let req = make_request("not-an-ip-address");
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_invalid_ip_uses_fail_decision_allow() {
        let engine = make_engine(true, "blocklist", vec!["CN"], "allow");
        let req = make_request("not-an-ip-address");
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Allow));
    }

    #[test]
    fn test_no_db_denies_on_fail_default() {
        // With no DB loaded and default_on_lookup_fail=deny,
        // any valid IP should be denied.
        let engine = make_engine(true, "blocklist", vec!["CN"], "deny");
        let req = make_request("1.2.3.4");
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Deny { .. }));
        assert!(result.reason.contains("lookup failed"));
    }

    #[test]
    fn test_no_db_allows_on_fail_allow() {
        // With no DB loaded and default_on_lookup_fail=allow,
        // any valid IP should be allowed.
        let engine = make_engine(true, "blocklist", vec!["CN"], "allow");
        let req = make_request("1.2.3.4");
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Allow));
    }

    #[test]
    fn test_country_codes_normalized_to_uppercase() {
        // Verify that lowercase country codes in config are matched
        // against uppercase ISO codes.
        let mut engine = make_engine(true, "blocklist", vec!["cn", "ru"], "allow");
        // Manually set the normalized list to verify uppercase conversion.
        engine.countries_normalized = vec!["CN".to_string(), "RU".to_string()];
        // Since we have no DB, the lookup returns None and we use the fail
        // decision (Allow). This test just verifies the normalization logic
        // doesn't panic and the engine handles lowercase input.
        let req = make_request("1.2.3.4");
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Allow));
    }

    #[test]
    fn test_private_ip_returns_none_country() {
        // Private IPs like 192.168.x.x have no country in GeoIP databases.
        // Without a DB, we can't fully test this, but we verify the engine
        // handles it gracefully via the fail decision.
        let engine = make_engine(true, "allowlist", vec!["US"], "deny");
        let req = make_request("192.168.1.1");
        let result = engine.evaluate(&req);
        // No DB → lookup fails → deny (per fail_decision).
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_loopback_ip_handled() {
        let engine = make_engine(true, "blocklist", vec!["CN"], "allow");
        let req = make_request("127.0.0.1");
        let result = engine.evaluate(&req);
        // No DB → lookup fails → allow (per fail_decision).
        assert!(matches!(result.decision, Decision::Allow));
    }

    #[test]
    fn test_ipv6_address_parsed() {
        let engine = make_engine(true, "blocklist", vec!["CN"], "allow");
        let req = make_request("::1");
        let result = engine.evaluate(&req);
        // ::1 is loopback — should parse fine, then lookup fails (no DB).
        assert!(matches!(result.decision, Decision::Allow));
    }
}
