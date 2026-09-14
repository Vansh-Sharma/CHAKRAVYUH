// SSRF Protector — Engine 6 of the Execution Ring
//
// Blocks tool calls that target internal/private network addresses.
// Protects against Server-Side Request Forgery (SSRF) attacks
// where an AI agent is tricked into accessing cloud metadata,
// internal services, or loopback interfaces.
//
// Blocked ranges:
//   10.0.0.0/8       — private (RFC 1918)
//   172.16.0.0/12    — private (RFC 1918)
//   192.168.0.0/16   — private (RFC 1918)
//   169.254.0.0/16   — link-local / cloud metadata (AWS/GCP/Azure)
//   127.0.0.0/8      — loopback
//   ::1              — IPv6 loopback
//   fc00::/7         — IPv6 unique local
//   fe80::/10        — IPv6 link-local
//   0.0.0.0          — unspecified
//   198.18.0.0/15    — benchmark testing (RFC 2544)
//
// Latency Budget: <1ms p99

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

/// Configuration for the SSRF Protector engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsrfProtectorConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Additional blocked CIDR ranges.
    #[serde(default)]
    pub extra_blocked_ranges: Vec<String>,
    /// Whether to allow private IPs when explicitly configured.
    #[serde(default)]
    pub allow_private_override: bool,
}

fn default_enabled() -> bool {
    true
}

impl Default for SsrfProtectorConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            extra_blocked_ranges: vec![],
            allow_private_override: false,
        }
    }
}

/// Result of an SSRF protection check.
#[derive(Debug, Clone, Serialize)]
pub struct SsrfProtectorResult {
    pub decision: crate::decision::Decision,
    pub reason: String,
    pub checked_target: String,
    pub matched_range: Option<String>,
    pub latency_ms: f64,
}

/// The SSRF Protector engine.
///
/// Checks whether a URL or IP target falls within blocked ranges.
#[derive(Clone)]
pub struct SsrfProtector {
    config: SsrfProtectorConfig,
    /// Pre-parsed blocked networks.
    blocked_networks: Vec<(ipnet::IpNet, String)>,
}

impl SsrfProtector {
    pub fn new(config: &SsrfProtectorConfig) -> crate::Result<Self> {
        let mut blocked_networks: Vec<(ipnet::IpNet, String)> = Vec::new();

        // RFC 1918 private ranges.
        let built_in = [
            ("10.0.0.0/8", "RFC1918-10"),
            ("172.16.0.0/12", "RFC1918-172"),
            ("192.168.0.0/16", "RFC1918-192"),
            ("169.254.0.0/16", "LINK-LOCAL-CLOUD-METADATA"),
            ("127.0.0.0/8", "LOOPBACK"),
            ("198.18.0.0/15", "RFC2544-BENCHMARK"),
            ("0.0.0.0/32", "UNSPECIFIED"),
            // IPv6 ranges.
            ("::1/128", "IPv6-LOOPBACK"),
            ("fc00::/7", "IPv6-UNIQUE-LOCAL"),
            ("fe80::/10", "IPv6-LINK-LOCAL"),
            ("::/128", "IPv6-UNSPECIFIED"),
        ];

        for (cidr, label) in &built_in {
            if let Ok(net) = cidr.parse::<ipnet::IpNet>() {
                blocked_networks.push((net, label.to_string()));
            }
        }

        // Extra ranges from config.
        for range in &config.extra_blocked_ranges {
            if let Ok(net) = range.parse::<ipnet::IpNet>() {
                blocked_networks.push((net, format!("EXTRA:{}", range)));
            }
        }

        Ok(Self {
            config: config.clone(),
            blocked_networks,
        })
    }

    /// Check if a URL target is safe (not in a blocked range).
    ///
    /// Accepts both raw IPs and hostnames. For hostnames, it checks
    /// the string representation (full DNS resolution would be async
    /// and is deferred to the host application).
    pub fn evaluate(&self, target: &str) -> SsrfProtectorResult {
        let start = std::time::Instant::now();

        if !self.config.enabled || self.config.allow_private_override {
            return SsrfProtectorResult {
                decision: crate::decision::Decision::Allow,
                reason: "ssrf_protector disabled or override active".into(),
                checked_target: target.into(),
                matched_range: None,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }

        // Try to parse as IP address.
        if let Ok(ip) = IpAddr::from_str(target) {
            if let Some((_, label)) = self.check_ip(&ip) {
                return SsrfProtectorResult {
                    decision: crate::decision::Decision::Deny {
                        code: "EXEC_SSRF_BLOCKED".into(),
                        retry_after: None,
                    },
                    reason: format!(
                        "target '{}' resolves to blocked range '{}'",
                        target, label
                    ),
                    checked_target: target.into(),
                    matched_range: Some(label),
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                };
            }
            // IP is safe.
            return SsrfProtectorResult {
                decision: crate::decision::Decision::Allow,
                reason: format!("target IP '{}' is not in any blocked range", target),
                checked_target: target.into(),
                matched_range: None,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }

        // Check if target contains a URL with a host.
        let host = extract_host_from_url(target);
        if let Some(host) = host {
            // Check if the hostname is a known internal name.
            if is_internal_hostname(&host) {
                return SsrfProtectorResult {
                    decision: crate::decision::Decision::Deny {
                        code: "EXEC_SSRF_BLOCKED".into(),
                        retry_after: None,
                    },
                    reason: format!("target '{}' uses internal hostname", target),
                    checked_target: target.into(),
                    matched_range: Some("INTERNAL-HOSTNAME".into()),
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                };
            }

            // Try to parse host as IP.
            if let Ok(ip) = IpAddr::from_str(&host) {
                if let Some((_, label)) = self.check_ip(&ip) {
                    return SsrfProtectorResult {
                        decision: crate::decision::Decision::Deny {
                            code: "EXEC_SSRF_BLOCKED".into(),
                            retry_after: None,
                        },
                        reason: format!(
                            "target URL '{}' has host in blocked range '{}'",
                            target, label
                        ),
                        checked_target: target.into(),
                        matched_range: Some(label),
                        latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                    };
                }
            }
        }

        // Target is not an IP and not a URL — treat as opaque string.
        // Check if it contains an IP-like pattern.
        for token in target.split(|c: char| !c.is_ascii_digit() && c != '.') {
            if let Ok(ip) = token.parse::<Ipv4Addr>() {
                if let Some((_, label)) = self.check_ip(&IpAddr::V4(ip)) {
                    return SsrfProtectorResult {
                        decision: crate::decision::Decision::Deny {
                            code: "EXEC_SSRF_BLOCKED".into(),
                            retry_after: None,
                        },
                        reason: format!(
                            "target '{}' contains blocked IP '{}' ({})",
                            target, token, label
                        ),
                        checked_target: target.into(),
                        matched_range: Some(label),
                        latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                    };
                }
            }
        }

        SsrfProtectorResult {
            decision: crate::decision::Decision::Allow,
            reason: format!("target '{}' passed SSRF checks", target),
            checked_target: target.into(),
            matched_range: None,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
        }
    }

    /// Check if an IP address falls within any blocked range.
    fn check_ip(&self, ip: &IpAddr) -> Option<(ipnet::IpNet, String)> {
        self.blocked_networks.iter().find(|(net, _)| net.contains(ip)).cloned()
    }
}

/// Extract hostname from a URL string.
fn extract_host_from_url(target: &str) -> Option<String> {
    let t = target.trim_start_matches("http://").trim_start_matches("https://");
    let host = t.split('/').next()?;
    let host = host.split(':').next()?; // Remove port
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Check if a hostname is a known internal name.
fn is_internal_hostname(host: &str) -> bool {
    let lower = host.to_lowercase();
    let internal_names = [
        "localhost",
        "metadata.google.internal",
        "metadata",
        "169.254.169.254",
        "instance-data",
        "kubernetes.default",
        "kubernetes.default.svc",
    ];
    internal_names.iter().any(|name| lower == *name || lower.ends_with(&format!(".{}", name)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_engine() -> SsrfProtector {
        SsrfProtector::new(&SsrfProtectorConfig::default()).unwrap()
    }

    #[test]
    fn block_loopback() {
        let engine = default_engine();
        let result = engine.evaluate("127.0.0.1");
        assert!(result.decision.is_deny());
        assert!(result.reason.contains("LOOPBACK"));
    }

    #[test]
    fn block_rfc1918() {
        let engine = default_engine();
        assert!(engine.evaluate("10.0.0.1").decision.is_deny());
        assert!(engine.evaluate("172.16.0.1").decision.is_deny());
        assert!(engine.evaluate("192.168.1.1").decision.is_deny());
    }

    #[test]
    fn block_cloud_metadata() {
        let engine = default_engine();
        let result = engine.evaluate("169.254.169.254");
        assert!(result.decision.is_deny());
        assert!(result.matched_range.as_deref() == Some("LINK-LOCAL-CLOUD-METADATA"));
    }

    #[test]
    fn allow_public_ip() {
        let engine = default_engine();
        let result = engine.evaluate("8.8.8.8");
        assert!(result.decision.is_allow());
    }

    #[test]
    fn block_url_with_internal_host() {
        let engine = default_engine();
        assert!(engine.evaluate("http://169.254.169.254/latest/meta-data/").decision.is_deny());
        assert!(engine.evaluate("http://localhost:8080/admin").decision.is_deny());
    }

    #[test]
    fn allow_public_url() {
        let engine = default_engine();
        let result = engine.evaluate("https://api.example.com/v1/data");
        assert!(result.decision.is_allow());
    }

    #[test]
    fn block_internal_hostname() {
        let engine = default_engine();
        assert!(engine.evaluate("http://metadata.google.internal/").decision.is_deny());
        assert!(engine.evaluate("http://kubernetes.default.svc/api").decision.is_deny());
    }

    #[test]
    fn extra_blocked_ranges() {
        let config = SsrfProtectorConfig {
            extra_blocked_ranges: vec!["203.0.113.0/24".into()],
            ..Default::default()
        };
        let engine = SsrfProtector::new(&config).unwrap();
        assert!(engine.evaluate("203.0.113.42").decision.is_deny());
    }

    #[test]
    fn ipv6_loopback() {
        let engine = default_engine();
        let result = engine.evaluate("::1");
        assert!(result.decision.is_deny());
    }
}
