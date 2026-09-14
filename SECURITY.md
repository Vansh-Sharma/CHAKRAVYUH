# Security Policy

## Supported Versions

| Version | Supported | Status |
|---------|:---------:|--------|
| 1.0.x | ✅ | Current release — security fixes only |
| < 1.0.0 | ❌ | End of life — upgrade required |

Only the latest 1.0.x patch release receives security patches. All earlier versions are considered end of life.

---

## Reporting a Vulnerability

If you believe you have discovered a security vulnerability in CHAKRAVYUH, we encourage responsible disclosure.

### Preferred Channel

**Email:** [security@chakravyuh.org](mailto:security@chakravyuh.org)

- Encrypt your report with our PGP key (fingerprint published at <https://chakravyuh.org/security>).
- Include a description of the vulnerability, steps to reproduce, and potential impact.
- We acknowledge receipt within 48 hours and provide an initial assessment within 7 business days.

### Alternative Channel

Open a **private GitHub issue** by visiting <https://github.com/vinomoid/chakravyuh/security/advisories/new> and selecting "Report a vulnerability." This uses GitHub's private vulnerability reporting feature, which restricts visibility to maintainers only.

### What to Expect

1. **Acknowledgment** within 48 hours.
2. **Initial assessment** and severity classification (Critical / High / Medium / Low) within 7 business days.
3. **Coordinated disclosure** — we will work with you on a fix and agree on a publication timeline.
4. **CVE assignment** for Critical and High severity findings, coordinated through GitHub Security Advisories.
5. **Public disclosure** no sooner than 90 days after report, or once a patched release is available.

We do not offer bug bounties at this time.

---

## Security Architecture

### No Unsafe Code

CHAKRAVYUH enforces `#![deny(unsafe_code)]` at the crate root. All code is safe Rust unless explicitly opted out at the module level with a documented justification reviewed by a maintainer.

### Transport Layer Security

TLS is provided by [rustls](https://github.com/rustls/rustls) 0.23 — a pure-Rust TLS implementation with no OpenSSL dependency. Built-in TLS termination is available via the optional `tls` feature flag. Production deployments are encouraged to terminate TLS at a reverse proxy (nginx, Caddy, AWS ALB).

### API Authentication

All authenticated endpoints require an API key validated via **HMAC-SHA256**. Keys are generated with `chakravyuh keys generate` and verified using constant-time comparison (`subtle` crate) to prevent timing attacks.

### Audit Trail Integrity

Every security decision produces an append-only audit record. Records are chained using **SHA-256** hashes — each entry includes the hash of the previous entry, making tampering detectable. Audit logs can be exported as JSON or CSV via the CLI or the `/v1/decisions/export` endpoint.

---

## Dependency Security

CHAKRAVYUH maintains a **zero-vulnerability** policy. Every release must pass `cargo audit` with 0 known vulnerabilities.

### Verified Dependency Versions

| Dependency | Version | Security Relevance |
|------------|---------|--------------------|
| `h2` | >= 0.4.16 | HTTP/2 framing (RUSTSEC-2026-0258 resolved) |
| `maxminddb` | 0.27 | GeoIP lookups (RUSTSEC-2025-0132 resolved) |
| `notify` | 8.0 | Config hot-reload (no `instant` transitive dep) |
| `axum-server` | 0.8 | TLS termination via rustls |
| `rustls` | 0.23 | Pure-Rust TLS (no OpenSSL) |
| `ed25519-dalek` | 2.1 | Cryptographic signatures (ANANTA trust plane) |
| `aes-gcm` | 0.10 | AES-256-GCM encryption (ANANTA) |
| `sha2` | 0.10 | Integrity verification |
| `blake3` | 1.5 | High-performance hashing (ANANTA) |
| `hmac` | 0.12 | API key authentication |
| `subtle` | 2.6 | Constant-time operations |

### Audit Workflow

```bash
cargo audit                # Must report 0 vulnerabilities
cargo audit --deny warnings  # CI enforces this gate
```

Dependency updates are reviewed for breaking changes and security relevance before merging.

---

## Incident Response

For security incidents affecting deployed CHAKRAVYUH instances, refer to the [Recovery Ring documentation](docs/06-deployment/PRODUCTION.md) and the incident response playbooks included in the `src/incident_response/` module.

---

## Security-Related Configuration

- **API keys**: Generate and rotate via `chakravyuh keys generate` / `chakravyuh keys rotate`.
- **TLS certificates**: Configure under `server.tls` in `config.yaml`. Certificates are not bundled — operators provide their own.
- **Rate limiting**: Token-bucket algorithm with configurable per-IP, per-key, and per-user limits.
- **Geo-fencing**: Requires a MaxMind GeoLite2 database file; the database is not distributed with the binary.

---

*Last updated: v1.0.0*