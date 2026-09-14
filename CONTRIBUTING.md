# Contributing to CHAKRAVYUH

Thank you for your interest in contributing. This guide covers the development workflow,
code standards, and how to submit a pull request.

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Rust | 1.75+ | Pinned via `rust-toolchain.toml` |
| protoc | 3.x | Required for gRPC/tonic build (`tonic-build` invokes `protoc`) |
| cargo-audit | latest | `cargo install cargo-audit` |
| cargo-nextest | latest (optional) | Faster test runner: `cargo install cargo-nextest` |

On Debian/Ubuntu: `sudo apt install protobuf-compiler`
On macOS: `brew install protobuf`

---

## Development Setup

```bash
git clone https://github.com/vinomoid/chakravyuh.git
cd chakravyuh
cargo build --release
```

To build with optional features:

```bash
cargo build --release --features tls,redis
```

---

## Code Style

CHAKRAVYUH enforces strict formatting and linting. All patches must pass both checks.

```bash
# Format — must produce no diffs
cargo fmt --all -- --check

# Lint — warnings are denied
cargo clippy --all-targets --all-features -- -D warnings
```

If `cargo fmt` or `cargo clippy` fails, the CI pipeline will reject the PR.

---

## Testing

Run the full test suite before pushing:

```bash
cargo test                          # 3200+ unit + integration tests
cargo test --all-features           # includes redis + tls paths
cargo test --release                # release-mode correctness
cargo test --doc                    # documentation tests
cargo audit                        # 0 vulnerabilities (mandatory)
```

For faster iteration during development:

```bash
cargo test -p chakravyuh shield::    # single module
cargo nextest run                   # if cargo-nextest is installed
```

Benchmarks (not run by default):

```bash
cargo bench                         # criterion benchmarks
```

---

## Commit Messages

CHAKRAVYUH uses [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

feat(shield): add custom WAF rule loading from YAML
fix(threat): resolve false positive on multi-byte encoded payloads
docs(api): document rate limiter configuration options
refactor(identity): extract trust scoring into standalone module
chore(deps): bump axum to 0.7.9
perf(shield): compile WAF regexes lazily on first request
test(execution): add SSRF cloud-metadata edge-case coverage
```

Accepted types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`.

Scope is optional but encouraged — use the ring or subsystem name (e.g., `shield`, `threat`,
`keshav`, `ananta`, `api`, `cli`).

---

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`.
2. **Make your changes** following the code style and testing guidelines above.
3. **Update tests** if you change behavior. New engines must include unit tests, integration
   tests, and ideally a fuzz target in `fuzz/fuzz_targets/`.
4. **Update documentation** if you add or change public API, configuration, or behavior.
5. **Open a PR** against `main`. Include:
   - A clear description of the change.
   - Links to any related issues.
   - Before/after benchmarks for performance changes.
6. **CI must pass**: `cargo fmt`, `cargo clippy`, `cargo test --all-features`, `cargo audit`.
7. **Review**: at least one maintainer approval is required.

Breaking changes to the public API (documented in `docs/API_STABILITY.md`) require a major
version bump and a migration guide.

---

## What Needs Help

The following areas are open for community contribution:

### Infrastructure & Ecosystem

- **Helm chart** for Kubernetes deployment (see `docs/06-deployment/KUBERNETES.md` for requirements).
- **Docker Compose** stack with Redis, Prometheus, and Grafana dashboards.

### SDKs

- **Python SDK** wrapping the HTTP API (`/v1/evaluate`, `/v1/proxy`, `/v1/execute`).
- **TypeScript SDK** with full type definitions for the decision and risk-score response types.

### Content & Data

- **Non-English attack corpus** — expand `data/attack_corpus/` with Japanese, Korean, Arabic, and
  other language prompt injection patterns.
- **Additional OWASP LLM Top 10 test vectors** for LLM03–LLM10.

### Testing & Validation

- **LLM provider integration tests** — end-to-end tests against real OpenAI, Anthropic, and
  Google Gemini APIs via the `/v1/proxy` endpoint.
- **ML-based risk scoring** for Keshav-Risk — replace static weights with trained models.
- **Load testing at production scale** — target 10,000+ req/s benchmark on bare metal.

---

## What Is NOT Ready for Contribution

The following items are part of **Phase 9 (Marvel)** and are not yet designed or stable.
Do not open PRs for these unless explicitly asked by a maintainer:

- Dynamic ML classifiers in the Threat Ring (replacing heuristic engines).
- Dynamic ring selection in Keshav-Orchestrate (currently static routing).
- Distributed deployment and consensus beyond the ANANTA gossip prototype.
- Plugin marketplace infrastructure.
- Cloud-native managed service offering.

---

## Code of Conduct

Be respectful and constructive. We enforce the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).

---

## Questions?

Open a [GitHub Discussion](https://github.com/vinomoid/chakravyuh/discussions) or email
[maintainers@chakravyuh.org](mailto:maintainers@chakravyuh.org).
