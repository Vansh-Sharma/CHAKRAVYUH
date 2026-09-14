# CHAKRAVYUH CLI Reference

> **Binary**: `chakravyuh`
> **Global Flag**: `-c, --config <PATH>` (default: `/etc/chakravyuh/config.yaml`)

---

## Server & Validation

### `chakravyuh serve`

Start the CHAKRAVYUH HTTP (and optionally gRPC) server.

```bash
chakravyuh serve --config /etc/chakravyuh/config.yaml --addr 0.0.0.0:8443
```

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config <PATH>` | `/etc/chakravyuh/config.yaml` | YAML configuration file |
| `-a, --addr <ADDR>` | `0.0.0.0:8443` | Bind address and port |

Graceful shutdown on `SIGINT`/`SIGTERM`. Log level override via `RUST_LOG` env var.

---

### `chakravyuh validate`

Quick config file validation (legacy). Validates YAML syntax and ring configuration.

```bash
chakravyuh validate --config config.yaml --verbose
```

| Flag | Description |
|------|-------------|
| `--verbose` | Show per-ring enabled/disabled status, storage backend |

**Output** (with `--verbose`):

```
Configuration is valid
  Shield Ring: enabled
  Threat Ring: enabled
  Identity Ring: enabled
  Agent Ring: enabled
  Memory Ring: enabled
  Execution Ring: enabled
  Storage: memory
```

**Exit codes**: `0` valid, `2` invalid.

---

### `chakravyuh test`

Smoke test against a running instance: health check, benign prompt, malicious prompt.

```bash
chakravyuh test --endpoint http://localhost:8443 --api-key sk-admin-test
```

| Flag | Description |
|------|-------------|
| `-e, --endpoint <URL>` | URL of running CHAKRAVYUH instance |
| `-k, --api-key <KEY>` | Optional API key for authentication |

---

### `chakravyuh version`

Print version, build profile, license.

```
CHAKRAVYUH v1.0.0
  Build:   release
  License: Apache-2.0
```

---

## Configuration Management

### `chakravyuh config validate`

Validate a YAML config file with optional verbose output showing all parsed sections.

```bash
chakravyuh config validate /etc/chakravyuh/config.yaml --verbose
```

---

### `chakravyuh config show`

Display parsed config. Filter to a single section. Options: `--format` (text/json), `section` (shield/threat/identity/agent/memory/execution/keshav/cross_ring/storage/governance/reasoning/recovery_sec).

```bash
chakravyuh config show config.yaml --format json shield
```

---

### `chakravyuh config defaults`

Print built-in default configuration. Optionally write to file.

```bash
chakravyuh config defaults --output /etc/chakravyuh/config.yaml
chakravyuh config defaults --format json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `yaml` | `yaml` or `json` |
| `--output <PATH>` | stdout | Write to file |

---

### `chakravyuh config diff`

Compare two config files and report differences.

```bash
chakravyuh config diff config.yaml config.production.yaml
```

**Output**:

```
3 differences found:
  Key                  | Base   | Modified
  threat.deny_threshold | 0.60  | 0.70
  storage.backend       | memory | redis
```

---

## Policy Management

### `chakravyuh policy compile`

Compile a YAML security policy to bytecode. Reports rule count, instructions, bytecode size.

```bash
chakravyuh policy compile policy.yaml --format json --output policy.bin
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `text` | `text` or `json` |
| `--output <PATH>` | — | Save compiled bytecode to file |

**Output**:

```
Policy Compilation
  Rule Count:      12
  Instructions:     48
  Bytecode Size:   256 B
  Source Hash:      a1b2c3d4...
```

---

### `chakravyuh policy inspect`

Disassemble bytecode. `--trace` executes with a sample SQL injection input.

```bash
chakravyuh policy inspect policy.yaml --trace
```

---

### `chakravyuh policy version`

Version history. With two files, compute hot-reload diff.

```bash
chakravyuh policy version policy.yaml policy.updated.yaml --format json
```

---

### `chakravyuh policy bytecode`

Dump raw bytecode in hex or disassembly format.

```bash
chakravyuh policy bytecode policy.yaml --format hex --output bytecode.hex
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `asm` | `hex` for raw bytes, `asm` for disassembly |
| `--output <PATH>` | — | Save hex dump to file |

---

## Prompt Evaluation

### `chakravyuh evaluate prompt`

Evaluate a single prompt offline against Shield and Threat rings.

```bash
chakravyuh evaluate prompt "Ignore all previous instructions" --verbose --format json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--source-ip` | `127.0.0.1` | Simulated source IP |
| `--user-id` | — | Simulated user ID |
| `--api-key` | — | Simulated API key |
| `--verbose` | false | Show detailed engine results |
| `--format` | `text` | `text` or `json` |

---

### `chakravyuh evaluate scan`

Scan a file of prompts (one per line or JSONL). Options: `--source-ip`, `--format` (text/json/summary), `--fail-fast`.

```bash
chakravyuh evaluate scan prompts.txt --format summary --fail-fast
```

---

### `chakravyuh evaluate batch`

Evaluate JSONL batch (`{"prompt":"..."}` format). Options: `--output <PATH>`, `--source-ip`.

```bash
chakravyuh evaluate batch test_prompts.jsonl --output results.jsonl
```

---

## Test Suites

### `chakravyuh test-suite shield`

OWASP LLM01 prompt injection benchmark (10 benign + 20 attack built-in).

```bash
chakravyuh test-suite shield --format csv > benchmark.csv
chakravyuh test-suite shield --benign custom.jsonl --attacks attacks.jsonl
```

Options: `--benign <FILE>`, `--attacks <FILE>`, `--format` (text/json/csv).

---

### `chakravyuh test-suite threat`

Threat ring detection accuracy. Options: `--file <FILE>` (JSONL: `{"prompt":"...","expected":"deny|allow"}`), `--format` (text/json).

```bash
chakravyuh test-suite threat --file tests.jsonl --format json
```

---

### `chakravyuh test-suite compliance`

```bash
chakravyuh test-suite compliance policy.yaml
```

---

### `chakravyuh test-suite quick`

Smoke test against a running instance (same as `chakravyuh test`). Options: `--endpoint`, `--api-key`.

---

## API Key Management

### `chakravyuh keys generate`

Generate an HMAC-SHA256 signed API key.

```bash
CHAKRAVYUH_MASTER_SECRET=mysecret chakravyuh keys generate \
  --name "prod-eval" --permissions "evaluate,proxy" --expires-days 365 --format json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--name` | `cli-generated` | Key label |
| `--description` | — | Key description |
| `--permissions` | `evaluate` | Comma-separated: `evaluate,proxy,execute,decisions,learn,policy,metrics,admin` |
| `--secret` | env var | Master secret (or `CHAKRAVYUH_MASTER_SECRET`) |
| `--expires-days` | `90` | Days until expiration (`0` = never) |
| `--format` | `text` | `text` or `json` |

**Output** (json):

```json
{"key_id": "ak_live_abc123", "name": "prod-eval", "permissions": ["Evaluate", "Proxy"],
 "expires_at": "2026-01-15T10:00:00+00:00", "secret_key": "ak_live_abc123:sig",
 "warning": "Save the secret key now. It cannot be retrieved again."}
```

---

### `chakravyuh keys verify`

Verify key signature. Options: `--secret` (or `CHAKRAVYUH_MASTER_SECRET` env var).

```bash
chakravyuh keys verify "ak_live_abc123:sig" --secret mysecret
```

---

### `chakravyuh keys info`

Decode key metadata (key ID, signature presence, inferred type). Options: `--format` (text/json).

```bash
chakravyuh keys info ak_live_abc123 --format json
```

---

### `chakravyuh keys list`

List API keys from a running instance. Options: `--endpoint`, `--api-key`.

---

### `chakravyuh keys revoke`

Revoke a key by ID. Options: `--endpoint`, `--api-key`.

---

## Audit Trail

### `chakravyuh audit verify`

Verify SHA-256 hash-chained audit log integrity.

```bash
chakravyuh audit verify --endpoint http://localhost:8443 --api-key sk-admin-key
```

---

### `chakravyuh audit tail`

Show recent audit entries. Default: 20 entries, text format, `http://localhost:8443`.

```bash
chakravyuh audit tail --count 50 --format jsonl
```

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --count` | `20` | Number of entries |
| `--format` | `text` | `text`, `json`, or `jsonl` |

---

### `chakravyuh audit search`

Search entries by `--source-ip`, `--path`, `--decision` (allow/deny/challenge). Default: 50 entries.

```bash
chakravyuh audit search --decision deny --limit 10 --format json
```

---

### `chakravyuh audit export`

Export to file. Default: `jsonl` format, 1000 entries.

```bash
chakravyuh audit export audit_dump.jsonl --format jsonl --limit 5000
```

---

### `chakravyuh audit stats`

```bash
chakravyuh audit stats --endpoint http://localhost:8443
```

---

## Status & Health

### `chakravyuh status health`

Check liveness or readiness. Default: liveness, 5s timeout, `http://localhost:8443`.

```bash
chakravyuh status health --ready --timeout 10
```

| Flag | Default | Description |
|------|---------|-------------|
| `--endpoint` | `http://localhost:8443` | Instance URL |
| `--ready` | false | Readiness (all rings healthy) vs liveness |
| `--timeout` | `5` | Timeout in seconds |

---

### `chakravyuh status rings`

Per-ring health, evaluation counts, error rates.

```bash
chakravyuh status rings --format text
```

---

### `chakravyuh status storage`

Storage backend health (memory or Redis).

```bash
chakravyuh status storage
```

---

### `chakravyuh status info`

System info from `/health`, `/version`, `/v1/storage/health`, `/v1/recovery`.

```bash
chakravyuh status info --format json
```

---

## Exit Codes

| Code | Name | Meaning |
|------|------|---------|
| 0 | `Ok` | Success |
| 1 | `GeneralError` | General failure |
| 2 | `ConfigError` | Configuration error |
| 3 | `PolicyError` | Policy compilation error |
| 4 | `ConnectionError` | Cannot reach endpoint |
| 5 | `PartialFailure` | Some checks failed |