# CHAKRAVYUH Configuration Reference

> **File**: `config.example.yaml` | **Default path**: `/etc/chakravyuh/config.yaml` | **Format**: YAML

---

## server

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `bind` | `string` | `"0.0.0.0:8443"` | Listen address and port |
| `workers` | `integer` | `4` | Tokio worker threads |
| `tls.cert_path` | `string` | — | TLS fullchain PEM (requires `--features tls`) |
| `tls.key_path` | `string` | — | TLS private key PEM |

```yaml
server:
  bind: "0.0.0.0:8443"
  workers: 4
```

---

## upstream

Required for `/v1/proxy`. Override API key via `CHAKRAVYUH_UPSTREAM_API_KEY` env var.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `url` | `string` | — | Upstream LLM API URL |
| `api_key` | `string` | `""` | Upstream authentication key |
| `timeout_secs` | `integer` | `60` | Upstream request timeout |
| `forward_client_auth` | `boolean` | `false` | Forward client `Authorization` header instead of `api_key` |

```yaml
upstream:
  url: "https://api.openai.com/v1/chat/completions"
  api_key: "sk-your-key-here"
  timeout_secs: 60
```

---

## logging

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `level` | `string` | `"info"` | `trace`, `debug`, `info`, `warn`, `error` (override via `RUST_LOG`) |
| `format` | `string` | `"text"` | `text` or `json` |

---

## shield (Ring 1 — Perimeter Defense)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `boolean` | `true` | Enable/disable Shield Ring |
| `input_validator.enabled` | `boolean` | `true` | Validate required fields and limits |
| `input_validator.max_prompt_length` | `integer` | `32000` | Max prompt length in characters |
| `input_validator.max_tokens` | `integer` | `8000` | Max token count |
| `input_validator.max_messages` | `integer` | `100` | Max messages in array |
| `input_validator.required_fields` | `list[string]` | `["model","messages"]` | Required fields |
| `rate_limiter.enabled` | `boolean` | `true` | Enable rate limiting |
| `rate_limiter.backend` | `string` | `"memory"` | `memory` or `redis` |
| `rate_limiter.limits.per_ip` | `string` | `"100/min"` | Per-IP rate limit |
| `rate_limiter.limits.per_api_key` | `string` | `"1000/min"` | Per-API-key rate limit |
| `rate_limiter.limits.per_user` | `string` | `"500/min"` | Per-user rate limit |
| `dos_protector.enabled` | `boolean` | `true` | DoS/anomaly detection |
| `dos_protector.baseline_window` | `integer` | `3600` | Baseline window (seconds) |
| `dos_protector.threshold_sigma` | `float` | `5.0` | Std-dev threshold for anomaly |
| `dos_protector.block_duration` | `integer` | `300` | Block duration (seconds) |
| `geo_fencer.enabled` | `boolean` | `false` | Geolocation filtering |
| `geo_fencer.mode` | `string` | `"blocklist"` | `blocklist` or `allowlist` |
| `geo_fencer.countries` | `list[string]` | `[]` | Country codes to block/allow |
| `geo_fencer.default_on_lookup_fail` | `string` | `"deny"` | `deny` or `allow` on lookup failure |
| `bot_detector.enabled` | `boolean` | `true` | Bot detection |
| `bot_detector.challenge_unknown` | `boolean` | `false` | Challenge unknown bots vs block |
| `bot_detector.good_bots` | `list[string]` | `[Googlebot, Bingbot, ...]` | Known good bot user-agents |
| `bot_detector.bad_bots` | `list[string]` | `[sqlmap, nikto, nmap, ...]` | Known bad bot user-agents |
| `waf.enabled` | `boolean` | `true` | WAF rule engine |
| `waf.sanitize` | `boolean` | `false` | Sanitize instead of deny |
| `waf.custom_rules` | `list` | `[]` | Custom WAF rules |

```yaml
shield:
  enabled: true
  input_validator:
    enabled: true
    max_prompt_length: 32000
  rate_limiter:
    enabled: true
    backend: memory
    limits:
      per_ip: "100/min"
  waf:
    enabled: true
```

---

## threat (Ring 3 — Cognitive Threat Detection)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `boolean` | `true` | Enable/disable Threat Ring |
| `deny_threshold` | `float` | `0.60` | Score >= this is denied |
| `challenge_threshold` | `float` | `0.30` | Score >= this is challenged |
| `pattern_matcher.enabled` | `boolean` | `true` | Regex/pattern detection |
| `semantic_classifier.enabled` | `boolean` | `true` | Semantic intent classification |
| `jailbreak_detector.enabled` | `boolean` | `true` | Jailbreak attempt detection |

```yaml
threat:
  enabled: true
  deny_threshold: 0.60
  challenge_threshold: 0.30
```

---

## identity (Ring 2 — Auth, AuthZ & Trust)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `boolean` | `true` | Enable/disable Identity Ring |
| `session_identity.enabled` | `boolean` | `true` | Validate API key format and JWT |
| `session_identity.valid_api_key_prefixes` | `list[string]` | `["sk-","pk-"]` | Allowed key prefixes |
| `session_identity.min_api_key_length` | `integer` | `16` | Min API key length |
| `session_identity.max_api_key_length` | `integer` | `256` | Max API key length |
| `session_identity.trusted_jwt_issuers` | `list[string]` | `[]` | Trusted JWT issuer URIs |
| `role_resolver.enabled` | `boolean` | `true` | Map key prefixes to roles |
| `role_resolver.api_key_prefix_roles` | `map[string,string]` | see below | Prefix-to-role mapping |
| `trust_accumulator.enabled` | `boolean` | `true` | Accumulate trust over time |
| `trust_accumulator.max_identities` | `integer` | `10000` | Max tracked identities |
| `trust_accumulator.decay_rate` | `float` | `0.02` | Trust decay per evaluation |
| `identity_anomaly.enabled` | `boolean` | `true` | Detect identity anomalies |
| `identity_anomaly.challenge_threshold` | `float` | `6.0` | Anomaly score for challenge |
| `identity_anomaly.deny_threshold` | `float` | `9.0` | Anomaly score for deny |
| `identity_anomaly.velocity_threshold` | `float` | `30.0` | Requests/min velocity threshold |
| `identity_anomaly.travel_speed_threshold` | `float` | `800.0` | Impossible travel (km/h) |
| `identity_anomaly.off_hours` | `list[integer]` | `[9, 17]` | Business hours [start, end] (24h) |

```yaml
identity:
  enabled: true
  role_resolver:
    enabled: true
    api_key_prefix_roles:
      "sk-admin-": "admin"
      "sk-op-": "operator"
      "sk-audit-": "auditor"
      "sk-svc-": "service"
  identity_anomaly:
    enabled: true
    challenge_threshold: 6.0
    deny_threshold: 9.0
    off_hours: [9, 17]
```

---

## execution (Ring 6 — Tool Call Firewall)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `boolean` | `true` | Enable/disable Execution Ring |
| `tool_allowlist.enabled` | `boolean` | `true` | Enforce tool allowlist |
| `tool_allowlist.tools[].name` | `string` | — | Tool name |
| `tool_allowlist.tools[].enabled` | `boolean` | `true` | Allow this tool |
| `tool_allowlist.tools[].max_calls_per_request` | `integer` | — | Max calls per request |
| `parameter_validator.enabled` | `boolean` | `true` | Validate tool parameters |
| `sandbox_executor.enabled` | `boolean` | `true` | Sandbox high-risk tools |
| `sandbox_executor.always_sandbox_tools` | `list[string]` | `[shell_exec,code_execution,file_write]` | Always-sandbox tools |
| `approval_workflow.enabled` | `boolean` | `true` | Human approval for dangerous ops |
| `approval_workflow.default_timeout_secs` | `integer` | `300` | Approval timeout |
| `approval_workflow.default_fallback` | `string` | `"deny"` | On timeout: `deny` or `allow` |
| `approval_workflow.rules[].tool_name` | `string` | — | Tool the rule applies to |
| `approval_workflow.rules[].required_approver_role` | `string` | — | Role to approve |
| `action_logger.enabled` | `boolean` | `true` | Log all tool executions |
| `action_logger.max_entries` | `integer` | `10000` | Max in-memory entries |
| `action_logger.log_full_params` | `boolean` | `true` | Log full parameters |
| `ssrf_protector.enabled` | `boolean` | `true` | Block SSRF / cloud metadata |
| `ssrf_protector.extra_blocked_ranges` | `list[string]` | `[]` | Additional CIDR blocks |

```yaml
execution:
  enabled: true
  tool_allowlist:
    enabled: true
    tools:
      - name: web_search
        enabled: true
        max_calls_per_request: 5
  ssrf_protector:
    enabled: true
```

---

## agent (Ring 4 — Agent Policy, Behavior & Scope)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `boolean` | `true` | Enable/disable Agent Ring |
| `deny_threshold` | `float` | `9.0` | Cumulative risk for denial |
| `agent_policy.enabled` | `boolean` | `true` | Per-agent-type permissions |
| `agent_policy.type_policies` | `map` | see below | Agent type → permission list |
| `permission_enforcer.enabled` | `boolean` | `true` | Enforce permission boundaries |
| `permission_enforcer.bypass_roles` | `list[string]` | `["admin"]` | Roles that bypass checks |
| `agent_scope.enabled` | `boolean` | `true` | Enforce scope limits |
| `agent_scope.max_traversal_depth` | `integer` | `5` | Max scope traversal depth |
| `capability_guard.enabled` | `boolean` | `true` | Guard against capability escalation |
| `behavior_monitor.enabled` | `boolean` | `true` | Monitor behavior patterns |
| `behavior_monitor.max_agents` | `integer` | `5000` | Max tracked agents |
| `behavior_monitor.rate_spike_threshold` | `float` | `3.0` | Action rate spike multiplier |
| `behavior_monitor.scope_violation_threshold` | `integer` | `5` | Violations before escalation |
| `behavior_monitor.min_actions_for_detection` | `integer` | `5` | Min actions before analysis |
| `tool_chaining_detector.enabled` | `boolean` | `true` | Detect dangerous chaining |
| `tool_chaining_detector.history_size` | `integer` | `20` | History window size |
| `tool_chaining_detector.max_agents` | `integer` | `5000` | Max tracked agents |
| `tool_chaining_detector.risk_threshold` | `float` | `6.0` | Risk score for flagging |

```yaml
agent:
  enabled: true
  deny_threshold: 9.0
  agent_policy:
    enabled: true
    type_policies:
      coder: [read, write, execute, file_system, api_call, tool_use, code_execution]
      researcher: [read, network_access, api_call, memory_read, tool_use]
      assistant: [read, memory_read, tool_use]
```

---

## memory (Ring 5 — Context Integrity)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `boolean` | `true` | Enable/disable Memory Ring |
| `deny_threshold` | `float` | `9.0` | Risk score for denial |
| `context_guard.enabled` | `boolean` | `true` | Enforce context limits |
| `context_guard.max_context_length` | `integer` | `128000` | Max context length (chars) |
| `context_guard.max_turns` | `integer` | `100` | Max conversation turns |
| `pii_extractor.enabled` | `boolean` | `true` | Detect PII in prompts |
| `conversation_tracker.enabled` | `boolean` | `true` | Track conversation state |
| `conversation_tracker.max_conversations` | `integer` | `5000` | Max tracked conversations |
| `conversation_tracker.hijack_detection_threshold` | `float` | `8.0` | Hijack alert threshold |
| `rag_poison_detector.enabled` | `boolean` | `true` | Detect RAG poisoning |
| `rag_poison_detector.max_entry_length` | `integer` | `50000` | Max RAG entry length to scan |
| `rag_poison_detector.poison_markers` | `list[string]` | see below | Text markers for poisoning |
| `provenance_validator.enabled` | `boolean` | `true` | Validate entry provenance and age |
| `provenance_validator.max_entry_age_hours` | `integer` | `720` | Max entry age (hours) |
| `memory_access_control.enabled` | `boolean` | `true` | Enforce memory access control |

```yaml
memory:
  enabled: true
  rag_poison_detector:
    enabled: true
    poison_markers: ["ignore previous", "system prompt", "you are now", "disregard"]
```

---

## reasoning (Ring 7 — Chain-of-Thought Integrity)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `boolean` | `true` | Enable/disable Reasoning Ring |
| `deny_threshold` | `float` | `9.0` | Risk score for denial |
| `coherence_checker.min_coherence_score` | `float` | `0.3` | Min coherence score |
| `hallucination_detector.sensitivity` | `float` | `0.7` | Hallucination sensitivity |
| `depth_analyzer.min_depth_ratio` | `float` | `0.2` | Min reasoning depth ratio |
| `bias_detector.bias_threshold` | `float` | `0.6` | Bias detection threshold |
| `step_validator.max_invalid_steps` | `integer` | `2` | Max invalid reasoning steps |
| `output_consistency.min_consistency` | `float` | `0.4` | Min output consistency |

---

## governance (Ring 8 — Policy, Audit & Compliance)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `boolean` | `true` | Enable/disable Governance Ring |
| `deny_threshold` | `float` | `9.0` | Risk score for denial |
| `policy_compliance.max_violations` | `integer` | `3` | Max violations before deny |
| `audit_logger.retention_days` | `integer` | `90` | Audit log retention |
| `data_retention.max_retention_days` | `integer` | `365` | Max data retention |
| `data_retention.auto_delete` | `boolean` | `false` | Auto-delete expired data |
| `consent_tracker.require_explicit_consent` | `boolean` | `false` | Require explicit consent |
| `compliance_reporter.compliance_threshold` | `float` | `0.5` | Min compliance score |
| `compliance_reporter.frameworks` | `list[string]` | `[GDPR,SOC2,HIPAA]` | Compliance frameworks |
| `sanction_checker.enabled` | `boolean` | `true` | Sanctions screening |
| `sanction_checker.blocked_entities` | `list[string]` | `[]` | Blocked entity names/IDs |
| `sanction_checker.blocked_regions` | `list[string]` | `[]` | Blocked region codes |

---

## recovery_sec (Ring 9 — Incident Response & Rollback)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `boolean` | `true` | Enable/disable Recovery Ring |
| `deny_threshold` | `float` | `9.0` | Risk score for denial |
| `incident_classifier.critical_threshold` | `float` | `8.0` | Critical incident threshold |
| `incident_classifier.high_threshold` | `float` | `5.0` | High incident threshold |
| `rollback_engine.max_rollback_window_secs` | `integer` | `3600` | Max rollback time window |
| `quarantine_manager.max_quarantine_size` | `integer` | `10000` | Max quarantined items |
| `quarantine_manager.auto_quarantine_on_critical` | `boolean` | `true` | Auto-quarantine on critical |
| `evidence_collector.retention_days` | `integer` | `365` | Evidence retention |
| `evidence_collector.hash_algorithm` | `string` | `"sha256"` | Evidence hash algorithm |
| `state_restorer.checkpoint_interval_secs` | `integer` | `300` | State checkpoint interval |
| `state_restorer.max_checkpoints` | `integer` | `50` | Max stored checkpoints |
| `notification_engine.channels` | `list[string]` | `["log"]` | `log`, `webhook` |
| `notification_engine.severity_filter` | `float` | `5.0` | Min severity for notifications |

---

## keshav — Central Decision Brain

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `boolean` | `true` | Enable Keshav orchestration |
| `risk.w_threat` | `float` | `0.30` | Weight: Threat Ring |
| `risk.w_identity` | `float` | `0.15` | Weight: Identity Ring |
| `risk.w_behavior` | `float` | `0.15` | Weight: Agent Ring |
| `risk.w_memory` | `float` | `0.10` | Weight: Memory Ring |
| `risk.w_execution` | `float` | `0.20` | Weight: Execution Ring |
| `risk.w_reasoning` | `float` | `0.05` | Weight: Reasoning Ring |
| `risk.w_governance` | `float` | `0.05` | Weight: Governance Ring |
| `risk.w_recovery` | `float` | `0.05` | Weight: Recovery Ring |
| `risk.w_context` | `float` | `0.10` | Weight: contextual factors |
| `orchestrate.enabled` | `boolean` | `true` | Enable pipeline orchestration |

```yaml
keshav:
  enabled: true
  risk:
    w_threat: 0.30
    w_identity: 0.15
    w_behavior: 0.15
    w_execution: 0.20
    w_context: 0.10
```

---

## cross_ring

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `boolean` | `true` | Enable cross-ring communication |
| `buffer_size` | `integer` | `1000` | Channel buffer size |
| `recovery.enabled` | `boolean` | `true` | Enable recovery monitoring |
| `recovery.failure_threshold` | `integer` | `5` | Failures before circuit opens |
| `recovery.recovery_timeout_secs` | `integer` | `30` | Time before circuit close attempt |
| `recovery.latency_threshold_ms` | `float` | `50.0` | Slow-ring latency threshold |
| `recovery.error_rate_threshold` | `float` | `0.5` | Error rate for degraded mode |
| `recovery.max_rings_down` | `integer` | `3` | Rings down before lockdown |
| `recovery.history_window` | `integer` | `100` | Recovery event history size |

---

## storage

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `backend` | `string` | `"memory"` | `memory` or `redis` (`--features redis`) |
| `redis_url` | `string` | `"redis://127.0.0.1:6379"` | Redis connection URL |
| `redis_prefix` | `string` | `"chakravyuh:"` | Key prefix |
| `timeout_ms` | `integer` | `1000` | Operation timeout (ms) |

> Degrades gracefully to in-memory if the configured backend fails to connect.

---

## grpc

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `boolean` | `false` | Enable gRPC server |
| `addr` | `string` | `"0.0.0.0:50051"` | gRPC bind address |

---

## config_watcher

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `boolean` | `false` | Auto-reload on config file change |
| `debounce_ms` | `integer` | `500` | Debounce interval (ms) |

---

## audit

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `boolean` | `true` | SHA-256 hash-chained audit trail |
| `max_in_memory` | `integer` | `10000` | Max in-memory audit entries |

---

## api_keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `boolean` | `false` | HMAC-SHA256 auth for `/v1/*` |
| `master_secret` | `string` | `""` | Master secret (use `CHAKRAVYUH_MASTER_SECRET` env var) |
| `timestamp_tolerance_secs` | `integer` | `300` | Allowed HMAC clock skew (seconds) |
| `require_for_v1` | `boolean` | `false` | Require signed key for all `/v1/*` |

---

## ananta_config_path

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| (root key) | `string\|null` | `null` | Path to ANANTA trust plane config |

When set, loads ANANTA — the autonomous trust plane that continuously verifies the security system itself. When `null`, runs in degraded mode. See `configs/ananta.example.yaml`.

```yaml
ananta_config_path: "/etc/chakravyuh/ananta.yaml"
```
