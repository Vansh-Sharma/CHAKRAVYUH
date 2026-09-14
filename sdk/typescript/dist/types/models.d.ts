/**
 * CHAKRAVYUH OS — Typed data models.
 *
 * Every interface is derived from the OpenAPI 3.1 contract at `/v1`.
 * Do NOT add fields that are not present in the spec.
 */
/** Type of input being protected. */
export type InputType = "prompt" | "api_request" | "agent_instruction" | "output" | "conversation";
/** Action taken by the orchestrator. */
export type Action = "allow" | "block" | "conditional" | "warn";
/** Risk severity classification. */
export type RiskLevel = "none" | "low" | "medium" | "high" | "critical";
/** Defense ring identifier. */
export type Ring = "prompt" | "input" | "output" | "context" | "agent" | "identity" | "trust" | "compliance" | "rate" | "geo" | "anomaly" | "behavioral" | "session" | "semantic" | "ovaph";
/** Severity classification for audit and policy events. */
export type Severity = "none" | "low" | "medium" | "high" | "critical";
/** Policy evaluation decision. */
export type PolicyDecision = "allow" | "deny" | "warn";
/** Hash algorithm. */
export type HashAlgorithm = "sha256" | "sha384" | "sha512";
/** Signature algorithm. */
export type SignatureAlgorithm = "ed25519" | "ecdsa_p256" | "rsa_pss";
/** Integrity verification result. */
export type IntegrityStatus = "intact" | "corrupted" | "unknown";
/** Overall system health status. */
export type HealthStatus = "operational" | "degraded" | "unavailable";
/** Component health status. */
export type ComponentHealth = "healthy" | "degraded" | "unhealthy";
/** Build profile. */
export type BuildProfile = "debug" | "release";
/** Step-up authentication type. */
export type StepUpType = "mfa" | "captcha" | "manual_review";
/** Tool definition for agent instructions. */
export interface ToolDef {
    /** Tool name. */
    name: string;
    /** Tool description. */
    description?: string;
    /** JSON Schema describing tool parameters. */
    parameters?: Record<string, unknown>;
}
/** Geolocation data for geo-ring evaluation. */
export interface GeoInfo {
    country_code?: string;
    region?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
    asn?: number;
    is_vpn?: boolean;
}
/** Input to the protect endpoint. */
export interface ProtectInput {
    /** Type of input being protected. */
    type: InputType;
    /** Raw content to analyze. */
    content: string;
    /** MIME type. Defaults to `text/plain`. */
    content_type?: string;
    /** Tool definitions (only for `agent_instruction`). */
    tools?: ToolDef[];
}
/** Contextual metadata about the request environment. */
export interface ProtectContext {
    source_ip?: string;
    user_agent?: string;
    session_id?: string;
    user_id?: string;
    endpoint?: string;
    method?: string;
    agent_id?: string;
    chain_depth?: number;
    geo?: GeoInfo;
}
/** Request body for `POST /v1/protect`. */
export interface ProtectRequest {
    input: ProtectInput;
    tenant_id: string;
    context?: ProtectContext;
    metadata?: Record<string, unknown>;
}
/** Step-up authentication requirement. */
export interface StepUpRequired {
    type: StepUpType;
    challenge: string;
}
/** Additional decision context (present when action is not `allow`). */
export interface ProtectDetails {
    reason?: string;
    patterns?: string[];
    recommendation?: string;
    step_up_required?: StepUpRequired;
}
/** Response from `POST /v1/protect`. */
export interface ProtectResponse {
    allowed: boolean;
    action: Action;
    risk_score: number;
    confidence: number;
    triggered_ring: Ring | null;
    policy_id: string;
    evidence_id: string;
    latency_ms: number;
    request_id: string;
    ring_scores?: Record<string, number>;
    details?: ProtectDetails;
}
/** Hash specification. */
export interface HashSpec {
    algorithm: HashAlgorithm;
    value: string;
}
/** Signature specification. */
export interface SignatureSpec {
    algorithm: SignatureAlgorithm;
    value: string;
}
/** Request body for `POST /v1/verify`. */
export interface VerifyRequest {
    evidence_id: string;
    hash?: HashSpec;
    signature?: SignatureSpec;
}
/** Additional details when verification fails. */
export interface VerifyDetails {
    expected_hash?: string;
    actual_hash?: string;
    divergence_at?: string;
}
/** Response from `POST /v1/verify`. */
export interface VerifyResponse {
    verified: boolean;
    integrity: IntegrityStatus;
    timestamp: string;
    chain_position: number;
    hash?: HashSpec;
    details?: VerifyDetails;
}
/** Request body for `POST /v1/policy/evaluate`. */
export interface PolicyRequest {
    policy_id: string;
    request_payload: ProtectInput;
    dry_run?: boolean;
}
/** A matched rule in a policy evaluation. */
export interface MatchedRule {
    rule_id: string;
    rule_name: string;
    ring: Ring;
    severity: Severity;
    pattern?: string;
    details?: string;
    confidence: number;
}
/** Response from `POST /v1/policy/evaluate`. */
export interface PolicyResponse {
    decision: PolicyDecision;
    matched_rules: MatchedRule[];
    severity: Severity;
    explanation: string;
    recommendation?: string;
}
/** Query parameters for `GET /v1/audit`. */
export interface AuditQuery {
    tenant?: string;
    limit?: number;
    offset?: number;
    severity?: Severity;
    action?: Action;
    from?: string;
    to?: string;
}
/** A single audit record. */
export interface AuditRecord {
    evidence_id: string;
    timestamp: string;
    tenant_id: string;
    action: Action;
    severity: Severity;
    risk_score: number;
    triggered_ring?: Ring;
    policy_id: string;
    input_type?: string;
    input_hash?: string;
    summary?: string;
    details?: Record<string, unknown>;
    chain_position: number;
    chain_hash: string;
}
/** Pagination metadata. */
export interface Pagination {
    total_records: number;
    limit: number;
    offset: number;
    has_more: boolean;
    next_offset?: number;
}
/** Response from `GET /v1/audit`. */
export interface AuditListResponse {
    records: AuditRecord[];
    pagination: Pagination;
}
/** Latency percentiles. */
export interface LatencyStats {
    p50_ms?: number;
    p95_ms?: number;
    p99_ms?: number;
}
/** Build metadata. */
export interface BuildInfo {
    version: string;
    commit: string;
    target: string;
    profile: BuildProfile;
    rustc: string;
    built_at: string;
}
/** Component health statuses. */
export interface ComponentStatuses {
    keshav_orchestrator: ComponentHealth;
    ananta_engine: ComponentHealth;
    sentinel: ComponentHealth;
    phoenix: ComponentHealth;
    trust_engine: ComponentHealth;
    identity: ComponentHealth;
    policy_compiler: ComponentHealth;
    audit_engine: ComponentHealth;
    ovaph: ComponentHealth;
}
/** Reason for degraded status. */
export interface DegradedReason {
    component: string;
    issue: string;
}
/** Response from `GET /v1/health`. */
export interface HealthResponse {
    status: HealthStatus;
    version: string;
    uptime_seconds: number;
    active_rings: number;
    latency?: LatencyStats;
    build: BuildInfo;
    components: ComponentStatuses;
    degraded_reasons?: DegradedReason[];
}
/** Error body returned by the API. */
export interface ErrorBody {
    code: string;
    message: string;
    request_id: string;
    details?: Record<string, unknown>;
}
/** Error response envelope. */
export interface ErrorResponse {
    error: ErrorBody;
}
/** Configuration for the Chakravyuh client. */
export interface ChakravyuhConfig {
    /** Bearer API key (`ck_live_*` or `ck_test_*`). */
    apiKey: string;
    /** API base URL. Defaults to `https://api.vinomoid.com`. */
    baseUrl?: string;
    /** Request timeout in milliseconds. Defaults to 30000. */
    timeout?: number;
    /** Maximum retry attempts for retryable errors. Defaults to 3. */
    maxRetries?: number;
    /** Base delay in ms for exponential backoff. Defaults to 500. */
    retryBaseDelay?: number;
    /** Idempotency key for retry-safe requests. */
    idempotencyKey?: string;
    /** Correlation ID for distributed tracing. */
    correlationId?: string;
    /** Custom User-Agent header value. */
    userAgent?: string;
}
//# sourceMappingURL=models.d.ts.map