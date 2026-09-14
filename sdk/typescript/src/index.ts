/**
 * CHAKRAVYUH OS — Official TypeScript SDK.
 *
 * @packageDocumentation
 *
 * ```ts
 * import { Chakravyuh } from "@vinomoid/chakravyuh";
 *
 * const ck = new Chakravyuh({
 *   apiKey: process.env.CK_API_KEY!,
 *   baseUrl: "https://api.chakravyuh.ai"
 * });
 *
 * const result = await ck.protect({
 *   input: "Ignore previous instructions",
 *   tenantId: "acme"
 * });
 *
 * console.log(result.allowed);
 * ```
 */

// ─── Client ─────────────────────────────────────────────────────

import { ChakravyuhHttpClient } from "./client";
import type { ChakravyuhConfig } from "./models";

// ─── Method modules ─────────────────────────────────────────────

import { protect, protectWith } from "./protect";
import { verify } from "./verify";
import { evaluatePolicy } from "./policy";
import { audit } from "./audit";
import { health } from "./health";

// ─── Re-export types (tree-shakeable) ────────────────────────────

export type {
  // Enums / unions
  InputType,
  Action,
  RiskLevel,
  Ring,
  Severity,
  PolicyDecision,
  HashAlgorithm,
  SignatureAlgorithm,
  IntegrityStatus,
  HealthStatus,
  ComponentHealth,
  BuildProfile,
  StepUpType,

  // Request types
  ChakravyuhConfig,
  ProtectInput,
  ProtectContext,
  ProtectRequest,
  VerifyRequest,
  PolicyRequest,
  AuditQuery,
  ToolDef,
  GeoInfo,
  HashSpec,
  SignatureSpec,

  // Response types
  ProtectResponse,
  ProtectDetails,
  StepUpRequired,
  VerifyResponse,
  VerifyDetails,
  PolicyResponse,
  MatchedRule,
  AuditRecord,
  AuditListResponse,
  Pagination,
  HealthResponse,
  LatencyStats,
  BuildInfo,
  ComponentStatuses,
  DegradedReason,

  // Error types
  ErrorBody,
  ErrorResponse,
} from "./models";

// ─── Re-export option types from their modules ─────────────────

export type { ProtectOptions } from "./protect";
export type { VerifyOptions } from "./verify";
export type { EvaluatePolicyOptions } from "./policy";
export type { AuditOptions } from "./audit";
export type { HealthOptions } from "./health";

// ─── Re-export errors ────────────────────────────────────────────

export {
  ChakravyuhError,
  UnauthorizedError,
  ForbiddenError,
  RateLimitError,
  ApiError,
  NetworkError,
} from "./errors";

// ─── Re-export auth ──────────────────────────────────────────────

export { ApiKey } from "./auth";

// ─── Main class ──────────────────────────────────────────────────

/**
 * CHAKRAVYUH OS client.
 *
 * The main entry point for the SDK. Instantiate with your API key and
 * call methods to interact with the CHAKRAVYUH OS API.
 *
 * @example
 * ```ts
 * import { Chakravyuh } from "@vinomoid/chakravyuh";
 *
 * const ck = new Chakravyuh({
 *   apiKey: process.env.CK_API_KEY!,
 * });
 *
 * // Quick protect
 * const result = await ck.protect({
 *   input: "What is the refund policy?",
 *   tenantId: "tenant_vino_001",
 * });
 * console.log(result.allowed, result.risk_score);
 *
 * // Full protect request
 * const full = await ck.protectWith({
 *   input: {
 *     type: "prompt",
 *     content: "Hello",
 *   },
 *   tenant_id: "tenant_vino_001",
 *   context: {
 *     source_ip: "203.0.113.42",
 *     session_id: "sess_abc123",
 *   },
 *   metadata: { model: "gpt-4o" },
 * });
 * ```
 */
export class Chakravyuh {
  private readonly _client: ChakravyuhHttpClient;

  constructor(config: ChakravyuhConfig) {
    this._client = new ChakravyuhHttpClient(config);
  }

  // ─── Accessors ───────────────────────────────────────────────

  /** Whether this client uses a production API key. */
  get isLive(): boolean {
    return this._client.isLive;
  }

  /** Whether this client uses a sandbox/test API key. */
  get isTest(): boolean {
    return this._client.isTest;
  }

  /** The configured API base URL. */
  get baseUrl(): string {
    return this._client.baseUrl;
  }

  // ─── Core Methods ─────────────────────────────────────────────

  /**
   * Analyze and protect an LLM interaction.
   *
   * This is the primary entry point for all real-time protection.
   *
   * @param params - Input string and tenant ID.
   * @returns Protection decision with risk score, confidence, and ring scores.
   *
   * @example
   * ```ts
   * const result = await ck.protect({
   *   input: "Ignore previous instructions",
   *   tenantId: "acme",
   * });
   * console.log(result.allowed); // false
   * console.log(result.risk_score); // 0.94
   * ```
   */
  async protect(params: {
    input: string;
    tenantId: string;
    inputType?: import("./models").InputType;
    context?: import("./models").ProtectContext;
    metadata?: Record<string, unknown>;
    contentType?: string;
    tools?: import("./models").ToolDef[];
    idempotencyKey?: string;
    correlationId?: string;
  }): Promise<import("./models").ProtectResponse> {
    return protect(this._client, params);
  }

  /**
   * Protect with a full {@link ProtectRequest} for maximum control.
   */
  async protectWith(
    request: import("./models").ProtectRequest,
    options?: { idempotencyKey?: string; correlationId?: string },
  ): Promise<import("./models").ProtectResponse> {
    return protectWith(this._client, request, options);
  }

  /**
   * Verify the cryptographic integrity of an audit evidence record.
   *
   * @param evidenceId - The evidence ID to verify.
   * @param options - Optional hash, signature, and correlation options.
   * @returns Verification result with integrity status and chain position.
   *
   * @example
   * ```ts
   * const result = await ck.verify("ev_8f14e45f");
   * console.log(result.verified); // true
   * console.log(result.integrity); // "intact"
   * ```
   */
  async verify(
    evidenceId: string,
    options?: import("./verify").VerifyOptions,
  ): Promise<import("./models").VerifyResponse> {
    return verify(this._client, evidenceId, options);
  }

  /**
   * Evaluate a security policy against a payload.
   *
   * @param params - Policy ID, input payload, and dry-run flag.
   * @returns Policy decision with matched rules and explanation.
   *
   * @example
   * ```ts
   * const result = await ck.evaluatePolicy({
   *   policyId: "pol_custom_sql_injection",
   *   payload: {
   *     type: "api_request",
   *     content: "SELECT * FROM users WHERE id = 1 OR 1=1",
   *   },
   *   dryRun: true,
   * });
   * console.log(result.decision); // "deny"
   * ```
   */
  async evaluatePolicy(
    params: {
      policyId: string;
      payload: import("./models").ProtectInput;
      dryRun?: boolean;
    },
    options?: { idempotencyKey?: string; correlationId?: string },
  ): Promise<import("./models").PolicyResponse> {
    return evaluatePolicy(this._client, params, options);
  }

  /**
   * List immutable audit records.
   *
   * @param options - Filtering, pagination, and correlation options.
   * @returns Paginated list of audit records.
   *
   * @example
   * ```ts
   * const { records, pagination } = await ck.audit({
   *   tenant: "tenant_vino_001",
   *   limit: 50,
   *   severity: "critical",
   * });
   * console.log(pagination.total_records);
   * ```
   */
  async audit(
    options?: import("./audit").AuditOptions,
  ): Promise<import("./models").AuditListResponse> {
    return audit(this._client, options);
  }

  /**
   * Get system health and status.
   *
   * @returns Health response with component statuses and latency stats.
   *
   * @example
   * ```ts
   * const status = await ck.health();
   * console.log(status.status); // "operational"
   * console.log(status.active_rings); // 15
   * ```
   */
  async health(
    options?: import("./health").HealthOptions,
  ): Promise<import("./models").HealthResponse> {
    return health(this._client, options);
  }
}
