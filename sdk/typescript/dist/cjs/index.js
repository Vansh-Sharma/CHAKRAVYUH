"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.Chakravyuh = exports.ApiKey = exports.NetworkError = exports.ApiError = exports.RateLimitError = exports.ForbiddenError = exports.UnauthorizedError = exports.ChakravyuhError = void 0;
// ─── Client ─────────────────────────────────────────────────────
const client_1 = require("./client");
// ─── Method modules ─────────────────────────────────────────────
const protect_1 = require("./protect");
const verify_1 = require("./verify");
const policy_1 = require("./policy");
const audit_1 = require("./audit");
const health_1 = require("./health");
// ─── Re-export errors ────────────────────────────────────────────
var errors_1 = require("./errors");
Object.defineProperty(exports, "ChakravyuhError", { enumerable: true, get: function () { return errors_1.ChakravyuhError; } });
Object.defineProperty(exports, "UnauthorizedError", { enumerable: true, get: function () { return errors_1.UnauthorizedError; } });
Object.defineProperty(exports, "ForbiddenError", { enumerable: true, get: function () { return errors_1.ForbiddenError; } });
Object.defineProperty(exports, "RateLimitError", { enumerable: true, get: function () { return errors_1.RateLimitError; } });
Object.defineProperty(exports, "ApiError", { enumerable: true, get: function () { return errors_1.ApiError; } });
Object.defineProperty(exports, "NetworkError", { enumerable: true, get: function () { return errors_1.NetworkError; } });
// ─── Re-export auth ──────────────────────────────────────────────
var auth_1 = require("./auth");
Object.defineProperty(exports, "ApiKey", { enumerable: true, get: function () { return auth_1.ApiKey; } });
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
class Chakravyuh {
    _client;
    constructor(config) {
        this._client = new client_1.ChakravyuhHttpClient(config);
    }
    // ─── Accessors ───────────────────────────────────────────────
    /** Whether this client uses a production API key. */
    get isLive() {
        return this._client.isLive;
    }
    /** Whether this client uses a sandbox/test API key. */
    get isTest() {
        return this._client.isTest;
    }
    /** The configured API base URL. */
    get baseUrl() {
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
    async protect(params) {
        return (0, protect_1.protect)(this._client, params);
    }
    /**
     * Protect with a full {@link ProtectRequest} for maximum control.
     */
    async protectWith(request, options) {
        return (0, protect_1.protectWith)(this._client, request, options);
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
    async verify(evidenceId, options) {
        return (0, verify_1.verify)(this._client, evidenceId, options);
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
    async evaluatePolicy(params, options) {
        return (0, policy_1.evaluatePolicy)(this._client, params, options);
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
    async audit(options) {
        return (0, audit_1.audit)(this._client, options);
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
    async health(options) {
        return (0, health_1.health)(this._client, options);
    }
}
exports.Chakravyuh = Chakravyuh;
//# sourceMappingURL=index.js.map