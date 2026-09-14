/**
 * CHAKRAVYUH OS — `POST /v1/policy/evaluate`
 *
 * Evaluates a custom or named security policy against a provided payload.
 * Supports dry-run mode for testing policies without side effects.
 */
import type { PolicyResponse, ProtectInput } from "./models";
import type { ChakravyuhHttpClient } from "./client";
/** Options for the `evaluatePolicy` method. */
export interface EvaluatePolicyOptions {
    /** If true, evaluates without creating audit records or modifying state. */
    dryRun?: boolean;
    /** Idempotency key. */
    idempotencyKey?: string;
    /** Correlation ID for distributed tracing. */
    correlationId?: string;
}
/**
 * Evaluate a security policy against a payload.
 *
 * Use this to:
 * - Test policy changes before deployment (dryRun: true)
 * - Evaluate complex custom policies
 * - Debug which rules match a given input
 * - Integrate policy decisions into external workflows
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
export declare function evaluatePolicy(client: ChakravyuhHttpClient, params: {
    policyId: string;
    payload: ProtectInput;
    dryRun?: boolean;
}, options?: {
    idempotencyKey?: string;
    correlationId?: string;
}): Promise<PolicyResponse>;
//# sourceMappingURL=policy.d.ts.map