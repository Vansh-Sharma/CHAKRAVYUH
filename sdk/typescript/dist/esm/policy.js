/**
 * CHAKRAVYUH OS — `POST /v1/policy/evaluate`
 *
 * Evaluates a custom or named security policy against a provided payload.
 * Supports dry-run mode for testing policies without side effects.
 */
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
export async function evaluatePolicy(client, params, options) {
    const request = {
        policy_id: params.policyId,
        request_payload: params.payload,
        dry_run: params.dryRun,
    };
    return client.post("/v1/policy/evaluate", request, options);
}
//# sourceMappingURL=policy.js.map