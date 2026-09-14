"use strict";
/**
 * CHAKRAVYUH OS — `POST /v1/verify`
 *
 * Verifies the cryptographic integrity of an audit evidence record.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.verify = verify;
/**
 * Verify the cryptographic integrity of an audit evidence record.
 *
 * Used by compliance teams, auditors, and downstream systems to confirm
 * that audit records have not been tampered with since creation.
 *
 * @example
 * ```ts
 * const result = await ck.verify("ev_8f14e45f");
 * console.log(result.verified); // true
 * ```
 */
async function verify(client, evidenceId, options) {
    const request = {
        evidence_id: evidenceId,
        hash: options?.hash,
        signature: options?.signature,
    };
    return client.post("/v1/verify", request, {
        idempotencyKey: options?.idempotencyKey,
        correlationId: options?.correlationId,
    });
}
//# sourceMappingURL=verify.js.map