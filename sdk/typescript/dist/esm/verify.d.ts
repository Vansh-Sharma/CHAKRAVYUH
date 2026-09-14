/**
 * CHAKRAVYUH OS — `POST /v1/verify`
 *
 * Verifies the cryptographic integrity of an audit evidence record.
 */
import type { VerifyResponse, HashSpec, SignatureSpec } from "./models";
import type { ChakravyuhHttpClient } from "./client";
/** Options for the `verify` method. */
export interface VerifyOptions {
    /** Optional hash specification to verify against. */
    hash?: HashSpec;
    /** Optional signature specification. */
    signature?: SignatureSpec;
    /** Idempotency key. */
    idempotencyKey?: string;
    /** Correlation ID for distributed tracing. */
    correlationId?: string;
}
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
export declare function verify(client: ChakravyuhHttpClient, evidenceId: string, options?: VerifyOptions): Promise<VerifyResponse>;
//# sourceMappingURL=verify.d.ts.map