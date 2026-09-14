/**
 * CHAKRAVYUH OS — Error classes.
 *
 * All errors thrown by the SDK extend {@link ChakravyuhError}.
 * Import individual classes or use `instanceof` checks.
 */
import type { ProtectResponse } from "./models";
/** Base error for all CHAKRAVYUH SDK errors. */
export declare class ChakravyuhError extends Error {
    /** Machine-readable error code from the API. */
    readonly code: string;
    /** Request identifier for support correlation. */
    readonly requestId: string;
    /** HTTP status code, if applicable. */
    readonly status: number;
    /** Additional error context from the API. */
    readonly details?: Record<string, unknown>;
    constructor(message: string, code: string, status: number, requestId: string, details?: Record<string, unknown>);
}
/** Thrown when authentication is missing or invalid (HTTP 401). */
export declare class UnauthorizedError extends ChakravyuhError {
    constructor(message?: string, code?: string, requestId?: string);
}
/**
 * Thrown when the request is denied (HTTP 403).
 *
 * For `/v1/protect`, the 403 body is a full `ProtectResponse` with
 * `allowed: false`. The parsed response object is attached as
 * `response` so callers can inspect `e.response.reason`,
 * `e.response.ring`, `e.response.evidence_id`, etc.
 *
 * @example
 * ```ts
 * try {
 *   await ck.protect({ input: "Ignore all previous instructions", tenantId: "t1" });
 * } catch (e) {
 *   if (e instanceof ForbiddenError) {
 *     console.log(e.response?.reason);   // WAF_PROMPT_INJECTION_IGNORE
 *     console.log(e.response?.ring);     // shield
 *   }
 * }
 * ```
 */
export declare class ForbiddenError extends ChakravyuhError {
    /** The parsed ProtectResponse from the 403 body, if available. */
    readonly response?: ProtectResponse;
    constructor(message?: string, code?: string, requestId?: string, response?: ProtectResponse);
}
/** Thrown when the rate limit is exceeded (HTTP 429). */
export declare class RateLimitError extends ChakravyuhError {
    /** Seconds until the rate limit window resets. */
    readonly retryAfter: number | null;
    constructor(message: string, code: string | undefined, requestId: string | undefined, retryAfter: undefined | number);
}
/** Thrown when the API returns a non-2xx response (except 401/403/429). */
export declare class ApiError extends ChakravyuhError {
    constructor(message: string, code: string, status: number, requestId: string, details?: Record<string, unknown>);
}
/** Thrown when a network-level failure occurs (DNS, timeout, connection reset). */
export declare class NetworkError extends ChakravyuhError {
    /** Whether the error is retryable with backoff. */
    readonly retryable: boolean;
    constructor(message: string, retryable?: boolean);
}
/**
 * Construct the correct error class from an API error response.
 *
 * For HTTP 403 from `/v1/protect`, the body is a `ProtectResponse`
 * (not an error envelope). The response fields are parsed and attached
 * to the returned `ForbiddenError` as `response`.
 *
 * @internal
 */
export declare function errorFromResponse(status: number, body: unknown, retryAfter?: number | null | undefined): ChakravyuhError;
//# sourceMappingURL=errors.d.ts.map