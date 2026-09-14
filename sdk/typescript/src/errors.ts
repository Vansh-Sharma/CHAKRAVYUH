/**
 * CHAKRAVYUH OS — Error classes.
 *
 * All errors thrown by the SDK extend {@link ChakravyuhError}.
 * Import individual classes or use `instanceof` checks.
 */

import type { ErrorBody, ProtectResponse } from "./models";

// ─── Base Error ─────────────────────────────────────────────────

/** Base error for all CHAKRAVYUH SDK errors. */
export class ChakravyuhError extends Error {
  /** Machine-readable error code from the API. */
  public readonly code: string;
  /** Request identifier for support correlation. */
  public readonly requestId: string;
  /** HTTP status code, if applicable. */
  public readonly status: number;
  /** Additional error context from the API. */
  public readonly details?: Record<string, unknown>;

  constructor(
    message: string,
    code: string,
    status: number,
    requestId: string,
    details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.status = status;
    this.requestId = requestId;
    this.details = details;
  }
}

// ─── 401 Unauthorized ───────────────────────────────────────────

/** Thrown when authentication is missing or invalid (HTTP 401). */
export class UnauthorizedError extends ChakravyuhError {
  constructor(
    message = "Authentication required. Provide a valid Bearer token.",
    code = "authentication_required",
    requestId = "",
  ) {
    super(message, code, 401, requestId);
  }
}

// ─── 403 Forbidden ──────────────────────────────────────────────

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
export class ForbiddenError extends ChakravyuhError {
  /** The parsed ProtectResponse from the 403 body, if available. */
  public readonly response?: ProtectResponse;

  constructor(
    message = "Your tenant does not have permission for this operation.",
    code = "access_denied",
    requestId = "",
    response?: ProtectResponse,
  ) {
    super(message, code, 403, requestId);
    this.response = response;
  }
}

// ─── 429 Rate Limited ──────────────────────────────────────────

/** Thrown when the rate limit is exceeded (HTTP 429). */
export class RateLimitError extends ChakravyuhError {
  /** Seconds until the rate limit window resets. */
  public readonly retryAfter: number | null;

  constructor(
    message: string,
    code = "rate_limited",
    requestId = "",
    retryAfter: undefined | number,
  ) {
    super(message, code, 429, requestId);
    this.name = "RateLimitError";
    this.retryAfter = retryAfter ?? null;
  }
}

// ─── 4xx / 5xx API Error ───────────────────────────────────────

/** Thrown when the API returns a non-2xx response (except 401/403/429). */
export class ApiError extends ChakravyuhError {
  constructor(
    message: string,
    code: string,
    status: number,
    requestId: string,
    details?: Record<string, unknown>,
  ) {
    super(message, code, status, requestId, details);
  }
}

// ─── Network Error ──────────────────────────────────────────────

/** Thrown when a network-level failure occurs (DNS, timeout, connection reset). */
export class NetworkError extends ChakravyuhError {
  /** Whether the error is retryable with backoff. */
  public readonly retryable: boolean;

  constructor(
    message: string,
    retryable = true,
  ) {
    super(message, "network_error", 0, "");
    this.name = "NetworkError";
    this.retryable = retryable;
  }
}

// ─── Factory ────────────────────────────────────────────────────

/**
 * Construct the correct error class from an API error response.
 *
 * For HTTP 403 from `/v1/protect`, the body is a `ProtectResponse`
 * (not an error envelope). The response fields are parsed and attached
 * to the returned `ForbiddenError` as `response`.
 *
 * @internal
 */
export function errorFromResponse(
  status: number,
  body: unknown,
  retryAfter?: number | null | undefined,
): ChakravyuhError {
  // ── 403 with a ProtectResponse body ──
  // The /v1/protect endpoint returns 403 with the full ProtectResponse
  // JSON (allowed, action, triggered_ring, details.reason, risk_score,
  // confidence, evidence_id, request_id) — NOT an error envelope.
  // Parse it and attach to ForbiddenError.response.
  if (status === 403 && isProtectResponseBody(body)) {
    const response = body as ProtectResponse;
    const reason = response.details?.reason ?? response.action ?? "Forbidden";
    const requestId = response.request_id ?? "";
    return new ForbiddenError(reason, "access_denied", requestId, response);
  }

  // ── Standard error envelope ──
  const errorBody = extractErrorBody(body);

  switch (status) {
    case 401:
      return new UnauthorizedError(
        errorBody?.message ?? "Authentication required.",
        errorBody?.code ?? "authentication_required",
        errorBody?.request_id ?? "",
      );
    case 403:
      return new ForbiddenError(
        errorBody?.message ?? "Access denied.",
        errorBody?.code ?? "access_denied",
        errorBody?.request_id ?? "",
      );
    case 429:
      return new RateLimitError(
        errorBody?.message ?? "Rate limit exceeded.",
        errorBody?.code ?? "rate_limited",
        errorBody?.request_id ?? "",
        retryAfter ?? undefined,
      );
    default:
      return new ApiError(
        errorBody?.message ?? `API error (HTTP ${status})`,
        errorBody?.code ?? "api_error",
        status,
        errorBody?.request_id ?? "",
        errorBody?.details,
      );
  }
}

/**
 * Check if a response body is a ProtectResponse (has `allowed` key).
 * Used to distinguish 403 from /v1/protect (ProtectResponse body)
 * from 403 elsewhere (error envelope body).
 */
function isProtectResponseBody(body: unknown): body is ProtectResponse {
  if (body === null || body === undefined || typeof body !== "object") {
    return false;
  }
  return "allowed" in body && typeof (body as ProtectResponse).allowed === "boolean";
}

function extractErrorBody(body: unknown): ErrorBody | undefined {
  if (body === null || body === undefined) return undefined;
  if (typeof body === "object" && "error" in body) {
    return (body as { error: ErrorBody }).error;
  }
  return undefined;
}
