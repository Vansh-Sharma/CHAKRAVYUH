/**
 * CHAKRAVYUH OS — Core HTTP client.
 *
 * Uses the native Fetch API (available in Node 18+, Deno, Bun, and all browsers).
 * Provides automatic retries with exponential backoff, timeout support,
 * and structured error handling.
 */
import { ApiKey } from "./auth";
import {} from "./models";
import { NetworkError, errorFromResponse } from "./errors";
const DEFAULT_BASE_URL = "https://api.vinomoid.com";
const DEFAULT_TIMEOUT = 30_000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_BASE_DELAY = 500;
const USER_AGENT = "chakravyuh-ts-sdk/1.0.0";
/**
 * Low-level HTTP client for the CHAKRAVYUH OS API.
 *
 * @internal Prefer using the {@link Chakravyuh} class instead.
 */
export class ChakravyuhHttpClient {
    _apiKey;
    _baseUrl;
    _timeout;
    _maxRetries;
    _retryBaseDelay;
    _userAgent;
    _defaultIdempotencyKey;
    _defaultCorrelationId;
    constructor(config) {
        this._apiKey = new ApiKey(config.apiKey);
        this._baseUrl = (config.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
        this._timeout = config.timeout ?? DEFAULT_TIMEOUT;
        this._maxRetries = config.maxRetries ?? DEFAULT_MAX_RETRIES;
        this._retryBaseDelay = config.retryBaseDelay ?? DEFAULT_RETRY_BASE_DELAY;
        this._userAgent = config.userAgent ?? USER_AGENT;
        this._defaultIdempotencyKey = config.idempotencyKey;
        this._defaultCorrelationId = config.correlationId;
    }
    // ─── Public accessors ───────────────────────────────────────
    get apiKey() {
        return this._apiKey;
    }
    get baseUrl() {
        return this._baseUrl;
    }
    get isLive() {
        return this._apiKey.isLive;
    }
    get isTest() {
        return this._apiKey.isTest;
    }
    // ─── Request methods ─────────────────────────────────────────
    /** Perform a GET request. */
    async get(path, options) {
        return this.request({
            method: "GET",
            path,
            correlationId: options?.correlationId ?? this._defaultCorrelationId,
        });
    }
    /** Perform a POST request with a JSON body. */
    async post(path, body, options) {
        return this.request({
            method: "POST",
            path,
            body,
            idempotencyKey: options?.idempotencyKey ?? this._defaultIdempotencyKey,
            correlationId: options?.correlationId ?? this._defaultCorrelationId,
        });
    }
    // ─── Core request with retries ──────────────────────────────
    async request(opts) {
        let lastError;
        for (let attempt = 0; attempt <= this._maxRetries; attempt++) {
            try {
                const url = `${this._baseUrl}${opts.path}`;
                const headers = this.buildHeaders(opts);
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), this._timeout);
                const response = await fetch(url, {
                    method: opts.method,
                    headers,
                    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
                    signal: controller.signal,
                });
                clearTimeout(timeoutId);
                const bodyBytes = await response.arrayBuffer();
                const text = new TextDecoder().decode(bodyBytes);
                // Non-2xx → parse error and possibly retry
                if (!response.ok) {
                    let parsed;
                    try {
                        parsed = JSON.parse(text);
                    }
                    catch {
                        parsed = undefined;
                    }
                    const retryAfter = parseRetryAfter(response.headers.get("retry-after"));
                    const error = errorFromResponse(response.status, parsed, retryAfter);
                    if (isRetryable(response.status) && attempt < this._maxRetries) {
                        const delay = this._retryBaseDelay * Math.pow(2, attempt) + jitter();
                        await sleep(delay);
                        lastError = error;
                        continue;
                    }
                    throw error;
                }
                // 2xx → parse as JSON
                let data;
                try {
                    data = JSON.parse(text);
                }
                catch {
                    throw new NetworkError(`Failed to decode response JSON from ${opts.method} ${opts.path}`, false);
                }
                return data;
            }
            catch (err) {
                // NetworkError / TimeoutError → retry if appropriate
                if (err instanceof NetworkError && err.retryable && attempt < this._maxRetries) {
                    const delay = this._retryBaseDelay * Math.pow(2, attempt) + jitter();
                    await sleep(delay);
                    lastError = err;
                    continue;
                }
                // Re-throw known SDK errors directly
                if (err instanceof Error &&
                    ("code" in err || "status" in err || err.name === "AbortError")) {
                    if (err.name === "AbortError") {
                        throw new NetworkError(`Request timed out after ${this._timeout}ms`, true);
                    }
                    throw err;
                }
                // Unknown error → wrap in NetworkError
                throw new NetworkError(err instanceof Error ? err.message : String(err), true);
            }
        }
        // Should not reach here, but just in case
        throw lastError instanceof Error
            ? lastError
            : new NetworkError("Max retries exceeded", false);
    }
    // ─── Header construction ─────────────────────────────────────
    buildHeaders(opts) {
        const headers = {
            Authorization: this._apiKey.bearer,
            Accept: "application/json",
            "User-Agent": this._userAgent,
        };
        if (opts.method === "POST" && opts.body !== undefined) {
            headers["Content-Type"] = "application/json";
        }
        if (opts.idempotencyKey) {
            headers["Idempotency-Key"] = opts.idempotencyKey;
        }
        if (opts.correlationId) {
            headers["X-Correlation-Id"] = opts.correlationId;
        }
        if (opts.headers) {
            Object.assign(headers, opts.headers);
        }
        return headers;
    }
}
// ─── Helpers ────────────────────────────────────────────────────
function isRetryable(status) {
    // Retry on 429 (rate limit), 500 (internal), 502, 503, 504
    return status === 429 || status === 500 || status === 502 || status === 503 || status === 504;
}
function parseRetryAfter(value) {
    if (!value)
        return null;
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? n : null;
}
function jitter() {
    return Math.random() * 200;
}
function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
//# sourceMappingURL=client.js.map