/**
 * CHAKRAVYUH OS — Core HTTP client.
 *
 * Uses the native Fetch API (available in Node 18+, Deno, Bun, and all browsers).
 * Provides automatic retries with exponential backoff, timeout support,
 * and structured error handling.
 */
import { ApiKey } from "./auth";
import { type ChakravyuhConfig } from "./models";
/**
 * Low-level HTTP client for the CHAKRAVYUH OS API.
 *
 * @internal Prefer using the {@link Chakravyuh} class instead.
 */
export declare class ChakravyuhHttpClient {
    private readonly _apiKey;
    private readonly _baseUrl;
    private readonly _timeout;
    private readonly _maxRetries;
    private readonly _retryBaseDelay;
    private readonly _userAgent;
    private readonly _defaultIdempotencyKey;
    private readonly _defaultCorrelationId;
    constructor(config: ChakravyuhConfig);
    get apiKey(): ApiKey;
    get baseUrl(): string;
    get isLive(): boolean;
    get isTest(): boolean;
    /** Perform a GET request. */
    get<T>(path: string, options?: {
        correlationId?: string;
    }): Promise<T>;
    /** Perform a POST request with a JSON body. */
    post<T>(path: string, body: unknown, options?: {
        idempotencyKey?: string;
        correlationId?: string;
    }): Promise<T>;
    private request;
    private buildHeaders;
}
//# sourceMappingURL=client.d.ts.map