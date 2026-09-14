/**
 * CHAKRAVYUH OS — API key validation and Bearer token formatting.
 */
/**
 * Validate and format an API key for Bearer authentication.
 *
 * Keys must start with `ck_live_` (production) or `ck_test_` (sandbox).
 */
export declare class ApiKey {
    private readonly _raw;
    constructor(key: string);
    /** The Bearer-formatted authorization header value. */
    get bearer(): string;
    /** Whether this is a production key. */
    get isLive(): boolean;
    /** Whether this is a sandbox/test key. */
    get isTest(): boolean;
    /** The raw key value (use with caution). */
    get raw(): string;
}
import { UnauthorizedError } from "./errors";
export { UnauthorizedError };
//# sourceMappingURL=auth.d.ts.map