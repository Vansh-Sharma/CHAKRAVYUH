"use strict";
/**
 * CHAKRAVYUH OS — API key validation and Bearer token formatting.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.UnauthorizedError = exports.ApiKey = void 0;
/**
 * Validate and format an API key for Bearer authentication.
 *
 * Keys must start with `ck_live_` (production) or `ck_test_` (sandbox).
 */
class ApiKey {
    _raw;
    constructor(key) {
        const trimmed = key.trim();
        if (!trimmed.startsWith("ck_live_") && !trimmed.startsWith("ck_test_")) {
            throw new errors_1.UnauthorizedError(`Invalid API key format. Keys must start with \`ck_live_\` or \`ck_test_\`.
Got: \`${trimmed.slice(0, 8)}...\``, "invalid_api_key", "");
        }
        this._raw = trimmed;
    }
    /** The Bearer-formatted authorization header value. */
    get bearer() {
        return `Bearer ${this._raw}`;
    }
    /** Whether this is a production key. */
    get isLive() {
        return this._raw.startsWith("ck_live_");
    }
    /** Whether this is a sandbox/test key. */
    get isTest() {
        return this._raw.startsWith("ck_test_");
    }
    /** The raw key value (use with caution). */
    get raw() {
        return this._raw;
    }
}
exports.ApiKey = ApiKey;
// Re-export for convenience — callers only need to import from "./errors"
const errors_1 = require("./errors");
Object.defineProperty(exports, "UnauthorizedError", { enumerable: true, get: function () { return errors_1.UnauthorizedError; } });
//# sourceMappingURL=auth.js.map