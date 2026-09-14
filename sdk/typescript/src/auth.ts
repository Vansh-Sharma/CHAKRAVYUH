/**
 * CHAKRAVYUH OS — API key validation and Bearer token formatting.
 */

/**
 * Validate and format an API key for Bearer authentication.
 *
 * Keys must start with `ck_live_` (production) or `ck_test_` (sandbox).
 */
export class ApiKey {
  private readonly _raw: string;

  constructor(key: string) {
    const trimmed = key.trim();
    if (!trimmed.startsWith("ck_live_") && !trimmed.startsWith("ck_test_")) {
      throw new UnauthorizedError(
        `Invalid API key format. Keys must start with \`ck_live_\` or \`ck_test_\`.
Got: \`${trimmed.slice(0, 8)}...\``,
        "invalid_api_key",
        "",
      );
    }
    this._raw = trimmed;
  }

  /** The Bearer-formatted authorization header value. */
  get bearer(): string {
    return `Bearer ${this._raw}`;
  }

  /** Whether this is a production key. */
  get isLive(): boolean {
    return this._raw.startsWith("ck_live_");
  }

  /** Whether this is a sandbox/test key. */
  get isTest(): boolean {
    return this._raw.startsWith("ck_test_");
  }

  /** The raw key value (use with caution). */
  get raw(): string {
    return this._raw;
  }
}

// Re-export for convenience — callers only need to import from "./errors"
import { UnauthorizedError } from "./errors";
export { UnauthorizedError };
