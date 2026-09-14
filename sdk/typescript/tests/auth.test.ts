/**
 * Tests for API key validation.
 */
import { describe, it, expect } from "vitest";
import { ApiKey } from "../src/auth";

describe("ApiKey", () => {
  it("accepts live keys", () => {
    const key = new ApiKey("ck_live_abc123");
    expect(key.isLive).toBe(true);
    expect(key.isTest).toBe(false);
    expect(key.bearer).toBe("Bearer ck_live_abc123");
    expect(key.raw).toBe("ck_live_abc123");
  });

  it("accepts test keys", () => {
    const key = new ApiKey("ck_test_xyz789");
    expect(key.isLive).toBe(false);
    expect(key.isTest).toBe(true);
  });

  it("trims whitespace", () => {
    const key = new ApiKey("  ck_live_abc  ");
    expect(key.raw).toBe("ck_live_abc");
  });

  it("rejects invalid key formats", () => {
    expect(() => new ApiKey("sk_live_abc")).toThrow();
    expect(() => new ApiKey("random_key")).toThrow();
    expect(() => new ApiKey("")).toThrow();
  });
});
