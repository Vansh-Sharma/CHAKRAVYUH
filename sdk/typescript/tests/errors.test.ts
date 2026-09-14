/**
 * Tests for error classes.
 */
import { describe, it, expect } from "vitest";
import {
  ChakravyuhError,
  UnauthorizedError,
  ForbiddenError,
  RateLimitError,
  ApiError,
  NetworkError,
  errorFromResponse,
} from "../src/errors";

describe("UnauthorizedError", () => {
  it("has correct defaults", () => {
    const err = new UnauthorizedError();
    expect(err).toBeInstanceOf(ChakravyuhError);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("UnauthorizedError");
    expect(err.status).toBe(401);
    expect(err.code).toBe("authentication_required");
    expect(err.message).toContain("Authentication required");
  });

  it("accepts custom message", () => {
    const err = new UnauthorizedError("Custom msg", "custom_code", "req_abc");
    expect(err.message).toBe("Custom msg");
    expect(err.code).toBe("custom_code");
    expect(err.requestId).toBe("req_abc");
  });
});

describe("ForbiddenError", () => {
  it("has correct defaults", () => {
    const err = new ForbiddenError();
    expect(err.status).toBe(403);
    expect(err.code).toBe("access_denied");
  });
});

describe("RateLimitError", () => {
  it("has retryAfter", () => {
    const err = new RateLimitError("Slow down", "rate_limited", "req_123", 30);
    expect(err.status).toBe(429);
    expect(err.retryAfter).toBe(30);
  });

  it("retryAfter defaults to null", () => {
    const err = new RateLimitError("Slow down");
    expect(err.retryAfter).toBeNull();
  });
});

describe("ApiError", () => {
  it("carries status code and details", () => {
    const err = new ApiError(
      "Something went wrong",
      "internal_error",
      500,
      "req_int1",
      { field: "input.content" },
    );
    expect(err.status).toBe(500);
    expect(err.code).toBe("internal_error");
    expect(err.details).toEqual({ field: "input.content" });
  });
});

describe("NetworkError", () => {
  it("is retryable by default", () => {
    const err = new NetworkError("DNS failure");
    expect(err.retryable).toBe(true);
    expect(err.status).toBe(0);
  });
});

describe("errorFromResponse", () => {
  it("returns UnauthorizedError for 401", () => {
    const err = errorFromResponse(401, {
      error: { code: "auth_fail", message: "Bad token", request_id: "r1" },
    });
    expect(err).toBeInstanceOf(UnauthorizedError);
    expect(err.message).toBe("Bad token");
  });

  it("returns RateLimitError for 429", () => {
    const err = errorFromResponse(
      429,
      { error: { code: "rate_limited", message: "Too many", request_id: "r2" } },
      60,
    );
    expect(err).toBeInstanceOf(RateLimitError);
    expect((err as RateLimitError).retryAfter).toBe(60);
  });

  it("returns ApiError for 500", () => {
    const err = errorFromResponse(500, {
      error: { code: "boom", message: "Internal error", request_id: "r3" },
    });
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(500);
  });

  it("handles null body gracefully", () => {
    const err = errorFromResponse(503, null);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(503);
  });
});
