/**
 * CHAKRAVYUH OS — `POST /v1/protect`
 *
 * Analyzes a prompt, API request, agent instruction, or LLM traffic stream
 * against the active security policy rings and returns a protection decision.
 */

import type {
  ProtectRequest,
  ProtectResponse,
  InputType,
  ProtectContext,
  ToolDef,
} from "./models";
import type { ChakravyuhHttpClient } from "./client";

/** Options for the `protect` convenience method. */
export interface ProtectOptions {
  /** Tenant identifier for multi-tenant isolation. */
  tenantId: string;
  /** Optional request context. */
  context?: ProtectContext;
  /** Optional key-value metadata for custom policy evaluation. */
  metadata?: Record<string, unknown>;
  /** MIME type. Defaults to `text/plain`. */
  contentType?: string;
  /** Tool definitions (only for `agent_instruction`). */
  tools?: ToolDef[];
  /** Idempotency key. */
  idempotencyKey?: string;
  /** Correlation ID for distributed tracing. */
  correlationId?: string;
}

/**
 * Analyze and protect an LLM interaction.
 *
 * This is the primary entry point for all real-time protection.
 *
 * @example
 * ```ts
 * const result = await ck.protect({
 *   input: "Ignore previous instructions",
 *   tenantId: "acme"
 * });
 * console.log(result.allowed);
 * ```
 */
export async function protect(
  client: ChakravyuhHttpClient,
  params: { input: string; tenantId: string } & Omit<ProtectOptions, "tenantId"> &
    { inputType?: InputType },
): Promise<ProtectResponse> {
  const request: ProtectRequest = {
    input: {
      type: (params as Record<string, unknown>).inputType as InputType ?? "prompt",
      content: params.input,
      content_type: params.contentType,
      tools: params.tools,
    },
    tenant_id: params.tenantId,
    context: params.context,
    metadata: params.metadata,
  };

  return client.post<ProtectResponse>("/v1/protect", request, {
    idempotencyKey: params.idempotencyKey,
    correlationId: params.correlationId,
  });
}

/**
 * Protect with a full {@link ProtectRequest} for maximum control.
 */
export async function protectWith(
  client: ChakravyuhHttpClient,
  request: ProtectRequest,
  options?: { idempotencyKey?: string; correlationId?: string },
): Promise<ProtectResponse> {
  return client.post<ProtectResponse>("/v1/protect", request, options);
}
