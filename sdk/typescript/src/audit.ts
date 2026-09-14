/**
 * CHAKRAVYUH OS — `GET /v1/audit`
 *
 * Returns a paginated list of immutable audit records.
 * Each record is cryptographically chained for tamper-proof integrity.
 */

import type { AuditQuery, AuditListResponse } from "./models";
import type { ChakravyuhHttpClient } from "./client";

/** Options for the `audit` method. */
export interface AuditOptions {
  /** Filter by tenant ID. */
  tenant?: string;
  /** Number of records to return (1–100, default 20). */
  limit?: number;
  /** Pagination offset. */
  offset?: number;
  /** Filter by severity. */
  severity?: AuditQuery["severity"];
  /** Filter by action. */
  action?: AuditQuery["action"];
  /** Start of time range (inclusive, ISO 8601). */
  from?: string;
  /** End of time range (exclusive, ISO 8601). */
  to?: string;
  /** Correlation ID for distributed tracing. */
  correlationId?: string;
}

/**
 * List immutable audit records.
 *
 * Records are ordered by timestamp (newest first) and support filtering
 * by tenant, severity, action type, and time range.
 *
 * @example
 * ```ts
 * const { records, pagination } = await ck.audit({
 *   tenant: "tenant_vino_001",
 *   limit: 50,
 * });
 * console.log(pagination.total_records);
 * ```
 */
export async function audit(
  client: ChakravyuhHttpClient,
  options?: AuditOptions,
): Promise<AuditListResponse> {
  const params = new URLSearchParams();

  if (options?.tenant) params.set("tenant", options.tenant);
  if (options?.limit !== undefined) params.set("limit", String(options.limit));
  if (options?.offset !== undefined) params.set("offset", String(options.offset));
  if (options?.severity) params.set("severity", options.severity);
  if (options?.action) params.set("action", options.action);
  if (options?.from) params.set("from", options.from);
  if (options?.to) params.set("to", options.to);

  const qs = params.toString();
  const path = `/v1/audit${qs ? `?${qs}` : ""}`;

  return client.get<AuditListResponse>(path, {
    correlationId: options?.correlationId,
  });
}
