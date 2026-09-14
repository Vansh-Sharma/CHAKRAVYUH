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
export declare function audit(client: ChakravyuhHttpClient, options?: AuditOptions): Promise<AuditListResponse>;
//# sourceMappingURL=audit.d.ts.map