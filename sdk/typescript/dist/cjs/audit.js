"use strict";
/**
 * CHAKRAVYUH OS — `GET /v1/audit`
 *
 * Returns a paginated list of immutable audit records.
 * Each record is cryptographically chained for tamper-proof integrity.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.audit = audit;
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
async function audit(client, options) {
    const params = new URLSearchParams();
    if (options?.tenant)
        params.set("tenant", options.tenant);
    if (options?.limit !== undefined)
        params.set("limit", String(options.limit));
    if (options?.offset !== undefined)
        params.set("offset", String(options.offset));
    if (options?.severity)
        params.set("severity", options.severity);
    if (options?.action)
        params.set("action", options.action);
    if (options?.from)
        params.set("from", options.from);
    if (options?.to)
        params.set("to", options.to);
    const qs = params.toString();
    const path = `/v1/audit${qs ? `?${qs}` : ""}`;
    return client.get(path, {
        correlationId: options?.correlationId,
    });
}
//# sourceMappingURL=audit.js.map