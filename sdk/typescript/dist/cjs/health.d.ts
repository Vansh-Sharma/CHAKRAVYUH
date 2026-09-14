/**
 * CHAKRAVYUH OS — `GET /v1/health`
 *
 * Returns the operational health of the CHAKRAVYUH OS instance.
 * This endpoint does not require authentication when accessed from
 * internal/private networks.
 */
import type { HealthResponse } from "./models";
import type { ChakravyuhHttpClient } from "./client";
/** Options for the `health` method. */
export interface HealthOptions {
    /** Correlation ID for distributed tracing. */
    correlationId?: string;
}
/**
 * Get system health and status.
 *
 * Use this for load balancer health checks, monitoring dashboards,
 * and operational alerts.
 *
 * @example
 * ```ts
 * const status = await ck.health();
 * console.log(status.status); // "operational"
 * console.log(status.components.ananta_engine); // "healthy"
 * ```
 */
export declare function health(client: ChakravyuhHttpClient, options?: HealthOptions): Promise<HealthResponse>;
//# sourceMappingURL=health.d.ts.map