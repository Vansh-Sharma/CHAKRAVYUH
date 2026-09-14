"use strict";
/**
 * CHAKRAVYUH OS — `GET /v1/health`
 *
 * Returns the operational health of the CHAKRAVYUH OS instance.
 * This endpoint does not require authentication when accessed from
 * internal/private networks.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.health = health;
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
async function health(client, options) {
    return client.get("/v1/health", {
        correlationId: options?.correlationId,
    });
}
//# sourceMappingURL=health.js.map