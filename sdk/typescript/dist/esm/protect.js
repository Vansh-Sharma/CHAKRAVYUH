/**
 * CHAKRAVYUH OS — `POST /v1/protect`
 *
 * Analyzes a prompt, API request, agent instruction, or LLM traffic stream
 * against the active security policy rings and returns a protection decision.
 */
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
export async function protect(client, params) {
    const request = {
        input: {
            type: params.inputType ?? "prompt",
            content: params.input,
            content_type: params.contentType,
            tools: params.tools,
        },
        tenant_id: params.tenantId,
        context: params.context,
        metadata: params.metadata,
    };
    return client.post("/v1/protect", request, {
        idempotencyKey: params.idempotencyKey,
        correlationId: params.correlationId,
    });
}
/**
 * Protect with a full {@link ProtectRequest} for maximum control.
 */
export async function protectWith(client, request, options) {
    return client.post("/v1/protect", request, options);
}
//# sourceMappingURL=protect.js.map