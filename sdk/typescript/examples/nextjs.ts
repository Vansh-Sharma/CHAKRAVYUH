/**
 * CHAKRAVYUH OS — Next.js App Router Example
 *
 * Server-side protect middleware for API routes.
 */

import { NextRequest, NextResponse } from "next/server";
import { Chakravyuh, UnauthorizedError, RateLimitError } from "@vinomoid/chakravyuh";

const ck = new Chakravyuh({
  apiKey: process.env.CK_API_KEY!,
  baseUrl: process.env.CK_BASE_URL,
  timeout: 10_000,
});

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();

    const result = await ck.protect({
      input: body.prompt ?? body.message,
      tenantId: body.tenantId ?? "default",
      context: {
        source_ip: request.headers.get("x-forwarded-for") ?? undefined,
        user_agent: request.headers.get("user-agent") ?? undefined,
        session_id: body.sessionId,
      },
      metadata: {
        model: body.model,
        environment: process.env.NODE_ENV,
      },
    });

    if (!result.allowed) {
      return NextResponse.json(
        {
          allowed: false,
          action: result.action,
          reason: result.details?.reason,
        },
        { status: 403 },
      );
    }

    return NextResponse.json({ allowed: true });
  } catch (err) {
    if (err instanceof UnauthorizedError) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    if (err instanceof RateLimitError) {
      return NextResponse.json(
        { error: "Rate limited", retryAfter: err.retryAfter },
        { status: 429 },
      );
    }
    throw err;
  }
}
