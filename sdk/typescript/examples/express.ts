/**
 * CHAKRAVYUH OS — Express Middleware Example
 *
 * Drop-in middleware that protects every POST /chat request.
 */

import express from "express";
import { Chakravyuh, type ProtectResponse } from "@vinomoid/chakravyuh";

const ck = new Chakravyuh({
  apiKey: process.env.CK_API_KEY!,
  baseUrl: process.env.CK_BASE_URL,
});

const app = express();
app.use(express.json());

// ─── Protect middleware ────────────────────────────────────────

app.post("/chat", async (req, res, next) => {
  try {
    const result: ProtectResponse = await ck.protect({
      input: req.body.prompt ?? req.body.message ?? "",
      tenantId: req.headers["x-tenant-id"] as string ?? "default",
      context: {
        source_ip: req.ip,
        user_agent: req.headers["user-agent"],
        session_id: req.headers["x-session-id"] as string | undefined,
      },
      metadata: {
        endpoint: "/chat",
        method: "POST",
      },
    });

    // Attach the protection result to the request for downstream handlers
    req.body._ck = result;

    if (!result.allowed) {
      res.status(403).json({
        allowed: false,
        action: result.action,
        risk_score: result.risk_score,
        reason: result.details?.reason,
      });
      return;
    }

    next();
  } catch (err) {
    next(err);
  }
});

// ─── Your chat handler ────────────────────────────────────────

app.post("/chat", async (req, res) => {
  // At this point, the request has been validated by Chakravyuh
  const ckResult = req.body._ck as ProtectResponse | undefined;

  res.json({
    reply: "Hello! How can I help you?",
    risk_score: ckResult?.risk_score ?? 0,
  });
});

// ─── Health check ──────────────────────────────────────────────

app.get("/health", async (_req, res, next) => {
  try {
    const status = await ck.health();
    res.json(status);
  } catch (err) {
    next(err);
  }
});

app.listen(3000, () => console.log("Server running on :3000"));
