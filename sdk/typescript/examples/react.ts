/**
 * CHAKRAVYUH OS — React Hook Example
 *
 * A custom React hook that wraps the SDK for client-side usage.
 * NOTE: In production, always proxy through your own backend to
 * avoid exposing API keys in the browser.
 */

import { useState, useCallback } from "react";
import { Chakravyuh, type ProtectResponse } from "@vinomoid/chakravyuh";

// Initialize the client once — in a real app, point to YOUR backend proxy.
const ck = new Chakravyuh({
  apiKey: process.env.NEXT_PUBLIC_CK_API_KEY!,
  baseUrl: process.env.NEXT_PUBLIC_CK_BASE_URL ?? "/api/chakravyuh",
});

interface UseChakravyuhReturn {
  protect: (input: string) => Promise<ProtectResponse | null>;
  result: ProtectResponse | null;
  loading: boolean;
  error: string | null;
}

/**
 * React hook for CHAKRAVYUH OS protection.
 *
 * @example
 * ```tsx
 * function ChatForm() {
 *   const { protect, result, loading, error } = useChakravyuh();
 *
 *   const handleSubmit = async (e: FormEvent) => {
 *     e.preventDefault();
 *     await protect(message);
 *     if (result?.allowed) {
 *       // send to LLM
 *     }
 *   };
 *
 *   return (
 *     <form onSubmit={handleSubmit}>
 *       <textarea onChange={(e) => setMessage(e.target.value)} />
 *       <button disabled={loading}>Send</button>
 *       {error && <p className="text-red-500">{error}</p>}
 *       {result && !result.allowed && (
 *         <p className="text-red-500">{result.details?.reason}</p>
 *       )}
 *     </form>
 *   );
 * }
 * ```
 */
export function useChakravyuh(tenantId = "default"): UseChakravyuhReturn {
  const [result, setResult] = useState<ProtectResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const protect = useCallback(
    async (input: string) => {
      setLoading(true);
      setError(null);
      setResult(null);

      try {
        const response = await ck.protect({
          input,
          tenantId,
        });
        setResult(response);
        return response;
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "Protection check failed";
        setError(message);
        return null;
      } finally {
        setLoading(false);
      }
    },
    [tenantId],
  );

  return { protect, result, loading, error };
}