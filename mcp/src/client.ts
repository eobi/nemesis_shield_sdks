// Secure API client for the authenticated Nemesis Shield tools.
//
// Security rules enforced here so individual tools can't get them wrong:
//   - The developer's API key is read ONLY from the NEMESIS_API_KEY env var (set in the MCP client
//     config). It is never a tool argument, never hardcoded, and never logged.
//   - Every error/response string is run through redact() so a token can never leak into tool output
//     or an agent's context.
//   - Auth-required tools degrade gracefully (a clear "set NEMESIS_API_KEY" hint) instead of throwing,
//     so the free/unauthenticated tools always work.

const API_BASE = (process.env.NEMESIS_API_BASE || "https://shield.nemesislabs.xyz").replace(/\/+$/, "");

export function apiKey(): string | undefined {
  const k = process.env.NEMESIS_API_KEY;
  return k && k.trim() ? k.trim() : undefined;
}

export function hasAuth(): boolean {
  return Boolean(apiKey());
}

export const AUTH_HINT =
  "This action needs your Nemesis API key. Add NEMESIS_API_KEY to your MCP client config (the server's " +
  "env), then retry. Create a key in the console at https://shield.nemesislabs.xyz. " +
  "Keep the server local (stdio) so the key stays on your machine.";

// Strip anything token-shaped from a string before it can reach tool output / model context.
export function redact(s: string): string {
  return String(s)
    .replace(/nsk_[A-Za-z0-9_-]{6,}/g, "nsk_…")
    .replace(/(?:sk|pk|key|api[_-]?key|token)[-_]?[A-Za-z0-9]{0,4}[A-Za-z0-9_-]{16,}/gi, "…redacted…")
    .replace(/(Bearer\s+)[A-Za-z0-9._-]+/gi, "$1…");
}

export interface ApiResult {
  ok: boolean;
  status: number;
  data?: any;
  error?: string;
}

// Authenticated JSON request. `path` is absolute from the host root (e.g. "/api/partner/v1/accounts").
export async function api(method: string, path: string, body?: unknown): Promise<ApiResult> {
  const key = apiKey();
  if (!key) return { ok: false, status: 0, error: AUTH_HINT };
  try {
    const r = await fetch(API_BASE + path, {
      method,
      headers: {
        authorization: `Bearer ${key}`,
        "content-type": "application/json",
        "user-agent": "nemesis-shield-mcp",
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await r.text();
    let data: any;
    try {
      data = text ? JSON.parse(text) : undefined;
    } catch {
      data = text;
    }
    if (!r.ok) {
      const detail = typeof data === "string" ? data : JSON.stringify(data ?? {});
      return { ok: false, status: r.status, error: redact(detail).slice(0, 400) };
    }
    return { ok: true, status: r.status, data };
  } catch (e: any) {
    return { ok: false, status: 0, error: redact(e?.message || String(e)) };
  }
}

// Convenience: turn an ApiResult into MCP tool text content, redacted.
export function resultText(r: ApiResult, okLines: (data: any) => string): string {
  if (!r.ok) return `Request failed${r.status ? ` (HTTP ${r.status})` : ""}: ${r.error || "unknown error"}`;
  return okLines(r.data);
}
