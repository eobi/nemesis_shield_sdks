// Minimal HTTP client with a cookie jar + timeout. Zero dependencies (Node 18+ fetch). Keeps a session
// across requests so a login carries into the rest of the run.

export class Session {
  constructor() {
    this.cookies = new Map(); // name -> value (single-origin session, good enough for one target)
    this.headers = {}; // sticky headers, e.g. Authorization after login
    this.log = []; // every request/response, for the coverage report
  }

  cookieHeader() {
    if (!this.cookies.size) return undefined;
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  absorb(res) {
    // Node fetch exposes multiple Set-Cookie via getSetCookie() (18.14+); fall back to the folded header.
    const raw = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [res.headers.get("set-cookie")].filter(Boolean);
    for (const line of raw) {
      const first = String(line).split(";")[0];
      const eq = first.indexOf("=");
      if (eq > 0) this.cookies.set(first.slice(0, eq).trim(), first.slice(eq + 1).trim());
    }
  }
}

/**
 * Perform one request. `opts`: { headers, json, form, body, timeoutMs, session }.
 *  - json: object -> JSON body   - form: FormData -> multipart   - body: raw string.
 * Returns { status, ok, headers, text, json, ms, error }.
 */
export async function request(method, url, opts = {}) {
  const { session, json, form, body, timeoutMs = 15000 } = opts;
  const headers = { accept: "application/json, text/html;q=0.9,*/*;q=0.8", ...(session?.headers || {}), ...(opts.headers || {}) };
  let payload;
  if (form) { payload = form; /* fetch sets multipart boundary */ }
  else if (json !== undefined) { headers["content-type"] = "application/json"; payload = JSON.stringify(json); }
  else if (body !== undefined) { payload = body; }
  const cookie = session?.cookieHeader();
  if (cookie) headers.cookie = cookie;

  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  const started = Date.now();
  try {
    const res = await fetch(url, { method, headers, body: payload, redirect: "manual", signal: ctrl.signal });
    session?.absorb(res);
    const text = await res.text();
    let parsed;
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("json")) { try { parsed = JSON.parse(text); } catch { /* leave undefined */ } }
    const out = { status: res.status, ok: res.ok, headers: Object.fromEntries(res.headers), text, json: parsed, ms: Date.now() - started };
    session?.log.push({ method, url, status: res.status, ms: out.ms });
    return out;
  } catch (e) {
    const out = { status: 0, ok: false, error: String(e?.name === "AbortError" ? "timeout" : e?.message || e), ms: Date.now() - started };
    session?.log.push({ method, url, status: 0, ms: out.ms, error: out.error });
    return out;
  } finally {
    clearTimeout(t);
  }
}
