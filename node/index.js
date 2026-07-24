// Nemesis Shield — Sentinel SDK for Node.
//
// One line to protect an Express/Connect app:
//
//   import { sentinel } from "@nemesis-shield/sentinel/express";
//   app.use(sentinel({ token: process.env.NEMESIS_TOKEN }));
//
// It observes every request/response, reports only privacy-preserving metadata (method, path
// shape, status, whether the caller was authenticated) to Nemesis Shield, which learns your app's
// normal behavior and flags/─later─blocks what deviates. It never ships your request bodies or
// source. Fail-open throughout: if Nemesis is unreachable, your app is unaffected.

const OBSERVE_URL = "https://shield.nemesislabs.xyz/api/v1/observe";
const LLM_URL = "https://shield.nemesislabs.xyz/api/v1/llm";

/**
 * Report a batch of request events to Nemesis Shield. Fire-and-forget; never throws.
 * @param {string} token   Your app install token (nsk_…).
 * @param {Array<{method:string,path:string,status:number,authenticated?:boolean}>} events
 * @param {{endpoint?:string}} [opts]
 */
export async function report(token, events, opts = {}) {
  if (!token || !events || events.length === 0) return;
  try {
    await fetch(opts.endpoint || OBSERVE_URL, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ events }),
    });
  } catch {
    /* fail open — never break the host app */
  }
}

/** Collapse a concrete path to its shape so IDs don't explode the baseline: /orders/123 -> /orders/{int} */
export function pathShape(path) {
  return String(path || "/")
    .split("?")[0]
    .split("/")
    .map((seg) =>
      /^\d+$/.test(seg) ? "{int}"
        : /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg) ? "{uuid}"
        : /^[0-9a-f]{16,}$/i.test(seg) ? "{hex}"
        : seg,
    )
    .join("/");
}

/**
 * Express / Connect middleware. Observes each request and reports it after the response is sent.
 * @param {{token:string, endpoint?:string, authed?:(req:any)=>boolean, shapePaths?:boolean}} config
 */
export function sentinel(config) {
  const token = config && config.token;
  const endpoint = config && config.endpoint;
  const isAuthed = (config && config.authed) || ((req) => Boolean(req.headers && (req.headers.authorization || req.headers.cookie)));
  const shape = !config || config.shapePaths !== false;
  if (!token) console.warn("[nemesis-shield] no token provided — the middleware is a no-op.");

  return function nemesisSentinel(req, res, next) {
    res.on("finish", () => {
      if (!token) return;
      const rawPath = req.originalUrl || req.url || "/";
      report(token, [{
        method: (req.method || "GET").toUpperCase(),
        path: shape ? pathShape(rawPath) : rawPath.split("?")[0],
        status: res.statusCode,
        authenticated: Boolean(isAuthed(req)),
      }], { endpoint });
    });
    next();
  };
}

/**
 * Report an LLM exchange for OWASP-LLM behavioral protection. Fire-and-forget.
 * @param {string} token
 * @param {{prompt:string, system?:string, response?:string, tools?:string[], allowedTools?:string[]}} exchange
 * @param {{endpoint?:string}} [opts]
 */
export async function reportLLM(token, exchange, opts = {}) {
  if (!token || !exchange) return;
  try {
    await fetch(opts.endpoint || LLM_URL, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ exchanges: [exchange] }),
    });
  } catch {
    /* fail open */
  }
}

export default { sentinel, report, reportLLM, pathShape };
