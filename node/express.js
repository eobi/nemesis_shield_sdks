// Express / Connect adapter. One line:
//   import { sentinel } from "@nemesis-shield/sentinel/express";
//   app.use(sentinel({ token: process.env.NEMESIS_TOKEN }));
// Observes every request and, in enforce mode, blocks off-baseline requests (403) before your
// routes run. Fail-open.
import { SentinelClient } from "./lib/client.js";
import { buildSketch } from "./lib/shape.js";

function queryOf(req) {
  if (req.query && typeof req.query === "object") return req.query;
  try { return Object.fromEntries(new URL(req.url, "http://x").searchParams); } catch { return {}; }
}
function authedOf(req, fn) {
  if (fn) return Boolean(fn(req));
  const h = req.headers || {};
  return Boolean(h.authorization || h.cookie || h["x-api-key"]);
}

export function sentinel(config = {}) {
  const client = new SentinelClient(config);
  const authFn = config.authed;
  return function nemesisSentinel(req, res, next) {
    const path = req.originalUrl || req.url || "/";
    const query = queryOf(req);
    const authenticated = authedOf(req, authFn);
    if (client.mode === "enforce" && !client.neverBlock(path)) {
      const verdict = client.decide(buildSketch({ method: req.method, path, query, authenticated }));
      if (client.shouldBlock(verdict)) {
        client.record(buildSketch({ method: req.method, path, query, authenticated, status: 403 }));
        res.statusCode = 403;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ error: "blocked_by_nemesis_shield", reason: verdict.reason }));
        return;
      }
    }
    res.on("finish", () => client.record(buildSketch({ method: req.method, path, query, authenticated, status: res.statusCode })));
    next();
  };
}

export { SentinelClient };
