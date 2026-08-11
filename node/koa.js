// Koa middleware. One line:
//   import { sentinelKoa } from "@nemesis-shield-autogon/sentinel/koa";
//   app.use(sentinelKoa({ token: process.env.NEMESIS_TOKEN }));
import { SentinelClient } from "./lib/client.js";
import { buildSketch } from "./lib/shape.js";

export function sentinelKoa(config = {}) {
  const client = new SentinelClient(config);
  return async function nemesisKoa(ctx, next) {
    let authenticated = false, path = "/", query = {};
    // FAIL-OPEN: any throw in the decision path must not break the request — swallow and continue.
    try {
      const h = ctx.request.headers || {};
      authenticated = Boolean(h.authorization || h.cookie || h["x-api-key"]);
      path = ctx.originalUrl || ctx.url || "/";
      query = ctx.query || {};
      if (client.mode === "enforce" && !client.neverBlock(path)) {
        const verdict = client.decide(buildSketch({ method: ctx.method, path, query, authenticated }));
        if (client.shouldBlock(verdict)) {
          client.record(buildSketch({ method: ctx.method, path, query, authenticated, status: 403 }));
          ctx.status = 403;
          ctx.body = { error: "blocked_by_nemesis_shield", reason: verdict.reason };
          return;
        }
      }
    } catch {
      /* fail-open */
    }
    try {
      await next();
    } finally {
      try { client.record(buildSketch({ method: ctx.method, path, query, authenticated, status: ctx.status })); }
      catch { /* fail-open telemetry */ }
    }
  };
}
export default sentinelKoa;
