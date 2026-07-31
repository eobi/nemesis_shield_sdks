// Koa middleware. One line:
//   import { sentinelKoa } from "@nemesis-shield/sentinel/koa";
//   app.use(sentinelKoa({ token: process.env.NEMESIS_TOKEN }));
import { SentinelClient } from "./lib/client.js";
import { buildSketch } from "./lib/shape.js";

export function sentinelKoa(config = {}) {
  const client = new SentinelClient(config);
  return async function nemesisKoa(ctx, next) {
    const h = ctx.request.headers || {};
    const authenticated = Boolean(h.authorization || h.cookie || h["x-api-key"]);
    const path = ctx.originalUrl || ctx.url || "/";
    const query = ctx.query || {};
    if (client.mode === "enforce" && !client.neverBlock(path)) {
      const verdict = client.decide(buildSketch({ method: ctx.method, path, query, authenticated }));
      if (client.shouldBlock(verdict)) {
        client.record(buildSketch({ method: ctx.method, path, query, authenticated, status: 403 }));
        ctx.status = 403;
        ctx.body = { error: "blocked_by_nemesis_shield", reason: verdict.reason };
        return;
      }
    }
    try {
      await next();
    } finally {
      client.record(buildSketch({ method: ctx.method, path, query, authenticated, status: ctx.status }));
    }
  };
}
export default sentinelKoa;
