// Fastify plugin. One line:
//   import { sentinelFastify } from "@nemesis-shield/sentinel/fastify";
//   await app.register(sentinelFastify, { token: process.env.NEMESIS_TOKEN });
import { SentinelClient } from "./lib/client.js";
import { buildSketch } from "./lib/shape.js";

function authed(req) {
  const h = req.headers || {};
  return Boolean(h.authorization || h.cookie || h["x-api-key"]);
}

export async function sentinelFastify(fastify, opts) {
  const client = new SentinelClient(opts);

  fastify.addHook("onRequest", async (req, reply) => {
    if (client.mode !== "enforce" || client.neverBlock(req.url)) return;
    const verdict = client.decide(buildSketch({ method: req.method, path: req.url, query: req.query, authenticated: authed(req) }));
    if (client.shouldBlock(verdict)) {
      client.record(buildSketch({ method: req.method, path: req.url, query: req.query, authenticated: authed(req), status: 403 }));
      reply.code(403).send({ error: "blocked_by_nemesis_shield", reason: verdict.reason }); // sending short-circuits
    }
  });

  fastify.addHook("onResponse", async (req, reply) => {
    client.record(buildSketch({ method: req.method, path: req.url, query: req.query, authenticated: authed(req), status: reply.statusCode }));
  });
}
// Break encapsulation so the hooks apply to the whole app, not just this plugin's context
// (this is what fastify-plugin does under the hood — done here to stay dependency-free).
sentinelFastify[Symbol.for("skip-override")] = true;

export default sentinelFastify;
