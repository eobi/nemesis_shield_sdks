// Deep test for the Cloudflare Worker proxy - drives the actual exported worker.fetch with a stubbed
// global fetch (mock Shield policy + mock Supabase backend) and proves: only /rest/ is guarded,
// off-baseline DB queries are blocked (403), approved ones pass, non-DB paths forward untouched, and
// the query STRUCTURE (PostgREST select/filter) is fed into the decision. Run: deno test tests/deep.ts
import { assertEquals } from "jsr:@std/assert@1";
import { createShield } from "../../edge/nemesis-shield.ts";
import worker from "../src/index.ts";

// Approved baseline shape: GET /rest/v1/products?select=* (computed via the same engine the proxy uses)
const s = createShield({});
const approved = s.buildSketch("GET", "/rest/v1/products", { select: "*" }, false, 0).shape;

const ORIG = globalThis.fetch;
globalThis.fetch = ((input: any, _init?: any) => {
  const url = typeof input === "string" ? input : input.url;
  if (url.includes("/api/v1/sketches")) {
    return Promise.resolve(
      new Response(JSON.stringify({ mode: "enforce", policy: { shapes: { [approved]: "allow" }, knownBad: [] } }), { status: 200 }),
    );
  }
  return Promise.resolve(new Response("supabase-backend-ok", { status: 200 })); // the real DB backend
}) as typeof fetch;

const env = { SUPABASE_URL: "https://proj.supabase.co", NEMESIS_TOKEN: "t", NEMESIS_ENDPOINT: "https://shield.nemesislabs.xyz/api/v1/sketches" };
const waits: Promise<unknown>[] = [];
const ctx = { waitUntil: (p: Promise<unknown>) => { waits.push(p); }, passThroughOnException() {} };
const call = (u: string, method = "GET") => worker.fetch(new Request("https://w" + u, { method }), env, ctx as any);

Deno.test("cloudflare proxy: /rest guarded, off-baseline blocked, non-DB forwarded", async () => {
  await call("/rest/v1/products?select=*"); // first request primes the policy refresh
  await Promise.all(waits);                  // policy now enforce + baseline

  assertEquals((await call("/rest/v1/products?select=*")).status, 200, "approved DB query passes");
  assertEquals((await call("/rest/v1/users?select=*")).status, 403, "off-baseline table blocked");
  assertEquals((await call("/rest/v1/products?select=*&role=eq.admin")).status, 403, "off-baseline filter (extra param) blocked");
  assertEquals((await call("/rest/v1/products?select=*", "DELETE")).status, 403, "off-baseline verb blocked");
  assertEquals((await call("/auth/v1/token")).status, 200, "non-DB path forwarded untouched (not guarded)");
  assertEquals((await call("/storage/v1/object/list")).status, 200, "storage path forwarded untouched");

  globalThis.fetch = ORIG;
});
