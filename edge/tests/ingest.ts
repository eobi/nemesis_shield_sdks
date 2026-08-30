// Ingest-volume + throttle contract for the edge SDK.
//
// Regression cover for the self-amplification that produced a 9.65x Vercel edge-request anomaly on our
// own portal: `handler()` used to call `flush()` unconditionally after every request, so `record()`'s
// 25-sketch batch threshold was dead code and each inbound request produced its own ingest POST. Add a
// per-request Shield construction on top (which the portal was doing) and the refresh TTL died too,
// making it TWO POSTs per request.
import { Shield } from "../nemesis-shield.ts";
import { assert, assertEquals } from "jsr:@std/assert@1";

type Call = { body: string };

/** A Shield wired to a stub fetch, with a controllable clock. Returns the calls it makes. */
function harness(respond: (n: number) => Response, opts: Record<string, unknown> = {}) {
  const calls: Call[] = [];
  let now = 1_700_000_000_000;
  const realFetch = globalThis.fetch;
  const realNow = Date.now;
  globalThis.fetch = ((_url: string, init: RequestInit) => {
    calls.push({ body: String(init.body) });
    return Promise.resolve(respond(calls.length));
  }) as typeof fetch;
  Date.now = () => now;
  const shield = new Shield({ token: "t", ...opts });
  return {
    shield,
    calls,
    advance: (ms: number) => (now += ms),
    restore: () => {
      globalThis.fetch = realFetch;
      Date.now = realNow;
    },
  };
}

const ok = () => new Response(JSON.stringify({ mode: "observe", policy: { shapes: {} } }), { status: 200 });
const throttled = (retryAfter?: string) =>
  new Response("{}", { status: 429, headers: retryAfter ? { "retry-after": retryAfter } : {} });

/** Drive N requests through the wrapped handler, as a real app would. */
async function drive(shield: Shield, n: number) {
  const h = shield.handler(() => new Response("ok"));
  for (let i = 0; i < n; i++) await h(new Request(`https://app.test/page/${i}`));
}

Deno.test("one long-lived Shield batches: 24 requests are not 24 ingest POSTs", async () => {
  const t = harness(ok);
  try {
    await drive(t.shield, 24);
    // 1 policy refresh (cold, TTL not yet satisfied) + 1 first-sketch flush. NOT one per request.
    assert(t.calls.length <= 2, `expected <= 2 ingest calls for 24 requests, got ${t.calls.length}`);
  } finally {
    t.restore();
  }
});

Deno.test("the refresh TTL holds across requests (this is what per-request construction broke)", async () => {
  const t = harness(ok, { ttlMs: 3000, flushIntervalMs: 60_000 });
  try {
    await drive(t.shield, 10);
    const afterFirstBurst = t.calls.length;
    t.advance(1000); // still inside the 3s TTL
    await drive(t.shield, 10);
    assertEquals(t.calls.length, afterFirstBurst); // no extra refresh, no extra flush
    t.advance(3500); // TTL expired -> exactly one more refresh
    await drive(t.shield, 1);
    assertEquals(t.calls.length, afterFirstBurst + 1);
  } finally {
    t.restore();
  }
});

Deno.test("a full batch still ships promptly", async () => {
  const t = harness(ok, { ttlMs: 60_000, flushIntervalMs: 60_000 });
  try {
    await drive(t.shield, 60); // 1 cold refresh + 1 first flush + 2 full batches of 25
    const sent = t.calls.filter((c) => c.body !== '{"sketches":[]}');
    assert(sent.length >= 2, `expected batched sends, got ${sent.length}`);
    assert(t.calls.length < 10, `expected batching, got ${t.calls.length} calls for 60 requests`);
  } finally {
    t.restore();
  }
});

Deno.test("a 429 mutes shipping until Retry-After elapses", async () => {
  const t = harness(() => throttled("1"), { ttlMs: 60_000, flushIntervalMs: 0 });
  try {
    await drive(t.shield, 1);
    const afterThrottle = t.calls.length;
    await drive(t.shield, 50); // 50 more requests while muted -> zero further ingest calls
    assertEquals(t.calls.length, afterThrottle);
    t.advance(1100);
    await drive(t.shield, 1);
    assert(t.calls.length > afterThrottle);
  } finally {
    t.restore();
  }
});

Deno.test("a throttled refresh keeps the last-known-good policy (the WAF must not fail open)", async () => {
  // First response installs an enforce policy; every later one is a 429.
  const enforcePolicy = () =>
    new Response(JSON.stringify({ mode: "enforce", policy: { shapes: { nothing: "allow" } } }), { status: 200 });
  const t = harness((n) => (n === 1 ? enforcePolicy() : throttled("60")), { ttlMs: 0 });
  try {
    await drive(t.shield, 1);
    assert(t.shield.enforcing(), "policy should have installed enforce mode");
    await drive(t.shield, 3); // refreshes now get throttled
    assert(t.shield.enforcing(), "a throttled refresh must NOT reset the Shield to observe");
    const res = await t.shield.handler(() => new Response("ok"))(new Request("https://app.test/.env"));
    assertEquals(res.status, 403); // still enforcing off-baseline
  } finally {
    t.restore();
  }
});
