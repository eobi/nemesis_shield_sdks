// Deep behaviour test — proves the Node SDK SEES an attacker's request from ANY route and blocks it
// in enforce mode: unknown paths, injected/extra query params, param-type / method / auth anomalies,
// and global threat-intel shapes. Also proves the safe-unlock (never block the login/auth path) and
// fail-open (no baseline => nothing blocked). Run: node tests/deep.mjs
import { SentinelClient } from "../lib/client.js";
import { buildSketch } from "../lib/shape.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  \x1b[32m✓\x1b[0m " + m)) : (fail++, console.log("  \x1b[31m✗ " + m + "\x1b[0m")));
const sec = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");

// A client whose policy we control directly (no network) — this is exactly what every adapter holds.
function clientWith({ mode = "enforce", allow = [], knownBad = [], bootstrap } = {}) {
  const c = new SentinelClient({ token: "t", transport: async () => null, mode, bootstrap });
  c._policy = { shapes: Object.fromEntries(allow.map((s) => [s, "allow"])), knownBad };
  c._haveBaseline = allow.length > 0 || knownBad.length > 0;
  return c;
}
const shapeOf = (o) => buildSketch(o).shape;
// The adapter block-path in one call: does this request get blocked?
const blocked = (c, req) =>
  c.mode === "enforce" && !c.neverBlock(req.path) && c.shouldBlock(c.decide(buildSketch(req)));

console.log("\x1b[1mNemesis Shield — Node deep coverage test\x1b[0m");

// The site's learned "normal": home, a product-by-id page, and a search with one alnum query param.
const BASE = [
  { method: "GET", path: "/" },
  { method: "GET", path: "/products/12345" },
  { method: "GET", path: "/search", query: { q: "shoes" } },
  { method: "POST", path: "/api/orders", query: {}, authenticated: true },
];
const allow = BASE.map(shapeOf);

sec("1 · query params actually change the shape (deep, not just route)");
ok(shapeOf({ method: "GET", path: "/search", query: { q: "x" } }) !==
   shapeOf({ method: "GET", path: "/search", query: { q: "x", inject: "1" } }),
   "adding a param (?q&inject) yields a different shape");
ok(shapeOf({ method: "GET", path: "/search", query: { q: "shoes" } }) !==
   shapeOf({ method: "GET", path: "/search", query: { q: "1 OR 1=1" } }),
   "param KIND change (alnum → string payload) yields a different shape");

sec("2 · enforce — attacker requests from ANY route are blocked");
const c = clientWith({ allow });
ok(!blocked(c, { method: "GET", path: "/" }), "approved GET / passes");
ok(!blocked(c, { method: "GET", path: "/products/999" }), "approved GET /products/{int} passes");
ok(!blocked(c, { method: "GET", path: "/search", query: { q: "boots" } }), "approved GET /search?q=<alnum> passes");
ok(blocked(c, { method: "GET", path: "/.env" }), "scanner path /.env blocked");
ok(blocked(c, { method: "GET", path: "/wp-config.php.bak" }), "scanner path /wp-config.php.bak blocked");
ok(blocked(c, { method: "GET", path: "/search", query: { q: "x", cmd: "id" } }), "injected extra param ?cmd=id blocked");
ok(blocked(c, { method: "GET", path: "/search", query: { q: "' OR 1=1--" } }), "SQLi-shaped param (kind change) blocked");
ok(blocked(c, { method: "POST", path: "/" }), "method anomaly POST / blocked");
ok(blocked(c, { method: "GET", path: "/api/orders", authenticated: false }), "auth anomaly (unauth to authed route) blocked");
ok(blocked(c, { method: "GET", path: "/admin/config" }), "unknown /admin/config blocked");

sec("3 · global threat intelligence (knownBad)");
const badShape = shapeOf({ method: "POST", path: "/xmlrpc.php" });
const c2 = clientWith({ allow, knownBad: [badShape] });
ok(blocked(c2, { method: "POST", path: "/xmlrpc.php" }), "knownBad shape blocked by global intel");

sec("4 · safe-unlock — the login/auth path is never blocked");
ok(!blocked(c, { method: "POST", path: "/login", query: { next: "x" } }), "/login never blocked (default bootstrap)");
ok(!blocked(c, { method: "GET", path: "/wp-login.php" }), "/wp-login.php never blocked");
ok(!blocked(c, { method: "GET", path: "/wp-admin/options.php" }), "/wp-admin never blocked");
const cTight = clientWith({ allow, bootstrap: ["/custom-auth"] });
ok(blocked(cTight, { method: "POST", path: "/login" }), "custom bootstrap replaces default (/login now enforced)");
ok(!blocked(cTight, { method: "POST", path: "/custom-auth" }), "custom bootstrap /custom-auth honored");

sec("5 · fail-open — no baseline yet, nothing is blocked");
const cEmpty = clientWith({ allow: [], knownBad: [] });
ok(!blocked(cEmpty, { method: "GET", path: "/.env" }), "off-baseline passes while no baseline exists");

sec("6 · observe mode never blocks");
const cObs = clientWith({ allow, mode: "observe" });
ok(!blocked(cObs, { method: "GET", path: "/.env" }), "observe mode: scanner path recorded, not blocked");

console.log("\n" + "─".repeat(52));
if (fail === 0) { console.log(`\x1b[32m\x1b[1mALL ${pass} CHECKS PASSED\x1b[0m`); process.exit(0); }
console.log(`\x1b[31m\x1b[1m${fail} FAILED\x1b[0m, ${pass} passed`); process.exit(1);
