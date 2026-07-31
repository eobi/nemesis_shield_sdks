// Deep coverage + cross-language PARITY test for the edge SDK. Proves (a) its shape hashes are now
// byte-for-byte identical to the backend family (same reference values as the Rust/Node parity tests),
// (b) it feeds query params, (c) it blocks attacks from any route in enforce mode, plus safe-unlock
// and fail-open. Run:  deno test edge/tests/deep.ts
import { Shield, neverBlock } from "../nemesis-shield.ts";
import { assert, assertEquals } from "jsr:@std/assert@1";

const s = new Shield({});
type Q = Record<string, string | string[]>;
function split(url: string): [string, Q] {
  const [p, qs] = url.split("?");
  const q: Q = {};
  if (qs) for (const pair of qs.split("&")) { const [k, v = ""] = pair.split("="); q[k] = v; }
  return [p, q];
}
const shape = (m: string, url: string, a = false) => { const [p, q] = split(url); return s.buildSketch(m, p, q, a, 0).shape; };

// A Shield whose policy we set directly (no network) — exactly what the handler holds at runtime.
function client(mode: string, allow: string[], knownBad: string[] = []) {
  const c = new Shield({}) as any;
  c.mode = mode;
  c.shapes = Object.fromEntries(allow.map((x) => [x, "allow"]));
  c.knownBad = new Set(knownBad);
  c.haveBaseline = allow.length > 0 || knownBad.length > 0;
  return c as Shield;
}
function blocked(c: any, m: string, url: string, a = false): boolean {
  const [p, q] = split(url);
  if (!c.enforcing() || neverBlock(p)) return false;
  return c.decide(c.buildSketch(m, p, q, a, 0).shape) != null;
}

Deno.test("cross-language parity — identical reference hashes to Rust/Node backend family", () => {
  assertEquals(shape("GET", "/orders/123"), "3e8cf0b3");                    // matches rust/lib.rs + node
  assertEquals(shape("GET", "/orders/123?expand=items"), "440c7e37");       // query IS in the shape now
});

Deno.test("query params change the shape (deep, not just route)", () => {
  assert(shape("GET", "/search?q=x") !== shape("GET", "/search?q=x&inject=1"));
  assert(shape("GET", "/search?q=shoes") !== shape("GET", "/search?q=%27"));
});

Deno.test("enforce — attacks from ANY route blocked, approved passes", () => {
  const allow = [
    shape("GET", "/"),
    shape("GET", "/products/12345"),
    shape("GET", "/search?q=shoes"),
    shape("POST", "/api/orders", true),
  ];
  const c = client("enforce", allow);
  assert(!blocked(c, "GET", "/"));
  assert(!blocked(c, "GET", "/products/999"));
  assert(!blocked(c, "GET", "/search?q=boots"));
  assert(!blocked(c, "POST", "/api/orders", true));
  assert(blocked(c, "GET", "/.env"));
  assert(blocked(c, "GET", "/wp-config.php.bak"));
  assert(blocked(c, "GET", "/search?q=x&cmd=id"));   // injected param
  assert(blocked(c, "POST", "/"));                    // method anomaly
  assert(blocked(c, "GET", "/api/orders"));           // auth anomaly
  assert(blocked(c, "GET", "/admin/config"));
  // knownBad
  const bad = shape("POST", "/xmlrpc.php");
  assert(blocked(client("enforce", allow, [bad]), "POST", "/xmlrpc.php"));
});

Deno.test("safe-unlock + fail-open + observe", () => {
  const allow = [shape("GET", "/")];
  const c = client("enforce", allow);
  assert(!blocked(c, "POST", "/login?next=x"));
  assert(!blocked(c, "GET", "/wp-login.php"));
  assert(!blocked(c, "GET", "/wp-admin/options.php"));
  assert(!blocked(client("enforce", []), "GET", "/.env"));       // fail-open, no baseline
  assert(!blocked(client("observe", allow), "GET", "/.env"));    // observe never blocks
});
