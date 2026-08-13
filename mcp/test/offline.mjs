// Offline functional test: spawn the built stdio server and exercise the tools that need NO network
// (protect, explain, list_frameworks, omniguard_catalog) plus inspect the new nemesis_omniguard_verify
// tool's schema. Network tools (scan, verify, score, create_*) are NOT called here — this stays offline.
//   Run:  npm run build && node test/offline.mjs
import { spawn } from "node:child_process";
import assert from "node:assert/strict";

const child = spawn("node", ["dist/index.js"], { stdio: ["pipe", "pipe", "ignore"] });
const pending = new Map();
let buf = "";
child.stdout.on("data", (d) => {
  buf += d;
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
    if (!line) continue;
    let m; try { m = JSON.parse(line); } catch { continue; }
    if (m.id != null && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  }
});
const send = (o) => child.stdin.write(JSON.stringify(o) + "\n");
let nextId = 1;
const rpc = (method, params) => new Promise((resolve, reject) => {
  const id = nextId++; pending.set(id, resolve);
  setTimeout(() => { if (pending.has(id)) { pending.delete(id); reject(new Error(`timeout: ${method}`)); } }, 12000);
  send({ jsonrpc: "2.0", id, method, params });
});
const callText = (name, args = {}) => rpc("tools/call", { name, arguments: args }).then((m) => (m.result?.content ?? []).map((c) => c.text).join("\n"));

const ok = (label) => console.log(`  \x1b[32m✓\x1b[0m ${label}`);
let failed = 0;
const check = (label, fn) => { try { fn(); ok(label); } catch (e) { failed++; console.log(`  \x1b[31m✗ ${label} — ${e.message}\x1b[0m`); } };

try {
  await rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "offline-test", version: "0" } });
  send({ jsonrpc: "2.0", method: "notifications/initialized" });

  console.log("\n\x1b[1mNemesis Shield MCP — offline functional test\x1b[0m\n");

  // 1) tools/list — count, new tool present, schema + annotation
  const { result } = await rpc("tools/list").then((m) => ({ result: m.result }));
  const tools = result.tools ?? [];
  const names = tools.map((t) => t.name);
  console.log(`Tools exposed (${names.length}): ${names.map((n) => n.replace(/^nemesis_/, "")).join(", ")}\n`);
  check("17 tools registered", () => assert.equal(names.length, 17));
  check("nemesis_omniguard_verify is registered", () => assert.ok(names.includes("nemesis_omniguard_verify")));
  const verify = tools.find((t) => t.name === "nemesis_omniguard_verify");
  check("verify schema has ingestToken + check + subject", () => {
    const p = Object.keys(verify.inputSchema?.properties ?? {});
    for (const k of ["ingestToken", "check", "subject", "lastName"]) assert.ok(p.includes(k), `missing ${k}`);
  });
  check("verify 'check' enum covers identity + AML + breach", () => {
    const en = verify.inputSchema.properties.check.enum ?? [];
    for (const v of ["sanctions_pep", "adverse_media", "bvn", "nin", "passport", "kyb", "breach"]) assert.ok(en.includes(v), `enum missing ${v}`);
  });
  check("verify is annotated as a WRITE tool (confirm-before-run)", () => {
    assert.equal(verify.annotations?.readOnlyHint, false);
    assert.ok(verify.annotations?.title);
  });

  // 2) offline tool calls — real responses, no network
  const cat = await callText("nemesis_omniguard_catalog");
  check("omniguard_catalog advertises the standalone verify checks", () => {
    assert.match(cat, /nemesis_omniguard_verify/);
    assert.match(cat, /sanctions_pep|bvn/);
  });

  const scr = await callText("nemesis_explain", { topic: "screening" });
  console.log(`\n  explain "screening" →\n    ${scr.slice(0, 160)}…\n`);
  check("explain 'screening' returns identity/sanctions guidance", () => assert.match(scr, /sanctions|BVN|verification/i));

  const kyc = await callText("nemesis_explain", { topic: "kyc" });
  check("explain 'kyc' returns identity guidance", () => assert.match(kyc, /identity|BVN|NIN|Passport/i));

  const prot = await callText("nemesis_protect", { framework: "supabase-edge" });
  check("protect 'supabase-edge' emits a real one-line integration", () => assert.match(prot, /withShield|nemesis/i));

  const fw = await callText("nemesis_list_frameworks");
  check("list_frameworks returns the supported set", () => assert.match(fw, /fastapi|express|nextjs/));

  console.log(`\n${failed === 0 ? "\x1b[32mALL OFFLINE CHECKS PASSED\x1b[0m" : `\x1b[31m${failed} CHECK(S) FAILED\x1b[0m`}\n`);
} catch (e) {
  console.error("harness error:", e.message); failed++;
} finally {
  child.kill();
  process.exit(failed === 0 ? 0 : 1);
}
