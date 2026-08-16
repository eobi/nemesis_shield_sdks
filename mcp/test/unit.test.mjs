// Unit tests for the pure logic of the Nemesis MCP server. No network, no credentials.
//   Run:  npm run build && node --test
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";

import { resolveFramework, protectText, suggestFramework, frameworkList } from "../dist/frameworks.js";
import { SECTORS, EVENTS, suggestOmniguard, omniguardCatalog } from "../dist/omniguard.js";
import { redact, paymentMessage } from "../dist/client.js";
import { explainText, explainTopics } from "../dist/explain.js";

test("frameworks: resolveFramework handles names + aliases + unknowns", () => {
  assert.equal(resolveFramework("fastapi"), "fastapi");
  assert.equal(resolveFramework("FastAPI"), "fastapi");
  assert.equal(resolveFramework("next"), "nextjs");
  assert.equal(resolveFramework("asp.net"), "aspnet");
  assert.equal(resolveFramework("react"), "browser");
  assert.equal(resolveFramework("prompt-injection"), "llm");
  assert.equal(resolveFramework("nonsense-xyz"), null);
});

test("frameworks: protectText emits the verified install line, never invents one", () => {
  const fa = protectText("fastapi");
  assert.match(fa, /pip install nemesis-shield/);
  assert.match(fa, /SentinelMiddleware/);
  assert.match(fa, /NEMESIS_TOKEN/);
  const ex = protectText("express");
  assert.match(ex, /@nemesis-shield-autogon\/sentinel/);
  // Unknown stack lists the supported set instead of hallucinating.
  const unknown = protectText("cobol");
  assert.match(unknown, /supports/);
  assert.ok(frameworkList().length >= 13);
});

test("frameworks: suggestFramework maps detected tech to a protect key", () => {
  assert.equal(suggestFramework(["Next.js", "Cloudflare"]), "nextjs");
  assert.equal(suggestFramework(["Django"]), "django");
  assert.equal(suggestFramework(["Laravel"]), "laravel");
  assert.equal(suggestFramework(["Nothing", "Recognizable"]), null);
});

test("omniguard: catalog + sector/event suggestion is personalized", () => {
  assert.ok(SECTORS.find((s) => s.key === "ecommerce"));
  assert.ok(SECTORS.find((s) => s.key === "fintech"));
  assert.ok(EVENTS.checkout && EVENTS.transfer);
  assert.deepEqual(suggestOmniguard("I'm building an ecommerce checkout"), { industry: "ecommerce", event: "checkout" });
  const ft = suggestOmniguard("a fintech transfer API");
  assert.equal(ft.industry, "fintech");
  assert.equal(ft.event, "transfer");
  assert.match(omniguardCatalog(), /checkout/);
  assert.match(omniguardCatalog(), /transfer/);
  // the catalog now advertises the standalone verify/screening checks (0.2.6)
  assert.match(omniguardCatalog(), /nemesis_omniguard_verify/);
  assert.match(omniguardCatalog(), /sanctions_pep|bvn/);
});

test("client: redact scrubs tokens; paymentMessage handles 402", () => {
  assert.match(redact("token nsk_deadbeefdeadbeefdeadbeef here"), /nsk_…/);
  assert.doesNotMatch(redact("nsk_deadbeefdeadbeefdeadbeef"), /deadbeef/);
  assert.match(redact("Authorization: Bearer abc.def.ghi"), /Bearer …/);
  assert.equal(paymentMessage({ ok: true, status: 200 }), null);
  const pay = paymentMessage({ ok: false, status: 402, data: { detail: "Reports are a Pro feature.", url: "https://shield.nemesislabs.xyz/app/billing" } });
  assert.match(pay, /Pro feature/);
  assert.match(pay, /shield\.nemesislabs\.xyz\/app\/billing/);
  // 402 with no url falls back to the billing page.
  assert.match(paymentMessage({ ok: false, status: 402, data: {} }), /app\/billing/);
});

test("explain: known topics answer; unknown lists topics", () => {
  assert.match(explainText("idor"), /IDOR|BOLA/);
  assert.match(explainText("prompt-injection"), /prompt injection/i);
  assert.match(explainText("business-logic"), /Omniguard/);
  // new screening/KYC/AML topics (0.2.6)
  assert.match(explainText("screening"), /sanctions|BVN|verification/i);
  assert.match(explainText("kyc"), /identity|BVN|NIN|Passport/i);
  assert.match(explainText("aml"), /sanctions|screening|structuring|goAML/i);
  assert.ok(explainTopics().includes("screening"));
  assert.ok(explainTopics().includes("positive-security"));
  assert.match(explainText("totally-unknown-topic"), /Topics I can explain/);
});

// Integration: spawn the built stdio server and assert the full tool set is exposed.
test("stdio: server lists all tools", async () => {
  const tools = await new Promise((resolve, reject) => {
    const child = spawn("node", ["dist/index.js"], { stdio: ["pipe", "pipe", "ignore"] });
    let buf = "";
    const to = setTimeout(() => { child.kill(); reject(new Error("timeout")); }, 15000);
    child.stdout.on("data", (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (!line) continue;
        let m;
        try { m = JSON.parse(line); } catch { continue; }
        if (m.id === 2) { clearTimeout(to); child.kill(); resolve(m.result?.tools ?? []); }
      }
    });
    const send = (o) => child.stdin.write(JSON.stringify(o) + "\n");
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "test", version: "0" } } });
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  });
  const names = tools.map((t) => t.name);
  for (const name of [
    "nemesis_protect", "nemesis_scan", "nemesis_explain", "nemesis_list_frameworks",
    "nemesis_create_app", "nemesis_list_apps", "nemesis_set_mode",
    "nemesis_provision_edge", "nemesis_edge_status", "nemesis_protect_llm",
    "nemesis_create_omniguard", "nemesis_omniguard_catalog", "nemesis_omniguard_score", "nemesis_omniguard_verify", "nemesis_omniguard_screen",
    "nemesis_omniguard_outcome", "nemesis_omniguard_flag", "nemesis_approve_routes", "nemesis_run_learn", "nemesis_server_agent",
  ]) {
    assert.ok(names.includes(name), `missing tool: ${name}`);
  }
  assert.equal(names.length, 20, `expected 20 tools, got ${names.length}`);
  // the new verify tool exposes the right input schema (check + subject + ingestToken)
  const verify = tools.find((t) => t.name === "nemesis_omniguard_verify");
  assert.ok(verify, "nemesis_omniguard_verify not registered");
  const props = Object.keys(verify.inputSchema?.properties ?? {});
  for (const p of ["ingestToken", "check", "subject"]) assert.ok(props.includes(p), `verify missing param: ${p}`);
  // the FREE sanctions/PEP screening tool: a plain {ingestToken, name} call, read-only, framed as free
  const screen = tools.find((t) => t.name === "nemesis_omniguard_screen");
  assert.ok(screen, "nemesis_omniguard_screen not registered");
  const sprops = Object.keys(screen.inputSchema?.properties ?? {});
  for (const p of ["ingestToken", "name"]) assert.ok(sprops.includes(p), `screen missing param: ${p}`);
  assert.ok(!sprops.includes("check"), "screen must not expose a check selector (screening-only)");
  assert.equal(screen.annotations?.readOnlyHint, true, "screen should be read-only (safe to auto-run)");
  assert.match(screen.description, /FREE/, "screen description should state it is FREE");
  // outcome: report a scored transaction's true label (fraud/chargeback/legit) — a write, not read-only
  const outcome = tools.find((t) => t.name === "nemesis_omniguard_outcome");
  assert.ok(outcome, "nemesis_omniguard_outcome not registered");
  const oprops = Object.keys(outcome.inputSchema?.properties ?? {});
  for (const p of ["ingestToken", "outcome"]) assert.ok(oprops.includes(p), `outcome missing param: ${p}`);
  assert.equal(outcome.annotations?.readOnlyHint, false, "outcome writes data — not read-only");
  // flag: entity risk-flag (recon -> cash-out) — a write with entityType + flag
  const flag = tools.find((t) => t.name === "nemesis_omniguard_flag");
  assert.ok(flag, "nemesis_omniguard_flag not registered");
  const fprops = Object.keys(flag.inputSchema?.properties ?? {});
  for (const p of ["ingestToken", "entityType", "entityValue", "flag"]) assert.ok(fprops.includes(p), `flag missing param: ${p}`);
  assert.equal(flag.annotations?.readOnlyHint, false, "flag writes data — not read-only");
  // every tool carries advisory annotations (a title + a readOnlyHint) for client permission UX
  for (const t of tools) {
    assert.ok(t.annotations?.title, `tool ${t.name} missing annotation title`);
    assert.equal(typeof t.annotations?.readOnlyHint, "boolean", `tool ${t.name} missing readOnlyHint`);
  }
});
