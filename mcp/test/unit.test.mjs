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
        if (m.id === 2) { clearTimeout(to); child.kill(); resolve((m.result?.tools ?? []).map((t) => t.name)); }
      }
    });
    const send = (o) => child.stdin.write(JSON.stringify(o) + "\n");
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "test", version: "0" } } });
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  });
  for (const name of [
    "nemesis_protect", "nemesis_scan", "nemesis_explain", "nemesis_list_frameworks",
    "nemesis_create_app", "nemesis_list_apps", "nemesis_set_mode",
    "nemesis_provision_edge", "nemesis_edge_status", "nemesis_protect_llm",
    "nemesis_create_omniguard", "nemesis_omniguard_catalog", "nemesis_omniguard_score", "nemesis_approve_routes", "nemesis_run_learn", "nemesis_server_agent",
  ]) {
    assert.ok(tools.includes(name), `missing tool: ${name}`);
  }
});
