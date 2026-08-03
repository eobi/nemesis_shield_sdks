#!/usr/bin/env node
// Nemesis Learn — exercise every route of your app (dev/staging) so Nemesis Shield's behavioral model
// finishes learning fast, ready to enforce. Language/framework-agnostic (HTTP-level), runs offline,
// optionally discovers routes from a repo. Zero dependencies.

import { writeFileSync, readFileSync, mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { Session } from "./http.mjs";
import { makeLlm } from "./llm.mjs";
import { discoverOpenApi, crawl, discoverRepo, mergeEndpoints } from "./discover.mjs";
import { login, runExercise } from "./exercise.mjs";
import { buildReport, printSummary } from "./report.mjs";

const out = (s) => process.stdout.write(s + "\n");
const VERSION = (() => { try { return JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version; } catch { return "0"; } })();
const DEFAULT_SHIELD = "https://shield.nemesislabs.xyz";

function parseArgs(argv) {
  const a = { headers: {} };
  for (let i = 0; i < argv.length; i++) {
    let k = argv[i];
    if (!k.startsWith("--")) continue;
    let v;
    if (k.includes("=")) { [k, v] = [k.slice(0, k.indexOf("=")), k.slice(k.indexOf("=") + 1)]; }
    else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) v = argv[++i];
    else v = true;
    k = k.slice(2);
    if (k === "header") { const idx = String(v).indexOf(":"); if (idx > 0) a.headers[String(v).slice(0, idx).trim()] = String(v).slice(idx + 1).trim(); }
    else a[k] = v;
  }
  return a;
}

const HELP = `
Nemesis Learn — build your app's behavioral baseline, fast.

Usage:
  nemesis-learn --target <url> [options]

Core:
  --target <url>          Your running dev/staging app (e.g. http://localhost:3000)   [required]
  --repo <path|git-url>   Also discover routes from source code (any language)
  --out <file>            Write the JSON coverage report (default: nemesis-learn-report.json)

LLM (optional — makes generated inputs realistic; without it, schema/heuristics are used):
  --llm-provider <p>      openai | anthropic | ollama
  --llm-key <key>         API key (or env OPENAI_API_KEY / ANTHROPIC_API_KEY / LLM_API_KEY)
  --llm-model <model>     Override the default model
  --llm-base <url>        Override the API base (e.g. an Ollama host for fully-offline runs)

Auth (so protected routes are learned too):
  --login-url <url>       Login endpoint (absolute, or path on --target)
  --login-body <json>     JSON credentials, e.g. '{"email":"you@app.com","password":"..."}'
  --login-method <m>      Default POST
  --header "K: V"         Extra sticky header (repeatable), e.g. an API key

Report to Shield (so the portal shows baseline readiness + the enforce gate):
  --app-token <nsk_…>     Your app's Nemesis Shield token — posts coverage back to the app
  --report-to <url>       Shield base URL (default https://shield.nemesislabs.xyz)

Tuning:
  --max <n>               Max requests (default 500)
  --concurrency <n>       Parallel requests (default 4)
  --delay <ms>            Delay between requests (default 0)
  --timeout <ms>          Per-request timeout (default 15000)
  --max-pages <n>         Crawl page cap (default 40)
  --no-openapi            Skip OpenAPI discovery
  --no-crawl              Skip HTML crawling

Examples:
  nemesis-learn --target http://localhost:3000
  nemesis-learn --target http://localhost:8000 --repo . --llm-provider openai --llm-key sk-...
  nemesis-learn --target http://localhost:5000 --login-url /api/login \\
    --login-body '{"email":"dev@acme.com","password":"devpass"}'
  nemesis-learn --target http://localhost:3000 --app-token nsk_live_… --repo .
`;

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || (!args.target && !process.env.NEMESIS_LEARN_TARGET)) { out(HELP); process.exit(args.help ? 0 : 1); }

  const target = String(args.target || process.env.NEMESIS_LEARN_TARGET).replace(/\/$/, "");
  try { new URL(target); } catch { out(`Invalid --target: ${target}`); process.exit(1); }

  const config = {
    maxRequests: num(args.max, 500),
    concurrency: num(args.concurrency, 4),
    delayMs: num(args.delay, 0),
    timeoutMs: num(args.timeout, 15000),
    maxPages: num(args["max-pages"], 40),
    loginUrl: args["login-url"],
    loginBody: args["login-body"],
    loginMethod: args["login-method"],
  };
  const llmKey = args["llm-key"] || process.env.OPENAI_API_KEY || process.env.ANTHROPIC_API_KEY || process.env.LLM_API_KEY;
  const llm = args["llm-provider"] ? makeLlm({ provider: args["llm-provider"], apiKey: llmKey, model: args["llm-model"], baseUrl: args["llm-base"] }) : null;

  const session = new Session();
  Object.assign(session.headers, args.headers);

  out(`\n  Nemesis Learn · target ${target}${llm ? ` · llm ${llm.provider}/${llm.model}` : " · llm off (heuristics)"}\n`);
  const startedAt = new Date().toISOString();

  // 1) discover
  out("  Discovering routes…");
  let discovered = [];
  if (!args["no-openapi"]) {
    const oa = await discoverOpenApi(target, session);
    if (oa.endpoints.length) out(`    openapi   ${oa.endpoints.length} operations  (${oa.specUrl})`);
    discovered = mergeEndpoints(discovered, oa.endpoints);
  }
  if (!args["no-crawl"]) {
    const cr = await crawl(target, session, { maxPages: config.maxPages });
    if (cr.endpoints.length) out(`    crawl     ${cr.endpoints.length} routes  (${cr.pages} pages)`);
    discovered = mergeEndpoints(discovered, cr.endpoints);
  }
  if (args.repo) {
    const dir = await resolveRepo(String(args.repo));
    if (dir) { const rp = discoverRepo(dir); out(`    repo      ${rp.endpoints.length} routes  (${rp.filesScanned} files)`); discovered = mergeEndpoints(discovered, rp.endpoints); }
  }
  if (!discovered.length) { out("\n  No routes discovered. Is the target reachable? Try --repo <path> or --no-crawl off, and check --target.\n"); process.exit(2); }
  out(`  Discovered ${discovered.length} unique routes.\n`);

  // 2) auth
  if (config.loginUrl) { out("  Authenticating…"); await login(target, session, config, out); out(""); }

  // 3) exercise
  out(`  Exercising up to ${Math.min(config.maxRequests, discovered.length)} routes (${config.concurrency} parallel)…`);
  const results = await runExercise({ endpoints: discovered, base: target, session, config, llm, log: out });

  // 4) report
  const finishedAt = new Date().toISOString();
  const report = buildReport({ target, discovered, results, startedAt, finishedAt });
  const outFile = String(args.out || "nemesis-learn-report.json");
  try { writeFileSync(outFile, JSON.stringify(report, null, 2)); } catch { /* non-fatal */ }
  printSummary(report, out);
  out(`  Full report → ${outFile}\n`);

  // 5) report coverage back to Shield (optional) — lets the portal show baseline readiness and the
  // "ready to enforce" gate on your app. Fail-open: a reporting hiccup never fails the run.
  const appToken = args["app-token"] || process.env.NEMESIS_SHIELD_TOKEN;
  if (appToken) {
    const shieldBase = String(args["report-to"] || process.env.NEMESIS_SHIELD_URL || DEFAULT_SHIELD).replace(/\/$/, "");
    await reportCoverage(shieldBase, String(appToken), report, out);
  }
}

async function reportCoverage(base, token, rep, log) {
  // Shapes only — method + route template + status. No payloads, no concrete URLs.
  const payload = {
    discovered: rep.discovered.total,
    exercised: rep.exercised.total,
    reached: rep.reachedServer,
    coveragePct: rep.coveragePct,
    uploads: rep.exercised.uploads,
    errors: rep.errors.length,
    bySource: rep.discovered.bySource,
    routes: rep.requests.slice(0, 1000).map((r) => ({ method: r.method, path: r.path, status: r.status || 0 })),
    tool: "nemesis-learn",
    toolVersion: VERSION,
  };
  const url = `${base}/api/v1/learn/coverage`;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 15000);
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    }).finally(() => clearTimeout(t));
    const j = await res.json().catch(() => ({}));
    if (!res.ok || j?.error) {
      const why = j?.error === "invalid_token" ? "app token not recognized" : (j?.error || `HTTP ${res.status}`);
      log(`  Shield: coverage not recorded (${why}). Your local report above is still valid.`);
      return;
    }
    const b = j.behaviors || {};
    log(`  Shield: baseline recorded for "${j.app}" — ${b.total || 0} behaviors learned · ${b.inReview || 0} in review · ${b.approved || 0} approved.`);
    log(`  Open Shield → ${j.app || "your app"} → Baseline readiness to approve and flip to ENFORCE.`);
  } catch (e) {
    log(`  Shield: could not reach ${base} (${e?.name === "AbortError" ? "timed out" : e?.message || e}). Your local report above is still valid.`);
  }
}

async function resolveRepo(repo) {
  if (existsSync(repo)) return repo;
  if (/^(https?:\/\/|git@)/.test(repo)) {
    try {
      const dir = mkdtempSync(join(tmpdir(), "nemesis-learn-"));
      out(`    cloning ${repo} …`);
      execFileSync("git", ["clone", "--depth", "1", repo, dir], { stdio: "ignore" });
      return dir;
    } catch { out("    (could not clone repo — skipping repo discovery)"); return null; }
  }
  out(`    (repo path not found: ${repo})`);
  return null;
}

const num = (v, d) => { const n = Number(v); return Number.isFinite(n) ? n : d; };

main().catch((e) => { out(`\n  Error: ${e?.stack || e}\n`); process.exit(1); });
