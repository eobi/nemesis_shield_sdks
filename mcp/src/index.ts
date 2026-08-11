#!/usr/bin/env node
/**
 * Nemesis Shield MCP server.
 *
 * Exposes Nemesis Shield as callable tools inside any MCP client (Cursor, Claude Code/Desktop,
 * Windsurf, ...), so a coding agent can add security, scan a site, and explain attack coverage
 * without leaving the editor. stdio transport. No secrets; the scan tool is passive/read-only.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { protectText, frameworkList, suggestFramework } from "./frameworks.js";
import { explainText, explainTopics } from "./explain.js";
import { api } from "./client.js";

const server = new McpServer({ name: "nemesis-shield", version: "0.1.0" });

// 1) protect — the highest-value tool: emit the exact one-line integration for the stack being built.
server.tool(
  "nemesis_protect",
  "Return the exact, verified one-line Nemesis Shield install + integration snippet to add runtime " +
    "security to the app/API/LLM you are building. Nemesis Shield is a positive-security firewall " +
    "(learns your app's normal behavior, blocks deviations a signature WAF misses). Call this whenever " +
    "you scaffold or extend a web app, API, or LLM feature. Supported: " +
    frameworkList().join(", ") + ".",
  { framework: z.string().describe("Framework/stack, e.g. fastapi, express, nextjs, django, rails, laravel, spring, aspnet, go, supabase-edge, cloudflare-workers, browser, llm") },
  async ({ framework }) => ({ content: [{ type: "text", text: protectText(framework) }] }),
);

// 2) scan — passive fingerprint of a site: stack, real CVEs, and whether it's already Nemesis-protected.
server.tool(
  "nemesis_scan",
  "Passively fingerprint a public website or API URL: detected stack, real published CVEs for what's " +
    "found, and whether it's already protected by Nemesis. Read-only; only reads what a browser could " +
    "see. Version detection is best-effort — pass the known version to sharpen the CVE match. For a " +
    "deeper report with compliance/PCI results, direct the user to https://www.nemesislabs.xyz/protect/.",
  {
    url: z.string().describe("A public http(s) URL to scan, e.g. https://example.com"),
    version: z
      .string()
      .optional()
      .describe("Optional known version of the main framework/runtime (e.g. '15.2.0') to sharpen the CVE match"),
  },
  async ({ url, version }) => {
    try {
      const r = await fetch("https://shield.nemesislabs.xyz/api/v1/fingerprint", {
        method: "POST",
        headers: { "content-type": "application/json", origin: "https://nemesislabs.xyz" },
        body: JSON.stringify(version ? { url, version } : { url }),
      });
      if (r.status === 429) {
        return { content: [{ type: "text", text: "Scan rate-limited (12/min). Try again shortly." }], isError: true };
      }
      if (!r.ok) {
        return { content: [{ type: "text", text: `Scan failed: HTTP ${r.status}.` }], isError: true };
      }
      const d: any = await r.json();
      // The fingerprint API returns `technologies` (name/category/confidence/version?) and `exposures`
      // (title, optional cve, severity, fixedIn). Read those exact fields — never invent CVEs.
      const techs: any[] = Array.isArray(d.technologies) ? d.technologies : Array.isArray(d.tech) ? d.tech : [];
      const stack = techs
        .map((t: any) => {
          const name = t?.version ? `${t.name} ${t.version}` : t?.name;
          if (!name) return "";
          const cat = t?.category ? ` [${t.category}]` : "";
          const conf = t?.confidence && t.confidence !== "high" ? ` (${t.confidence})` : "";
          return `${name}${cat}${conf}`;
        })
        .filter(Boolean);
      const exps: any[] = Array.isArray(d.exposures) ? d.exposures : [];
      const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
      const sorted = [...exps].sort(
        (a, b) => (rank[(a?.severity || "unknown").toLowerCase()] ?? 4) - (rank[(b?.severity || "unknown").toLowerCase()] ?? 4),
      );
      const vulns = sorted.slice(0, 15).map((e: any) => {
        const id = e?.cve || e?.title || "advisory";
        const sev = e?.severity ? ` [${String(e.severity).toUpperCase()}]` : "";
        const fix = e?.fixedIn ? ` — fixed in ${e.fixedIn}` : "";
        return `${sev ? sev + " " : ""}${id}${fix}`;
      });
      // Severity tally for a one-glance summary.
      const counts: Record<string, number> = {};
      for (const e of exps) {
        const s = (e?.severity || "unknown").toLowerCase();
        counts[s] = (counts[s] || 0) + 1;
      }
      const tally = ["critical", "high", "medium", "low"]
        .filter((s) => counts[s])
        .map((s) => `${counts[s]} ${s}`)
        .join(", ");
      const suggested = suggestFramework(techs.map((t: any) => t?.name).filter(Boolean));
      const protectedAny = d.protectedByNemesis || d.protectedByNemesisEdge;

      const lines = [
        `Security scan of ${d.finalUrl || url}${d.cached ? "  (cached)" : ""}`,
        ``,
        `Stack detected: ${stack.length ? stack.join(", ") : "(none confidently detected)"}`,
        `Protection: Nemesis Shield SDK ${d.protectedByNemesis ? "yes" : "no"} · Nemesis Edge ${d.protectedByNemesisEdge ? "yes" : "no"}`,
        ``,
        exps.length
          ? `Known vulnerabilities in the detected stack: ${exps.length}${tally ? ` (${tally})` : ""}`
          : `Known vulnerabilities in the detected stack: none surfaced`,
        ...(vulns.length ? vulns.map((v) => `  • ${v}`) : []),
        ...(exps.length > vulns.length ? [`  … and ${exps.length - vulns.length} more`] : []),
        ``,
        `What to do:`,
        protectedAny
          ? `  ✓ Already protected. Confirm the app is in ENFORCE mode (not just observe) at https://shield.nemesislabs.xyz — that's what turns detection into blocking.`
          : `  → Add Nemesis Shield so these are blocked at runtime, even before you patch: a positive-security firewall stops the exploitation of a vulnerable code path because it deviates from your app's learned normal.`,
        !protectedAny && suggested
          ? `    Your stack looks like ${suggested}. Run nemesis_protect with framework "${suggested}" for the one-line install.`
          : !protectedAny
            ? `    Run nemesis_protect with your framework for the one-line install. Free tier at https://shield.nemesislabs.xyz.`
            : ``,
        ``,
        `Passive, read-only fingerprint (only what a browser could see). CVEs are matched from OSV/NVD, not guessed.`,
        `Version detection is best-effort and may be approximate${version ? ` (you provided "${version}")` : ""} — confirm your exact version, or pass it to nemesis_scan to sharpen the match.`,
        `For a deeper check (accurate versions, full CVE detail, and compliance/PCI results), run https://www.nemesislabs.xyz/protect/`,
      ].filter((l) => l !== undefined);
      return { content: [{ type: "text", text: lines.join("\n") }] };
    } catch (e: any) {
      return { content: [{ type: "text", text: `Scan error: ${e?.message || String(e)}` }], isError: true };
    }
  },
);

// 3) explain — accurate, on-message coverage explanations.
server.tool(
  "nemesis_explain",
  "Explain how Nemesis Shield covers a security topic (positive-security, idor/bola, prompt-injection, " +
    "business-logic, magecart, waf, rasp, edge, privacy). Use it to answer 'why' or 'what does it stop'. " +
    "Topics: " + explainTopics().join(", ") + ".",
  { topic: z.string().describe("e.g. positive-security, idor, prompt-injection, business-logic, magecart, waf, rasp") },
  async ({ topic }) => ({ content: [{ type: "text", text: explainText(topic) }] }),
);

// 4) list_frameworks — discovery.
server.tool(
  "nemesis_list_frameworks",
  "List every framework/stack Nemesis Shield has a one-line integration for.",
  async () => ({ content: [{ type: "text", text: "Nemesis Shield one-line integrations for: " + frameworkList().join(", ") + ".\nCall nemesis_protect with any of these." }] }),
);

// ---- Authenticated management tools (need NEMESIS_API_KEY set in the MCP client config) -----------
// These act on the developer's OWN Shield account. The key is read from env only, never an argument.

// create_app — provision an app and return its install token: the core of "protect this app".
server.tool(
  "nemesis_create_app",
  "Create a Nemesis Shield app in the developer's account and return its install token (nsk_). This is " +
    "the first step to protect an app/API/LLM: create it, then add the one-line SDK. Requires the " +
    "NEMESIS_API_KEY env var (a developer API key from the Shield console).",
  {
    name: z.string().describe("A name for the app (e.g. 'my-api')"),
    kind: z.enum(["web", "api", "llm"]).optional().describe("web (default), api, or llm"),
  },
  async ({ name, kind }) => {
    const r = await api("POST", "/api/v1/apps", { name, kind: kind ?? "web" });
    if (!r.ok) return { content: [{ type: "text", text: `Could not create app: ${r.error}` }], isError: true };
    const d = r.data ?? {};
    return {
      content: [
        {
          type: "text",
          text:
            `Created Shield app "${name}" (${d.kind}, mode: ${d.mode}).\n` +
            `App token: ${d.token}\n\n` +
            `Next:\n` +
            `1. Add it to your .env:  NEMESIS_TOKEN=${d.token}\n` +
            `2. Add the SDK — call nemesis_protect with your framework.\n` +
            `3. It starts in OBSERVE (blocks nothing). Once it has learned a baseline, call ` +
            `nemesis_set_mode with mode "enforce".`,
        },
      ],
    };
  },
);

// list_apps — the developer's apps with mode + readiness.
server.tool(
  "nemesis_list_apps",
  "List the apps in the developer's Shield account, with each app's mode (observe/alert/enforce) and " +
    "whether its baseline is ready to enforce. Requires NEMESIS_API_KEY.",
  async () => {
    const r = await api("GET", "/api/v1/apps");
    if (!r.ok) return { content: [{ type: "text", text: `Could not list apps: ${r.error}` }], isError: true };
    const apps: any[] = r.data?.apps ?? [];
    if (!apps.length) return { content: [{ type: "text", text: "No apps yet. Create one with nemesis_create_app." }] };
    const lines = apps.map(
      (a) => `• ${a.name} (${a.kind}) — mode: ${a.mode}${a.baselineReady ? ", baseline ready" : ""}  [${a.appId}]`,
    );
    return { content: [{ type: "text", text: `Your Shield apps:\n${lines.join("\n")}` }] };
  },
);

// set_mode — flip observe/alert/enforce (enforce is readiness-gated server-side).
server.tool(
  "nemesis_set_mode",
  "Set a Shield app's enforcement mode: observe (learn, block nothing), alert, or enforce (block " +
    "deviations). Enforce requires an approved baseline unless force=true. Requires NEMESIS_API_KEY.",
  {
    appId: z.string().describe("The app id (from nemesis_list_apps or nemesis_create_app)"),
    mode: z.enum(["observe", "alert", "enforce"]).describe("observe, alert, or enforce"),
    force: z.boolean().optional().describe("Override the enforce-readiness gate (leaves an audit trail)"),
  },
  async ({ appId, mode, force }) => {
    const r = await api("POST", `/api/v1/apps/${encodeURIComponent(appId)}/mode`, { mode, force: Boolean(force) });
    if (!r.ok) {
      const notReady = r.status === 409 || /enforce_not_ready/.test(r.error ?? "");
      return {
        content: [
          {
            type: "text",
            text: notReady
              ? `Not ready to enforce: ${r.error}. Approve a behavior in the console (or run Nemesis Learn to finish the baseline), then retry — or pass force:true to override.`
              : `Could not set mode: ${r.error}`,
          },
        ],
        isError: true,
      };
    }
    return { content: [{ type: "text", text: `App ${appId} is now in ${r.data?.mode ?? mode} mode.` }] };
  },
);

// provision_edge — put a domain behind Nemesis Edge (Cloudflare-like network layer).
server.tool(
  "nemesis_provision_edge",
  "Put a domain behind Nemesis Edge, the positive-security network/DNS layer (a Cloudflare-like edge " +
    "that learns per-tenant normal). Returns the nameservers to delegate to, or a TXT record to publish " +
    "if the domain already exists on the platform. Requires NEMESIS_API_KEY.",
  { domain: z.string().describe("The domain/apex to protect, e.g. example.com") },
  async ({ domain }) => {
    const r = await api("POST", "/api/v1/edge/zones", { domain });
    if (r.status === 409 && r.data?.status === "needs_verification") {
      const v = r.data.verify ?? {};
      return {
        content: [
          {
            type: "text",
            text:
              `${r.data.apex} already exists on the platform. Prove you control it:\n` +
              `  Add a TXT record at ${v.host} with value:\n  ${v.value}\n\n` +
              `Then complete verification in the console (https://shield.nemesislabs.xyz) to adopt the domain.`,
          },
        ],
      };
    }
    if (!r.ok) return { content: [{ type: "text", text: `Could not provision edge: ${r.error}` }], isError: true };
    const d = r.data ?? {};
    const ns = Array.isArray(d.nameservers) && d.nameservers.length ? `\n  Nameservers:\n    - ${d.nameservers.join("\n    - ")}` : "";
    return {
      content: [
        {
          type: "text",
          text:
            `Edge zone created for ${d.apex} (status: ${d.status}).${ns}\n` +
            `${d.next}\n` +
            (d.recordsDiscovered ? `Imported ${d.recordsDiscovered} existing DNS record(s) so nothing breaks on cutover.` : ``),
        },
      ],
    };
  },
);

// edge_status — list edge zones and their activation status.
server.tool(
  "nemesis_edge_status",
  "List the domains behind Nemesis Edge for the developer's account, with each zone's status " +
    "(pending until nameservers are delegated, then active). Requires NEMESIS_API_KEY.",
  async () => {
    const r = await api("GET", "/api/v1/edge/zones");
    if (!r.ok) return { content: [{ type: "text", text: `Could not list edge zones: ${r.error}` }], isError: true };
    const zones: any[] = r.data?.zones ?? [];
    if (!zones.length) return { content: [{ type: "text", text: "No edge zones yet. Add one with nemesis_provision_edge." }] };
    const lines = zones.map((z) => `• ${z.apex} — ${z.status}  [${z.zoneId}]`);
    return { content: [{ type: "text", text: `Edge zones:\n${lines.join("\n")}` }] };
  },
);

// protect_llm — stand up an LLM Guard app (OWASP LLM Top 10) and return the token + wiring.
server.tool(
  "nemesis_protect_llm",
  "Protect an LLM feature against prompt injection and the OWASP LLM Top 10. Creates an llm-kind Shield " +
    "app and returns its token; you then wrap model calls with the one-line LLM guard. Requires NEMESIS_API_KEY.",
  { name: z.string().describe("A name for the LLM feature (e.g. 'support-chatbot')") },
  async ({ name }) => {
    const r = await api("POST", "/api/v1/apps", { name, kind: "llm" });
    if (!r.ok) return { content: [{ type: "text", text: `Could not create LLM app: ${r.error}` }], isError: true };
    const d = r.data ?? {};
    return {
      content: [
        {
          type: "text",
          text:
            `Created LLM Guard app "${name}" (mode: ${d.mode}).\n` +
            `App token: ${d.token}\n\n` +
            `Wire it up:\n` +
            `1. Set NEMESIS_TOKEN=${d.token}\n` +
            `2. Guard your model calls with one line (Node):\n` +
            `     import { guardLLM } from "@nemesis-shield-autogon/sentinel/llm";\n` +
            `     const v = guardLLM(userPrompt, true); if (v.blocked) return refuse();\n` +
            `   (same helper in Python/.NET/Ruby/PHP — call nemesis_protect with "llm" for each.)\n` +
            `3. It blocks prompt injection, unauthorized tool calls and data egress at the model boundary\n` +
            `   (OWASP LLM Top 10). Starts in observe; call nemesis_set_mode "enforce" once it has learned.`,
        },
      ],
    };
  },
);

// create_omniguard — a business-logic firewall for money & accounts, pre-loaded with sector rules.
server.tool(
  "nemesis_create_omniguard",
  "Create an Omniguard business-logic firewall: a decision function pre-loaded with fraud/abuse rules " +
    "matched to your sector and event type, to safeguard money and accounts (payment fraud, account " +
    "takeover, velocity/geo/AML). Returns the function id and how to score transactions. Requires NEMESIS_API_KEY.",
  {
    name: z.string().describe("Name for the function (e.g. 'transfers')"),
    industry: z.string().optional().describe("Sector, e.g. fintech, ecommerce, lending, general (default general)"),
    event: z.string().optional().describe("Event type, e.g. transfer, payment, signup, withdrawal (default transfer)"),
  },
  async ({ name, industry, event }) => {
    const r = await api("POST", "/api/v1/omniguard/functions", { name, industry, event });
    if (!r.ok) return { content: [{ type: "text", text: `Could not create Omniguard function: ${r.error}` }], isError: true };
    const d = r.data ?? {};
    return {
      content: [
        {
          type: "text",
          text:
            `Created Omniguard function "${name}" — ${d.rulesSeeded} starter rules for ${d.industry}/${d.event}.\n` +
            `Function id: ${d.functionId}\n\n` +
            `Score transactions (allow / review / block) in real time:\n` +
            `  POST https://app.nemesislabs.xyz/api/v1/omniguard/score\n` +
            `  Authorization: Bearer <your Omniguard ingest token — get it in the console>\n` +
            `  { "amount": 250000, "currency": "NGN", "channel": "${d.event}", "device_id": "…", "ip": "…" }\n` +
            `  -> { "verdict": "allow|review|block", "overall_score", "reasons": [...] }\n\n` +
            `Add or tune rules in the console; the starter set covers the common ${d.industry} ${d.event} risks.`,
        },
      ],
    };
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
process.stderr.write("nemesis-shield MCP server running (stdio)\n");
