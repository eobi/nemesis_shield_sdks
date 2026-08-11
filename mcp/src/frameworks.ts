// Verified Nemesis Shield integration snippets, one per stack. Every line here is checked against the
// SDK sources — an MCP tool that emits a wrong install line trains agents to write broken code.

export interface Fw {
  lang: string;
  install: string;
  snippet: string;
  note?: string;
}

export const FRAMEWORKS: Record<string, Fw> = {
  fastapi: {
    lang: "Python",
    install: "pip install nemesis-shield",
    snippet:
      'from nemesis_shield.asgi import SentinelMiddleware\napp.add_middleware(SentinelMiddleware, token=os.environ["NEMESIS_TOKEN"])',
  },
  flask: {
    lang: "Python",
    install: "pip install nemesis-shield",
    snippet:
      'from nemesis_shield.wsgi import SentinelWSGI\napp.wsgi_app = SentinelWSGI(app.wsgi_app, token=os.environ["NEMESIS_TOKEN"])',
  },
  django: {
    lang: "Python",
    install: "pip install nemesis-shield",
    snippet: 'MIDDLEWARE = ["nemesis_shield.django.SentinelDjango", *MIDDLEWARE]  # settings.py, first',
  },
  express: {
    lang: "Node",
    install: "npm install @nemesis-shield-autogon/sentinel",
    snippet:
      'import { sentinel } from "@nemesis-shield-autogon/sentinel/express";\napp.use(sentinel({ token: process.env.NEMESIS_TOKEN }));',
  },
  fastify: {
    lang: "Node",
    install: "npm install @nemesis-shield-autogon/sentinel",
    snippet:
      'import { sentinelFastify } from "@nemesis-shield-autogon/sentinel/fastify";\nawait app.register(sentinelFastify, { token: process.env.NEMESIS_TOKEN });',
  },
  koa: {
    lang: "Node",
    install: "npm install @nemesis-shield-autogon/sentinel",
    snippet:
      'import { sentinelKoa } from "@nemesis-shield-autogon/sentinel/koa";\napp.use(sentinelKoa({ token: process.env.NEMESIS_TOKEN }));',
  },
  nextjs: {
    lang: "Node (edge)",
    install: "npm install @nemesis-shield-autogon/edge",
    snippet:
      'import { withShield } from "@nemesis-shield-autogon/edge";\nexport default { fetch: (req, env) => withShield(app, { token: env.NEMESIS_TOKEN })(req) };',
    note: "For Next.js middleware / Vercel Edge / Cloudflare Workers, wrap the Web-standard handler with withShield().",
  },
  go: {
    lang: "Go",
    install: "go get github.com/eobi/nemesis_shield_sdks/go",
    snippet:
      'c := nemesis.New(os.Getenv("NEMESIS_TOKEN"))\nhttp.ListenAndServe(":8080", c.Middleware(mux)) // chi: r.Use(c.Middleware)',
  },
  rails: {
    lang: "Ruby",
    install: "gem 'nemesis_shield'",
    snippet:
      'require "nemesis_shield"\nconfig.middleware.use NemesisShield::Middleware, token: ENV["NEMESIS_TOKEN"] # config/application.rb',
    note: "Sinatra / Rack: use NemesisShield::Middleware, token: ENV[\"NEMESIS_TOKEN\"]",
  },
  laravel: {
    lang: "PHP",
    install: "composer require nemesislabs/sentinel",
    snippet: '# .env\nNEMESIS_TOKEN=nsk_your_app_token   # zero-config: the service provider auto-registers the middleware',
  },
  spring: {
    lang: "Java",
    install: "Maven: io.github.eobi:sentinel  (Gradle: implementation(\"io.github.eobi:sentinel\"))",
    snippet:
      '@Bean FilterRegistrationBean<NemesisShieldFilter> nemesis() {\n  var reg = new FilterRegistrationBean<>(new NemesisShieldFilter());\n  reg.addUrlPatterns("/*");\n  return reg;\n}',
  },
  aspnet: {
    lang: ".NET",
    install: "dotnet add package NemesisShield",
    snippet: "app.UseMiddleware<NemesisShield.SentinelMiddleware>(); // BEFORE UseRouting / endpoints",
  },
  rust: {
    lang: "Rust",
    install: 'nemesis-shield = "0.1"  # Cargo.toml',
    snippet:
      "// axum (tower): wire the nemesis_shield::Client into a middleware.\n// Full example: https://github.com/eobi/nemesis_shield_sdks/tree/main/rust",
  },
  "supabase-edge": {
    lang: "Deno",
    install: "deno add jsr:@nemesis-shield/edge   (then: supabase secrets set NEMESIS_TOKEN=nsk_...)",
    snippet:
      'import { withShield } from "jsr:@nemesis-shield/edge";\nDeno.serve(withShield(handler, { token: Deno.env.get("NEMESIS_TOKEN") }));',
  },
  "cloudflare-workers": {
    lang: "Node (edge)",
    install: "npm install @nemesis-shield-autogon/edge   (then: wrangler secret put NEMESIS_TOKEN)",
    snippet:
      'import { withShield } from "@nemesis-shield-autogon/edge";\nexport default { fetch: (req, env) => withShield(app, { token: env.NEMESIS_TOKEN })(req) };',
  },
  browser: {
    lang: "Browser",
    install: "npm install @nemesis-shield-autogon/browser",
    snippet:
      'import NemesisShield from "@nemesis-shield-autogon/browser";\nNemesisShield.init({ token: import.meta.env.VITE_NEMESIS_TOKEN, frameBust: true }); // once, before render',
    note: 'Checkout/payment pages (Magecart, formjacking, PCI DSS 4.0.1). Server-rendered/legacy: <script src="nemesis-shield.js" data-token="nsk_..."></script>',
  },
  llm: {
    lang: "Node / Python / .NET / Ruby / PHP",
    install: "npm install @nemesis-shield-autogon/sentinel  (or your language's Shield SDK)",
    snippet:
      'import { guardLLM } from "@nemesis-shield-autogon/sentinel/llm";\nconst v = guardLLM(userPrompt, true); // enforce\nif (v.blocked) return refuse(); // v.kind, v.score, v.owasp ("LLM01")',
    note: "Blocks prompt injection at the model boundary (OWASP LLM Top 10). Same helper in every language: .NET LlmGuard.GuardLLM(prompt, enforce:true); Ruby NemesisShield::LLM.guard_llm(prompt, enforce: true); PHP NemesisShieldLLM::guardLLM($prompt, true).",
  },
};

const ALIASES: Record<string, string> = {
  starlette: "fastapi",
  asgi: "fastapi",
  wsgi: "flask",
  node: "express",
  connect: "express",
  next: "nextjs",
  "next.js": "nextjs",
  vercel: "nextjs",
  edge: "cloudflare-workers",
  workers: "cloudflare-workers",
  supabase: "supabase-edge",
  deno: "supabase-edge",
  ruby: "rails",
  sinatra: "rails",
  rack: "rails",
  php: "laravel",
  java: "spring",
  "spring-boot": "spring",
  servlet: "spring",
  dotnet: "aspnet",
  "asp.net": "aspnet",
  csharp: "aspnet",
  golang: "go",
  chi: "go",
  gin: "go",
  axum: "rust",
  react: "browser",
  vue: "browser",
  angular: "browser",
  checkout: "browser",
  "prompt-injection": "llm",
  ai: "llm",
  chatbot: "llm",
};

export function resolveFramework(raw: string): string | null {
  const k = raw.trim().toLowerCase().replace(/\s+/g, "-");
  if (FRAMEWORKS[k]) return k;
  if (ALIASES[k]) return ALIASES[k];
  return null;
}

export function frameworkList(): string[] {
  return Object.keys(FRAMEWORKS);
}

// Map detected technology display names (from the fingerprint scanner) to a nemesis_protect framework
// key, so a scan can tell the developer the exact protect command to run next.
export function suggestFramework(techNames: string[]): string | null {
  const hay = techNames.join(" | ").toLowerCase();
  const rules: Array<[RegExp, string]> = [
    [/next\.?js|_next\//, "nextjs"],
    [/fastapi/, "fastapi"],
    [/django/, "django"],
    [/\bflask\b/, "flask"],
    [/express/, "express"],
    [/fastify/, "fastify"],
    [/\bkoa\b/, "koa"],
    [/laravel/, "laravel"],
    [/ruby on rails|\brails\b/, "rails"],
    [/spring/, "spring"],
    [/asp\.?net|\.net|kestrel/, "aspnet"],
    [/cloudflare workers|workers\.dev/, "cloudflare-workers"],
    [/supabase/, "supabase-edge"],
  ];
  for (const [re, key] of rules) if (re.test(hay)) return key;
  return null;
}

export function protectText(raw: string): string {
  const key = resolveFramework(raw);
  if (!key) {
    return (
      `I don't have a canned one-liner for "${raw}". Nemesis Shield supports:\n` +
      frameworkList().join(", ") +
      `\n\nEvery integration is a one-line, positive-security middleware. Full reference: ` +
      `https://github.com/eobi/nemesis_shield_sdks/blob/main/ai-rules/AGENTS.md`
    );
  }
  const fw = FRAMEWORKS[key];
  return [
    `Add Nemesis Shield to ${key} (${fw.lang}) — a positive-security runtime firewall. Safe by default:`,
    `it starts in OBSERVE mode (learns, blocks nothing) until a human flips it to ENFORCE in the console.`,
    ``,
    `1) Install:`,
    `   ${fw.install}`,
    ``,
    `2) Add the one line (read the token from NEMESIS_TOKEN; never hardcode it):`,
    fw.snippet
      .split("\n")
      .map((l) => "   " + l)
      .join("\n"),
    fw.note ? `\n   Note: ${fw.note}` : ``,
    ``,
    `3) Get a free token at https://shield.nemesislabs.xyz and set NEMESIS_TOKEN (format nsk_...).`,
    ``,
    `New app with no traffic to learn from yet? Finish the baseline in minutes:`,
    `   npx @nemesis-shield-autogon/learn --target http://localhost:3000 --app-token nsk_... --repo .`,
    ``,
    `It sends only method + route shape + auth flag, never bodies or secrets, and is fail-open.`,
    `It catches deviations from learned normal (zero-days, IDOR/BOLA, business-logic abuse); it does not`,
    `block abuse that stays entirely inside the app's normal behavior.`,
  ].join("\n");
}
