#!/usr/bin/env node
// create-nemesis-app — scaffold a starter app that ships with a positive-security
// WAF already wired in. Zero dependencies, Node >= 18.
//
//   npm create nemesis-app@latest my-app -- --template express
//   npx create-nemesis-app my-app --template fastapi
//   npx create-nemesis-app                # interactive
"use strict";

const fs = require("fs");
const path = require("path");
const readline = require("readline");

const TEMPLATES = {
  express: "Express (Node) API with the Sentinel middleware",
  nextjs: "Next.js app guarded from middleware.ts",
  fastapi: "FastAPI (Python) app with the Sentinel ASGI middleware",
  "supabase-edge": "Supabase Edge Function wrapped with withShield",
};

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--template" || a === "-t") args.template = argv[++i];
    else if (a.startsWith("--template=")) args.template = a.split("=")[1];
    else if (a === "--help" || a === "-h") args.help = true;
    else args._.push(a);
  }
  return args;
}

function ask(rl, q) {
  return new Promise((res) => rl.question(q, (a) => res(a.trim())));
}

function copyDir(src, dest, replace) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    // templates ship dotfiles as `_gitignore`, `_env.example` so npm keeps them in the tarball
    const outName = entry.name.replace(/^_gitignore$/, ".gitignore").replace(/^_env\./, ".env.");
    const s = path.join(src, entry.name);
    const d = path.join(dest, outName);
    if (entry.isDirectory()) copyDir(s, d, replace);
    else {
      let body = fs.readFileSync(s, "utf8");
      for (const [k, v] of Object.entries(replace)) body = body.split(k).join(v);
      fs.writeFileSync(d, body);
    }
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(`create-nemesis-app — scaffold an app with a positive-security WAF built in\n`);
    console.log(`Usage: npx create-nemesis-app [dir] --template <name>\n`);
    console.log(`Templates:`);
    for (const [k, v] of Object.entries(TEMPLATES)) console.log(`  ${k.padEnd(15)} ${v}`);
    process.exit(0);
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    let dir = args._[0];
    if (!dir) dir = (await ask(rl, "Project directory (my-nemesis-app): ")) || "my-nemesis-app";

    let template = args.template;
    if (!template) {
      console.log("\nTemplates:");
      const keys = Object.keys(TEMPLATES);
      keys.forEach((k, i) => console.log(`  ${i + 1}) ${k} — ${TEMPLATES[k]}`));
      const pick = await ask(rl, `\nChoose (1-${keys.length}, default 1): `);
      template = keys[(parseInt(pick, 10) || 1) - 1] || keys[0];
    }
    if (!TEMPLATES[template]) {
      console.error(`\nUnknown template "${template}". Options: ${Object.keys(TEMPLATES).join(", ")}`);
      process.exit(1);
    }

    const target = path.resolve(process.cwd(), dir);
    if (fs.existsSync(target) && fs.readdirSync(target).length > 0) {
      console.error(`\nDirectory ${dir} already exists and is not empty. Aborting.`);
      process.exit(1);
    }

    const templateDir = path.join(__dirname, "templates", template);
    const appName = path.basename(target).replace(/[^a-zA-Z0-9-_]/g, "-").toLowerCase() || "nemesis-app";
    copyDir(templateDir, target, { "__APP_NAME__": appName });

    console.log(`\n  Scaffolded a ${template} app in ${dir} with Nemesis Shield wired in.\n`);
    console.log(`  It ships in observe mode. It blocks nothing until you approve a baseline.\n`);
    console.log(`  Next:`);
    console.log(`    1. Get a free app token (nsk_...) at https://shield.nemesislabs.xyz`);
    console.log(`    2. cd ${dir} && copy .env.example to .env and paste your token`);
    console.log(`    3. Install + run (see the README in the project)`);
    console.log(`    4. Fill the baseline: npx @nemesis-shield-autogon/learn --target http://localhost:3000 --app-token nsk_... --repo .`);
    console.log(`    5. Approve the learned routes in the console, then flip to enforce.\n`);
    console.log(`  Building with an AI editor? The project includes an AGENTS.md so your`);
    console.log(`  coding agent keeps adding security as it writes code.\n`);
  } finally {
    rl.close();
  }
}

main().catch((e) => {
  console.error(e && e.message ? e.message : e);
  process.exit(1);
});
