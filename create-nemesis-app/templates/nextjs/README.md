# __APP_NAME__

A Next.js app guarded by a positive-security WAF (Nemesis Shield) from `middleware.ts`.

```bash
cp .env.example .env      # paste your nsk_ token from https://shield.nemesislabs.xyz
npm install
npm run dev
```

Observe mode by default. Fill the baseline, approve it, then enforce:

```bash
npx @nemesis-shield-autogon/learn --target http://localhost:3000 --app-token nsk_... --repo .
```

The same `withShield` wrapper works on Vercel Edge and Cloudflare Workers. See `AGENTS.md`.
