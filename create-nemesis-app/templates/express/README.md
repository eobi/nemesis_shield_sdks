# __APP_NAME__

An Express API with a positive-security WAF (Nemesis Shield) built in.

```bash
cp .env.example .env      # paste your nsk_ token from https://shield.nemesislabs.xyz
npm install
npm run dev
```

The app runs in **observe mode**: it blocks nothing and learns your normal traffic. Fill the
baseline, then enforce:

```bash
npx @nemesis-shield-autogon/learn --target http://localhost:3000 --app-token nsk_... --repo .
```

Approve the learned routes in the console, then flip the app to enforce. See `AGENTS.md` for
the rules your AI editor should follow when adding more code.
