# __APP_NAME__

A FastAPI app with a positive-security WAF (Nemesis Shield) built in.

```bash
cp .env.example .env      # paste your nsk_ token from https://shield.nemesislabs.xyz
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export $(grep -v '^#' .env | xargs)
uvicorn main:app --reload --port 3000
```

Observe mode by default. Fill the baseline, approve it, then enforce:

```bash
npx @nemesis-shield-autogon/learn --target http://localhost:3000 --app-token nsk_... --repo .
```

See `AGENTS.md` for the rules your AI editor should follow.
