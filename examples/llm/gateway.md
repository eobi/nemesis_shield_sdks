# Sentinel LLM Gateway - protect any app with zero code changes

Drop the gateway in front of any OpenAI-compatible endpoint. It inspects the request prompt, the
response, and any RAG upload, and blocks OWASP-LLM attacks inline (adds an `X-Nemesis-Verdict` header).

```bash
pip install nemesis-shield
python -m nemesis_shield.gateway \
  --upstream http://127.0.0.1:9920 \   # your app
  --port 9910 --mode enforce           # observe = telemetry only

# then point your client at the gateway:
#   base_url = "http://127.0.0.1:9910/v1"
```

Blocks: direct injection (request) · secret & system-prompt leak (response) · RAG indirect-injection
(`/upload`). Push a retrained model centrally with `--model-url` (or env `NEMESIS_MODEL_URL`).
