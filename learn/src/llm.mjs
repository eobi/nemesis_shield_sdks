// LLM provider abstraction — OpenAI, Anthropic, or a local Ollama model (fully offline). Zero deps, just
// fetch to each REST API. The agent uses the LLM to (a) infer routes from repo/HTML it can't parse
// structurally, and (b) generate REALISTIC field values so learned behavior mirrors real traffic. It is
// OPTIONAL: without a key the agent falls back to schema/heuristic value generation and still works.

export function makeLlm(cfg) {
  if (!cfg || !cfg.provider) return null;
  const provider = cfg.provider;
  const model = cfg.model || DEFAULT_MODEL[provider];
  const key = cfg.apiKey;
  const base = cfg.baseUrl;

  async function complete(system, user, { json = false } = {}) {
    try {
      if (provider === "openai") {
        const r = await fetch(`${base || "https://api.openai.com/v1"}/chat/completions`, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
          body: JSON.stringify({ model, messages: [{ role: "system", content: system }, { role: "user", content: user }], temperature: 0.4, ...(json ? { response_format: { type: "json_object" } } : {}) }),
        });
        const j = await r.json();
        return j.choices?.[0]?.message?.content ?? "";
      }
      if (provider === "anthropic") {
        const r = await fetch(`${base || "https://api.anthropic.com"}/v1/messages`, {
          method: "POST",
          headers: { "content-type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01" },
          body: JSON.stringify({ model, max_tokens: 1024, system: system + (json ? " Respond with ONLY valid JSON." : ""), messages: [{ role: "user", content: user }] }),
        });
        const j = await r.json();
        return j.content?.[0]?.text ?? "";
      }
      if (provider === "ollama") {
        const r = await fetch(`${base || "http://localhost:11434"}/api/chat`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ model, stream: false, format: json ? "json" : undefined, messages: [{ role: "system", content: system }, { role: "user", content: user }] }),
        });
        const j = await r.json();
        return j.message?.content ?? "";
      }
    } catch (e) {
      return "";
    }
    return "";
  }

  async function completeJson(system, user) {
    const txt = await complete(system, user, { json: true });
    return safeJson(txt);
  }

  return { provider, model, complete, completeJson };
}

const DEFAULT_MODEL = { openai: "gpt-4o-mini", anthropic: "claude-3-5-haiku-latest", ollama: "llama3.1" };

export function safeJson(txt) {
  if (!txt) return null;
  try { return JSON.parse(txt); } catch { /* try to extract a fenced/loose object */ }
  const m = String(txt).match(/\{[\s\S]*\}|\[[\s\S]*\]/);
  if (m) { try { return JSON.parse(m[0]); } catch { /* give up */ } }
  return null;
}
