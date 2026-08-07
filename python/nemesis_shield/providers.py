"""Auto-instrumentation for LLM providers - wrap your client once and every call is guarded.

No hard dependency on openai / anthropic / langchain: everything is duck-typed, so importing this
module never fails and works across SDK minor versions. In `enforce` mode a high/critical detection
raises `SentinelBlocked` (request-side, before the model is called; or response-side, before the
output reaches your users). In `observe` mode nothing is blocked - you just get telemetry via
`on_result`.

    from nemesis_shield.providers import guard_openai
    client = guard_openai(OpenAI(), mode="enforce", allowed_tools=["search"])
    client.chat.completions.create(model="gpt-4o-mini", messages=[...])   # now guarded
"""

from .llm import guard_llm


class SentinelBlocked(Exception):
    """Raised in enforce mode when a request or response is blocked. `.result` holds the analysis."""

    def __init__(self, phase: str, result: dict):
        kinds = ",".join(sorted({d["kind"] for d in (result or {}).get("detections", [])})) or "?"
        super().__init__(f"Nemesis Shield blocked this {phase} (LLM guard: {kinds})")
        self.phase = phase
        self.result = result


# ── extraction helpers (accept SDK objects OR plain dicts) ───────────────────
def _get(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _messages_to_prompt(messages):
    prompt, system = [], []
    for m in messages or []:
        role, content = _get(m, "role"), _get(m, "content")
        text = content if isinstance(content, str) else " ".join(
            str(_get(p, "text", "")) for p in (content or []) if _get(p, "type") in (None, "text"))
        if role == "system":
            system.append(str(text or ""))
        elif role == "user":
            prompt.append(str(text or ""))
    return "\n".join(prompt), ("\n".join(system) or None)


def _openai_response(resp):
    choices = _get(resp, "choices") or []
    if not choices:
        return "", [], []
    msg = _get(choices[0], "message") or {}
    content = str(_get(msg, "content") or "")
    tools, args = [], []
    for tc in (_get(msg, "tool_calls") or []):
        fn = _get(tc, "function") or {}
        if _get(fn, "name"):
            tools.append(str(_get(fn, "name")))
        if _get(fn, "arguments"):
            args.append(str(_get(fn, "arguments")))
    return content, tools, args


def _anthropic_response(resp):
    content, tools, args = [], [], []
    for block in (_get(resp, "content") or []):
        btype = _get(block, "type")
        if btype == "text":
            content.append(str(_get(block, "text") or ""))
        elif btype == "tool_use":
            tools.append(str(_get(block, "name") or ""))
            args.append(str(_get(block, "input") or ""))
    return "\n".join(content), tools, args


def _usage_tokens(resp):
    u = _get(resp, "usage") or {}
    return (_get(u, "prompt_tokens") or _get(u, "input_tokens"),
            _get(u, "completion_tokens") or _get(u, "output_tokens"))


# ── the shared guard step ────────────────────────────────────────────────────
def _guard(phase, mode, on_result, **exchange):
    g = guard_llm(mode=mode, on_result=on_result, **exchange)
    if not g["allowed"]:
        raise SentinelBlocked(phase, g["result"])
    return g["result"]


# ── OpenAI (also covers Azure OpenAI - same client shape) ─────────────────────
def guard_openai(client, *, mode="observe", allowed_tools=None, on_result=None):
    """Wrap an OpenAI/AzureOpenAI client in place so chat.completions.create is guarded. Returns it."""
    completions = client.chat.completions
    original = completions.create

    def create(*args, **kwargs):
        messages = kwargs.get("messages") or (args[0] if args else [])
        prompt, system = _messages_to_prompt(messages)
        _guard("request", mode, on_result, prompt=prompt, allowed_tools=allowed_tools)
        resp = original(*args, **kwargs)
        content, tools, targs = _openai_response(resp)
        pt, ct = _usage_tokens(resp)
        _guard("response", mode, on_result, prompt=prompt, system=system, response=content,
               tools=tools or None, tool_args=targs or None, allowed_tools=allowed_tools,
               prompt_tokens=pt, completion_tokens=ct, model=kwargs.get("model"), provider="openai")
        return resp

    completions.create = create
    return client


# ── Anthropic ────────────────────────────────────────────────────────────────
def guard_anthropic(client, *, mode="observe", allowed_tools=None, on_result=None):
    """Wrap an Anthropic client in place so messages.create is guarded. Returns it."""
    messages_api = client.messages
    original = messages_api.create

    def create(*args, **kwargs):
        prompt, _sys = _messages_to_prompt(kwargs.get("messages") or [])
        system = kwargs.get("system") or _sys
        _guard("request", mode, on_result, prompt=prompt, allowed_tools=allowed_tools)
        resp = original(*args, **kwargs)
        content, tools, targs = _anthropic_response(resp)
        pt, ct = _usage_tokens(resp)
        _guard("response", mode, on_result, prompt=prompt, system=system, response=content,
               tools=tools or None, tool_args=targs or None, allowed_tools=allowed_tools,
               prompt_tokens=pt, completion_tokens=ct, model=kwargs.get("model"), provider="anthropic")
        return resp

    messages_api.create = create
    return client


# ── LangChain callback handler ───────────────────────────────────────────────
def sentinel_callback(*, mode="observe", allowed_tools=None, on_result=None):
    """Return a LangChain BaseCallbackHandler that guards each LLM call. Import is lazy so this module
    stays dependency-free. Pass it via callbacks=[sentinel_callback(mode="enforce")]."""
    try:
        from langchain_core.callbacks import BaseCallbackHandler  # type: ignore
    except Exception:  # pragma: no cover - exercised only when langchain is installed
        try:
            from langchain.callbacks.base import BaseCallbackHandler  # type: ignore
        except Exception as e:
            raise ImportError("LangChain is not installed") from e

    class _Sentinel(BaseCallbackHandler):
        def on_llm_start(self, serialized, prompts, **kwargs):
            for p in prompts or []:
                _guard("request", mode, on_result, prompt=str(p), allowed_tools=allowed_tools)

        def on_llm_end(self, response, **kwargs):
            for gen in (_get(response, "generations") or []):
                for g in (gen or []):
                    text = _get(g, "text") or ""
                    _guard("response", mode, on_result, prompt="", response=str(text),
                           allowed_tools=allowed_tools)

    return _Sentinel()
