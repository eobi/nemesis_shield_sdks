"""LLM Guard — mirrors the JS shared analyzeLLM. OWASP LLM Top 10 (2025) detection at the model
boundary, with identical shape hashes to the Node SDK. Includes blocking helpers (guard_llm /
llm_should_block) at parity with the Node SDK so a Python app can enforce, not just observe."""

import re
from .tokenize import length_bucket
from .hash import shape_hash
from .mlguard import ml_injection_score, ML_BLOCK_THRESHOLD, ML_FLAG_THRESHOLD

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_INJECTION = [
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts?|context)", re.I), "ignore_previous"),
    (re.compile(r"disregard\s+(the\s+)?(above|previous|system)", re.I), "disregard"),
    (re.compile(r"forget\s+(everything|all|your)\s+(instructions|rules)", re.I), "forget_instructions"),
    (re.compile(r"you\s+are\s+now\s+(a|an|in)\b", re.I), "role_override"),
    (re.compile(r"(reveal|show|print|repeat)\s+(your|the)\s+(system\s+)?(prompt|instructions)", re.I), "prompt_extraction"),
    (re.compile(r"new\s+instructions?\s*:", re.I), "injected_instructions"),
    (re.compile(r"\[\s*system\s*\]", re.I), "fake_system_marker"),
    (re.compile(r"<\s*/?\s*(system|assistant)\s*>", re.I), "role_tag_injection"),
]
_JAILBREAK = [
    (re.compile(r"\bDAN\b|do\s+anything\s+now", re.I), "dan"),
    (re.compile(r"developer\s+mode", re.I), "developer_mode"),
    (re.compile(r"pretend\s+(you|there)\s+(are|is)\s+no\s+(restrictions|rules|filters?)", re.I), "pretend_no_rules"),
    (re.compile(r"you\s+have\s+no\s+(restrictions|limitations|guidelines)", re.I), "no_restrictions"),
    (re.compile(r"(bypass|ignore|disable)\s+(your\s+)?(safety|content\s+policy|guardrails?)", re.I), "bypass_safety"),
    (re.compile(r"jailbreak", re.I), "jailbreak_keyword"),
]
_OUTPUT_SECRETS = [
    (re.compile(r"\b(sk|pk)-[A-Za-z0-9]{20,}\b"), "api_key_in_output"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "email_in_output"),
    (re.compile(r"\b(?:\d[ -]*?){13,16}\b"), "card_number_in_output"),
    (re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"), "private_key_in_output"),
]

# Embedded-instruction markers for INDIRECT injection (instructions hidden in retrieved/tool content).
_EMBEDDED_INSTRUCTIONS = [
    (re.compile(r"follow\s+(the\s+)?(instructions|directions)\s+(in|below|contained)", re.I), "embedded_follow_instructions"),
    (re.compile(r"when\s+(you\s+)?summariz\w+.*\b(instead|also|append|include)\b", re.I), "embedded_summary_hijack"),
    (re.compile(r"\bAI\s+assistant\b.*\b(must|should|now)\b", re.I), "embedded_assistant_directive"),
    (re.compile(r"(send|post|exfiltrate|forward)\s+.*\b(to|at)\s+https?://", re.I), "embedded_exfil"),
    (re.compile(r"\bDOCJACK-\S+", re.I), "embedded_docjack_marker"),
]

# Cloud-metadata / private-network hosts an agent tool should never reach (SSRF).
_INTERNAL_HOST = re.compile(
    r"^(?:localhost|0\.0\.0\.0|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.\d+\.\d+|\[?::1\]?|"
    r"metadata\.google\.internal|.*\.internal)$",
    re.I,
)
_URL_RE = re.compile(r"https?://([^/\s\"'<>)\]]+)", re.I)

# Model self-refusal — informational (the app defended itself; never blocked).
_REFUSAL = [
    (re.compile(r"\bI\s+(can'?t|cannot|won'?t|am\s+not\s+able\s+to|am\s+unable\s+to)\b", re.I), "refusal_cannot"),
    (re.compile(r"\bI'?m\s+sorry,?\s+but\b", re.I), "refusal_sorry"),
    (re.compile(r"\b(I\s+can'?t\s+help\s+with|I\s+won'?t\s+be\s+able\s+to\s+help)\b", re.I), "refusal_no_help"),
]

# OWASP LLM Top 10 (2025) category for each detection kind.
OWASP_LLM_2025 = {
    "prompt_injection": "LLM01",
    "indirect_injection": "LLM01",
    "jailbreak": "LLM01",
    "sensitive_output": "LLM02",
    "tool_ssrf": "LLM05",
    "unauthorized_tool_call": "LLM06",
    "system_prompt_leak": "LLM07",
    "excessive_input": "LLM10",
    "excessive_output": "LLM10",
    "model_refused": "LLM09",
    "ml_prompt_injection": "LLM01",
}


def owasp_for(kind: str) -> str:
    return OWASP_LLM_2025.get(kind, "LLM01")


def _scan(text, rules):
    return [label for rx, label in rules if rx.search(text)]


def _has_internal_url(text: str) -> bool:
    for m in _URL_RE.finditer(text or ""):
        host = m.group(1).split(":")[0].split("@")[-1]
        if _INTERNAL_HOST.match(host):
            return True
    return False


def analyze_llm(
    *,
    prompt: str,
    system: str | None = None,
    response: str | None = None,
    tools: list[str] | None = None,
    allowed_tools: list[str] | None = None,
    context: list[str] | None = None,
    tool_args: list[str] | None = None,
    model: str | None = None,
    provider: str | None = None,
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
) -> dict:
    detections = []
    prompt = prompt or ""

    for s in _scan(prompt, _INJECTION):
        detections.append({"kind": "prompt_injection", "severity": "high", "signal": s})
    for s in _scan(prompt, _JAILBREAK):
        detections.append({"kind": "jailbreak", "severity": "high", "signal": s})

    # INDIRECT injection (LLM01): untrusted retrieved/tool content fed back to the model.
    for doc in context or []:
        c = doc or ""
        for s in _scan(c, _INJECTION):
            detections.append({"kind": "indirect_injection", "severity": "high", "signal": "context:" + s})
        for s in _scan(c, _EMBEDDED_INSTRUCTIONS):
            detections.append({"kind": "indirect_injection", "severity": "high", "signal": s})

    # system-prompt leakage: check a few windows (not just the first 32 chars).
    if system and response and len(system) >= 24:
        mid = len(system) // 2
        for raw in (system[0:32], system[mid:mid + 32], system[-32:]):
            needle = raw.strip()
            if len(needle) >= 16 and needle in response:
                detections.append({"kind": "system_prompt_leak", "severity": "high", "signal": "system_prompt_in_output"})
                break

    if response:
        for s in _scan(response, _OUTPUT_SECRETS):
            detections.append({"kind": "sensitive_output", "severity": "high", "signal": s})

    if tools and allowed_tools is not None:
        allow = set(allowed_tools)
        for t in tools:
            if t not in allow:
                detections.append({"kind": "unauthorized_tool_call", "severity": "critical", "signal": "tool:" + t})

    # tool SSRF / egress (LLM05/LLM06): a tool call whose args point at an internal / metadata host.
    for arg in tool_args or []:
        if _has_internal_url(arg or ""):
            detections.append({"kind": "tool_ssrf", "severity": "high", "signal": "ssrf_internal_host"})
            break

    if len(prompt) > 20000:
        detections.append({"kind": "excessive_input", "severity": "medium", "signal": "prompt_over_20k"})
    if (prompt_tokens or 0) > 12000 or (completion_tokens or 0) > 6000:
        detections.append({"kind": "excessive_output", "severity": "medium", "signal": "tokens_over_budget"})

    # model self-refusal — informational only (never blocked).
    if response:
        for s in _scan(response, _REFUSAL):
            detections.append({"kind": "model_refused", "severity": "info", "signal": s})
            break

    # ML classifier (HashLR) — catches obfuscated/paraphrased injection the regex layer misses. Runs
    # only when no injection-family regex fired, so it adds coverage without changing existing shapes.
    has_inj_family = any(d["kind"] in ("prompt_injection", "jailbreak", "indirect_injection") for d in detections)
    if not has_inj_family:
        score = ml_injection_score(prompt)
        for doc in context or []:
            score = max(score, ml_injection_score(doc or ""))
        if score >= ML_BLOCK_THRESHOLD:
            detections.append({"kind": "ml_prompt_injection", "severity": "high", "signal": "ml_injection"})
        elif score >= ML_FLAG_THRESHOLD:
            detections.append({"kind": "ml_prompt_injection", "severity": "medium", "signal": "ml_injection_suspected"})

    for d in detections:
        d["owasp"] = owasp_for(d["kind"])

    signals = sorted(d["signal"] for d in detections)
    tool_names = sorted(tools or [])
    max_sev = "info"
    for d in detections:
        if _SEV_RANK[d["severity"]] > _SEV_RANK[max_sev]:
            max_sev = d["severity"]

    sketch = {
        "v": 1,
        "promptLen": length_bucket(len(prompt)),
        "toolNames": tool_names,
        "signals": signals,
        "shape": shape_hash({"kinds": sorted(d["kind"] for d in detections), "tools": tool_names}),
    }
    if response is not None:
        sketch["responseLen"] = length_bucket(len(response))

    return {"detections": detections, "sketch": sketch, "maxSeverity": max_sev}


def llm_should_block(result: dict, mode: str) -> bool:
    """Whether a result should block, given the app mode. Only enforce mode blocks; high+ severity.
    Mirrors the Node SDK's llmShouldBlock."""
    if mode != "enforce":
        return False
    return result.get("maxSeverity") in ("high", "critical")


def guard_llm(*, mode: str = "observe", on_result=None, **exchange) -> dict:
    """Guard an LLM exchange. Returns {"allowed": bool, "result": dict|None}. In enforce mode a
    high/critical detection yields allowed=False so the caller can refuse. Fail-open on error."""
    try:
        result = analyze_llm(**exchange)
        if on_result:
            on_result(result)
        return {"allowed": not llm_should_block(result, mode), "result": result}
    except Exception:
        return {"allowed": True, "result": None}
