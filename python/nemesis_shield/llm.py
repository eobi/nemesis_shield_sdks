"""LLM Guard — mirrors the JS shared analyzeLLM. OWASP LLM Top 10 detection at the model boundary,
with identical shape hashes to the Node SDK."""

import re
from .tokenize import length_bucket
from .hash import shape_hash

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


def _scan(text, rules):
    return [label for rx, label in rules if rx.search(text)]


def analyze_llm(
    *,
    prompt: str,
    system: str | None = None,
    response: str | None = None,
    tools: list[str] | None = None,
    allowed_tools: list[str] | None = None,
) -> dict:
    detections = []
    prompt = prompt or ""

    for s in _scan(prompt, _INJECTION):
        detections.append({"kind": "prompt_injection", "severity": "high", "signal": s})
    for s in _scan(prompt, _JAILBREAK):
        detections.append({"kind": "jailbreak", "severity": "high", "signal": s})

    if system and response and len(system) >= 24:
        needle = system[:32].strip()
        if len(needle) >= 16 and needle in response:
            detections.append({"kind": "system_prompt_leak", "severity": "high", "signal": "system_prompt_in_output"})

    if response:
        for s in _scan(response, _OUTPUT_SECRETS):
            detections.append({"kind": "sensitive_output", "severity": "high", "signal": s})

    if tools and allowed_tools is not None:
        allow = set(allowed_tools)
        for t in tools:
            if t not in allow:
                detections.append({"kind": "unauthorized_tool_call", "severity": "critical", "signal": "tool:" + t})

    if len(prompt) > 20000:
        detections.append({"kind": "excessive_input", "severity": "medium", "signal": "prompt_over_20k"})

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
