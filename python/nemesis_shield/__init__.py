"""Nemesis Shield - Sentinel SDK for Python. One line to protect a web app, API, or LLM app."""
from .sketch import build_sketch, SKETCH_VERSION
from .client import SentinelClient
from .llm import analyze_llm, guard_llm, llm_should_block, owasp_for, OWASP_LLM_2025
from .mlguard import ml_injection_score, refresh_model, MODEL_VERSION, ML_BLOCK_THRESHOLD, ML_FLAG_THRESHOLD
from .providers import guard_openai, guard_anthropic, sentinel_callback, SentinelBlocked
from .hash import fnv1a, shape_hash, stable_stringify
from .tokenize import classify, normalize_path, length_bucket

__all__ = [
    "build_sketch", "SKETCH_VERSION", "SentinelClient",
    "analyze_llm", "guard_llm", "llm_should_block", "owasp_for", "OWASP_LLM_2025",
    "ml_injection_score", "refresh_model", "MODEL_VERSION", "ML_BLOCK_THRESHOLD", "ML_FLAG_THRESHOLD",
    "guard_openai", "guard_anthropic", "sentinel_callback", "SentinelBlocked",
    "fnv1a", "shape_hash", "stable_stringify", "classify", "normalize_path", "length_bucket",
]
