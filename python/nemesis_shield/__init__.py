"""Nemesis Shield — Sentinel SDK for Python. One line to protect a web app, API, or LLM app."""
from .sketch import build_sketch, SKETCH_VERSION
from .client import SentinelClient
from .llm import analyze_llm
from .hash import fnv1a, shape_hash, stable_stringify
from .tokenize import classify, normalize_path, length_bucket

__all__ = [
    "build_sketch", "SKETCH_VERSION", "SentinelClient", "analyze_llm",
    "fnv1a", "shape_hash", "stable_stringify", "classify", "normalize_path", "length_bucket",
]
