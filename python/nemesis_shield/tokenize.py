"""Value tokenization + path normalization - mirrors the JS shared package exactly."""

import re

_RE = {
    "uuid": re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I),
    "email": re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    "url": re.compile(r"^https?://\S+$", re.I),
    "ipv4": re.compile(r"^(\d{1,3}\.){3}\d{1,3}$"),
    "ipv6": re.compile(r"^[0-9a-f:]+:[0-9a-f:]+$", re.I),
    "int": re.compile(r"^-?\d+$"),
    "float": re.compile(r"^-?\d*\.\d+$"),
    "date": re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?"),
    "jwt": re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"),
    "hex": re.compile(r"^[0-9a-f]+$", re.I),
    "base64": re.compile(r"^[A-Za-z0-9+/]+={0,2}$"),
    "alpha": re.compile(r"^[A-Za-z]+$"),
    "alnum": re.compile(r"^[A-Za-z0-9]+$"),
    # A run of 7+ letters => reads like a word / route name, not an opaque id/token.
    "word": re.compile(r"[A-Za-z]{7,}"),
}


def classify(value) -> str:
    if value is None or value == "":
        return "empty"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "int" if value.is_integer() else "float"
    s = str(value)
    if len(s) == 0:
        return "empty"
    if _RE["uuid"].search(s):
        return "uuid"
    if _RE["email"].search(s):
        return "email"
    if _RE["url"].search(s):
        return "url"
    if _RE["ipv4"].search(s):
        return "ipv4"
    if _RE["ipv6"].search(s):
        return "ipv6"
    if _RE["jwt"].search(s):
        return "jwt"
    if _RE["date"].search(s):
        return "date"
    if _RE["int"].search(s):
        return "int"
    if _RE["float"].search(s):
        return "float"
    if len(s) >= 16 and _RE["hex"].search(s):
        return "hex"
    if len(s) >= 16 and _RE["base64"].search(s) and not _RE["word"].search(s):
        return "base64"
    if _RE["alpha"].search(s):
        return "alpha"
    if _RE["alnum"].search(s):
        return "alnum"
    return "string"


def length_bucket(n: int) -> str:
    if n <= 0:
        return "0"
    if n <= 8:
        return "1-8"
    if n <= 32:
        return "9-32"
    if n <= 128:
        return "33-128"
    if n <= 1024:
        return "129-1k"
    if n <= 8192:
        return "1k-8k"
    return "8k+"


def _norm_seg(seg: str) -> str:
    if seg == "":
        return seg
    if ".." in seg:
        return "{traversal}"  # path-traversal segment (also keeps ".." out of telemetry)
    from urllib.parse import unquote

    kind = classify(unquote(seg))
    if kind in ("int", "float"):
        return "{int}"
    if kind == "uuid":
        return "{uuid}"
    if kind == "hex":
        return "{hex}"
    if kind == "base64":
        return "{token}"
    if kind == "alnum":
        return "{id}" if len(seg) >= 12 and not _RE["word"].search(seg) else seg
    return seg


def normalize_path(path: str) -> str:
    clean = path.split("?")[0].split("#")[0]
    out = "/".join(_norm_seg(s) for s in clean.split("/"))
    return "/" if out == "" else out
