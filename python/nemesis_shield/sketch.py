"""Behavioral sketch — mirrors the JS shared package, producing identical shape hashes."""

from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from .tokenize import classify, length_bucket, normalize_path
from .hash import shape_hash

SKETCH_VERSION = 1


def _status_class(status: int) -> str:
    return f"{status // 100}xx"


def _latency_bucket(ms: float) -> str:
    if ms < 10:
        return "<10ms"
    if ms < 50:
        return "10-50ms"
    if ms < 200:
        return "50-200ms"
    if ms < 1000:
        return "200ms-1s"
    if ms < 5000:
        return "1-5s"
    return "5s+"


def _shape_params(source: Optional[dict]) -> list[dict]:
    if not source:
        return []
    out = []
    for name, value in source.items():
        if isinstance(value, (list, tuple)):
            out.append(
                {
                    "name": name,
                    "kind": classify(value[0]) if len(value) else "empty",
                    "len": length_bucket(len(value)),
                    "nested": True,
                }
            )
        elif isinstance(value, dict):
            out.append({"name": name, "kind": "string", "len": length_bucket(len(value)), "nested": True})
        else:
            s = "" if value is None else str(value)
            out.append({"name": name, "kind": classify(value), "len": length_bucket(len(s))})
    return out


def build_sketch(
    *,
    method: str,
    path: str,
    query: Optional[dict] = None,
    body: Any = None,
    header_names: Optional[list[str]] = None,
    authenticated: bool = False,
    content_type: Optional[str] = None,
    status: int,
    res_content_type: Optional[str] = None,
    size_bytes: Optional[int] = None,
    duration_ms: Optional[float] = None,
) -> dict:
    route = normalize_path(path)
    body_obj = body if isinstance(body, dict) else None

    params = _shape_params(query) + _shape_params(body_obj)
    # dedupe by name (first wins), then sort by name — matches JS
    seen = set()
    deduped = []
    for p in params:
        if p["name"] in seen:
            continue
        seen.add(p["name"])
        deduped.append(p)
    deduped.sort(key=lambda p: p["name"])

    headers = sorted({h.lower() for h in (header_names or [])})

    # The shape is a REQUEST signature (method + route + params + auth). It deliberately excludes
    # status: enforcement decides whether to block BEFORE the response exists, so the identity a
    # request is matched against cannot depend on its status. Status is kept as an attribute below.
    shape = shape_hash(
        {
            "route": route,
            "method": method.upper(),
            "params": [[p["name"], p["kind"], 1 if p.get("nested") else 0] for p in deduped],
            "auth": 1 if authenticated else 0,
        }
    )

    sketch = {
        "v": SKETCH_VERSION,
        "route": route,
        "method": method.upper(),
        "params": deduped,
        "headers": headers,
        "authenticated": bool(authenticated),
        "status": status,
        "shape": shape,
    }
    if content_type:
        sketch["reqContentType"] = content_type
    if res_content_type:
        sketch["resContentType"] = res_content_type
    if size_bytes is not None:
        sketch["sizeBucket"] = length_bucket(size_bytes)
    if duration_ms is not None:
        sketch["latencyBucket"] = _latency_bucket(duration_ms)
    return sketch
