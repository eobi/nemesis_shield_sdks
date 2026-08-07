"""FNV-1a hashing + stable stringify - byte-for-byte compatible with the JS shared package,
so a Python app and a Node app with the same behavioral shape produce the SAME shape hash and
share behavioral intelligence. Do not change without updating the JS side and the parity test."""

import json


def fnv1a(s: str) -> str:
    # JS does: h ^= charCodeAt(i); h = (h + ((h<<1)+(h<<4)+(h<<7)+(h<<8)+(h<<24))) >>> 0
    # which is exactly (h * 16777619) mod 2**32 (1+2+16+128+256+16777216 = 16777619).
    h = 0x811C9DC5
    for ch in s:
        h ^= ord(ch)
        h = (h * 16777619) & 0xFFFFFFFF
    return format(h, "08x")


def stable_stringify(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):  # must precede int (bool is a subclass of int)
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return json.dumps(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(stable_stringify(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys())
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + stable_stringify(v[k]) for k in keys) + "}"
    raise TypeError(f"unstringifiable: {type(v)}")


def shape_hash(obj) -> str:
    return fnv1a(stable_stringify(obj))
