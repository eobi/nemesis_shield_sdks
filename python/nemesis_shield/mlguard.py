"""HashLR — ML prompt-injection classifier (Python). Byte-for-byte identical scoring to the JS/shared
implementation: feature buckets are int(fnv1a(feature),16) % dim, char n-grams over a canonicalized
(de-leetspeaked, ASCII-alnum) form. Complements the regex layer; catches obfuscation it misses."""

import json
import math
import os
import re

from .hash import fnv1a

with open(os.path.join(os.path.dirname(__file__), "ml_weights.json")) as _f:
    _MODEL = json.load(_f)

_DIM = _MODEL["dim"]
_BIAS = _MODEL["bias"]
_WEIGHTS = {int(k): v for k, v in _MODEL["weights"].items()}
ML_BLOCK_THRESHOLD = _MODEL.get("blockThreshold", 0.85)
ML_FLAG_THRESHOLD = _MODEL.get("flagThreshold", 0.45)
MODEL_VERSION = int(_MODEL.get("version", 1))


def refresh_model(url: str | None = None, timeout: float = 5.0):
    """Hot-swap the HashLR model from a cloud URL if a newer version is published — so the AI model
    can be retrained and pushed centrally without redeploying any SDK. Returns the new version number
    if updated, else None. Fail-safe: on any error the current (embedded) model is kept unchanged.

    URL defaults to env NEMESIS_MODEL_URL. The `dim` is fixed across versions (it defines the feature
    space); only weights / bias / thresholds are swapped."""
    import os
    import urllib.request

    global _WEIGHTS, _BIAS, MODEL_VERSION, ML_BLOCK_THRESHOLD, ML_FLAG_THRESHOLD
    url = url or os.environ.get("NEMESIS_MODEL_URL")
    if not url:
        return None
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            raw = r.read()
            sig = r.headers.get("X-Model-Signature")
        # Integrity: if a public key is pinned, the cloud bundle MUST carry a valid Ed25519 signature
        # over these exact bytes; otherwise we keep the current (trusted) model. With no key pinned,
        # verification is skipped and only the version gate + HTTPS transport apply.
        if not _verify_model_signature(raw, sig):
            return None
        m = json.loads(raw)
        if int(m.get("version", 0)) <= MODEL_VERSION or int(m.get("dim", _DIM)) != _DIM:
            return None
        _WEIGHTS = {int(k): v for k, v in m["weights"].items()}
        _BIAS = m["bias"]
        MODEL_VERSION = int(m["version"])
        ML_BLOCK_THRESHOLD = m.get("blockThreshold", ML_BLOCK_THRESHOLD)
        ML_FLAG_THRESHOLD = m.get("flagThreshold", ML_FLAG_THRESHOLD)
        return MODEL_VERSION
    except Exception:
        return None


# Ed25519 public key (hex) that signs published models. When set, cloud model pulls MUST carry a
# valid signature over the exact bytes (unsigned or tampered bundles are rejected; the embedded model
# is kept). Public key is safe to commit; the matching private seed lives only in the CI secret.
MODEL_PUBLIC_KEY_HEX = "23446c0eebba8871113c60c4ea2d8755a198d6b4c6ad1b6e2b6b097a2ce4e835"


def _verify_model_signature(raw: bytes, sig_b64) -> bool:
    if not MODEL_PUBLIC_KEY_HEX:
        return True  # no key pinned yet — version gate + HTTPS still protect the swap
    if not sig_b64:
        return False  # a key is pinned but the bundle is unsigned — reject
    try:
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(MODEL_PUBLIC_KEY_HEX)).verify(base64.b64decode(sig_b64), raw)
        return True
    except Exception:
        return False

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "8": "b", "|": "i"})
_WORD = re.compile(r"[a-z0-9']+")


def _canon(text: str) -> str:
    t = text.lower().translate(_LEET)
    return "".join(c for c in t if c.isascii() and c.isalnum())


def _bucket(s: str) -> int:
    return int(fnv1a(s), 16) % _DIM


def _features(text: str):
    b = set()
    ws = _WORD.findall(text.lower())
    for w in ws:
        b.add(_bucket("w:" + w))
    for i in range(len(ws) - 1):
        b.add(_bucket("b:" + ws[i] + " " + ws[i + 1]))
    c = _canon(text)
    for n in (3, 4, 5):
        for i in range(len(c) - n + 1):
            b.add(_bucket("c%d:" % n + c[i:i + n]))
    if len(text) > 2000:
        b.add(_bucket("e:long"))
    if sum(1 for ch in text if ord(ch) > 127) > 3:
        b.add(_bucket("e:nonascii"))
    return b


def ml_injection_score(text: str) -> float:
    """Probability (0..1) that `text` is a prompt-injection / jailbreak attempt."""
    z = _BIAS + sum(_WEIGHTS.get(bk, 0.0) for bk in _features(text))
    if z < -30:
        return 0.0
    if z > 30:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))
