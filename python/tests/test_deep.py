"""Deep coverage test — drives the real WSGI middleware end to end and proves the Python SDK SEES an
attacker's request from ANY route and blocks it in enforce mode: unknown paths, injected/extra query
params, param-type / method / auth anomalies, knownBad. Also proves the safe-unlock (never block the
login/auth path), fail-open (no baseline), and that query params now change the shape. Run:
    python -m pytest tests/test_deep.py    (or: python tests/test_deep.py)
"""

from nemesis_shield.wsgi import SentinelWSGI
from nemesis_shield.sketch import build_sketch


def _app(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"ok"]


def _env(method="GET", path="/", qs="", authed=False, cookie=False, ct=None):
    e = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": qs}
    if authed:
        e["HTTP_AUTHORIZATION"] = "Bearer x"
    if cookie:
        e["HTTP_COOKIE"] = "session=1"
    if ct:
        e["CONTENT_TYPE"] = ct
    return e


class _Rec:
    def __init__(self):
        self.status = None

    def __call__(self, status, headers, exc_info=None):
        self.status = status


def _mw(mode="enforce", allow=(), known_bad=(), bootstrap=None):
    mw = SentinelWSGI(_app, "t", transport=lambda b, tok: None, mode=mode, bootstrap=bootstrap)
    mw.client._policy = {"shapes": {s: "allow" for s in allow}, "knownBad": list(known_bad)}
    mw.client._have_baseline = bool(allow) or bool(known_bad)
    return mw


def _blocked(mw, **kw):
    rec = _Rec()
    mw(_env(**kw), rec)
    return rec.status is not None and rec.status.startswith("403")


def _shape(method, path, qs="", authed=False):
    from urllib.parse import parse_qsl
    q = dict(parse_qsl(qs, keep_blank_values=True))
    return build_sketch(method=method, path=path, query=q, authenticated=authed, status=0)["shape"]


# Learned "normal": home, product-by-id, a search with one alnum param, an authed order POST.
_BASE = [
    ("GET", "/", ""),
    ("GET", "/products/12345", ""),
    ("GET", "/search", "q=shoes"),
    ("POST", "/api/orders", ""),
]
_ALLOW = [_shape(m, p, qs, authed=(m == "POST")) for (m, p, qs) in _BASE]


def test_query_params_change_shape():
    assert _shape("GET", "/search", "q=x") != _shape("GET", "/search", "q=x&inject=1")
    assert _shape("GET", "/search", "q=shoes") != _shape("GET", "/search", "q=' OR 1=1--")


def test_enforce_blocks_attacks_from_any_route():
    mw = _mw(allow=_ALLOW)
    # approved pass
    assert not _blocked(mw, method="GET", path="/")
    assert not _blocked(mw, method="GET", path="/products/999")
    assert not _blocked(mw, method="GET", path="/search", qs="q=boots")
    assert not _blocked(mw, method="POST", path="/api/orders", authed=True)
    # attacks blocked
    assert _blocked(mw, method="GET", path="/.env")
    assert _blocked(mw, method="GET", path="/wp-config.php.bak")
    assert _blocked(mw, method="GET", path="/search", qs="q=x&cmd=id")       # injected param
    assert _blocked(mw, method="GET", path="/search", qs="q=' OR 1=1--")     # kind change
    assert _blocked(mw, method="POST", path="/")                            # method anomaly
    assert _blocked(mw, method="GET", path="/api/orders")                   # auth anomaly (unauth)
    assert _blocked(mw, method="GET", path="/admin/config")


def test_known_bad_blocked():
    bad = _shape("POST", "/xmlrpc.php")
    mw = _mw(allow=_ALLOW, known_bad=[bad])
    assert _blocked(mw, method="POST", path="/xmlrpc.php")


def test_safe_unlock_never_blocks_auth_path():
    mw = _mw(allow=_ALLOW)
    assert not _blocked(mw, method="POST", path="/login", qs="next=x")
    assert not _blocked(mw, method="GET", path="/wp-login.php")
    assert not _blocked(mw, method="GET", path="/wp-admin/options.php")
    tight = _mw(allow=_ALLOW, bootstrap=["/custom-auth"])
    assert _blocked(tight, method="POST", path="/login")        # default replaced
    assert not _blocked(tight, method="POST", path="/custom-auth")


def test_fail_open_no_baseline():
    mw = _mw(allow=[])
    assert not _blocked(mw, method="GET", path="/.env")


def test_observe_mode_never_blocks():
    mw = _mw(mode="observe", allow=_ALLOW)
    assert not _blocked(mw, method="GET", path="/.env")


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    p = f = 0
    for fn in fns:
        try:
            fn(); p += 1; print(f"  ✓ {fn.__name__}")
        except Exception:
            f += 1; print(f"  ✗ {fn.__name__}"); traceback.print_exc()
    print(f"\n{'ALL ' + str(p) + ' PASSED' if f == 0 else str(f) + ' FAILED, ' + str(p) + ' passed'}")
    raise SystemExit(1 if f else 0)
