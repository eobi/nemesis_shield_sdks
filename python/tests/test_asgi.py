import asyncio
from nemesis_shield.asgi import SentinelMiddleware

def drive(mw, scope):
    sent = []
    async def receive(): return {"type": "http.request", "body": b"", "more_body": False}
    async def send(ev): sent.append(ev)
    asyncio.run(mw(scope, receive, send))
    return sent

def make_scope(path="/users/5", method="GET", headers=None):
    return {"type": "http", "method": method, "path": path, "query_string": b"",
            "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()]}

def test_observe_records_and_passes_through():
    recorded = []
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})
    mw = SentinelMiddleware(app, token="t", transport=lambda b, t: recorded.append(b))
    sent = drive(mw, make_scope())
    assert any(e["type"] == "http.response.start" and e["status"] == 200 for e in sent)
    mw.client.flush()
    assert recorded and recorded[0][0]["route"] == "/users/{int}"

def test_enforce_blocks_known_bad():
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"secret"})
    mw = SentinelMiddleware(app, token="t", mode="enforce", transport=lambda b, t: None)
    from nemesis_shield import build_sketch
    pre = build_sketch(method="GET", path="/admin", status=0)["shape"]
    mw.client.set_policy({"shapes": {pre: "block"}})
    sent = drive(mw, make_scope(path="/admin"))
    assert any(e.get("status") == 403 for e in sent if e["type"] == "http.response.start")
