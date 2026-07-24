from nemesis_shield import SentinelClient, build_sketch

def sk(path="/x", status=200):
    return build_sketch(method="GET", path=path, status=status)

def test_requires_token():
    try:
        SentinelClient("")
        assert False
    except ValueError:
        pass

def test_observe_never_blocks():
    c = SentinelClient("t")
    c.set_policy({"shapes": {sk()["shape"]: "block"}})
    assert c.should_block(c.decide(sk())) is False

def test_enforce_blocks_known_bad_only():
    s = sk()
    c = SentinelClient("t", mode="enforce")
    c.set_policy({"shapes": {s["shape"]: "block"}})
    assert c.should_block(c.decide(s)) is True
    assert c.should_block(c.decide(sk("/other"))) is False

def test_global_known_bad():
    bad = sk("/evil")
    c = SentinelClient("t", mode="enforce")
    c.set_policy({"shapes": {}, "knownBad": [bad["shape"]]})
    assert c.should_block(c.decide(bad)) is True

def test_batches_and_applies_pushed_policy():
    seen = []
    def transport(batch, token):
        seen.append(batch)
        return {"policy": {"shapes": {"deadbeef": "block"}}}
    c = SentinelClient("t", transport=transport, batch_size=2)
    c.record(sk("/a")); c.record(sk("/b"))  # triggers flush at batch_size
    assert len(seen) == 1 and len(seen[0]) == 2
    assert c.decide({"shape": "deadbeef"})["action"] == "block"

def test_fails_open_on_transport_error():
    errs = []
    def transport(batch, token):
        raise RuntimeError("network down")
    c = SentinelClient("t", transport=transport, on_error=lambda e: errs.append(e))
    c.record(sk())
    c.flush()  # must not raise
    assert len(errs) >= 1
