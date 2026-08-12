import os
from fastapi import FastAPI
from nemesis_shield.asgi import SentinelMiddleware

app = FastAPI()

# Positive-security WAF. Observe mode until you approve a baseline; fail-open by design.
app.add_middleware(SentinelMiddleware, token=os.environ["NEMESIS_TOKEN"])


@app.get("/")
def root():
    return {"ok": True}


# Example object route. Check ownership in the handler; Nemesis catches the access
# pattern that deviates from this user's learned normal (the IDOR/BOLA class).
@app.get("/api/orders/{order_id}")
def get_order(order_id: str):
    return {"id": order_id, "note": "check ownership here"}
