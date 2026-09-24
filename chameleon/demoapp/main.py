"""Demo target application: deliberately simple, protected by approved patch rules.

This is only a demo target, not the product (chameleon.patch.rules is). It
stays safe even under attack: /files never touches the real filesystem --
a traversal-shaped request just returns fake, canary-tagged content so a
successful attack is detectable, exactly like the honeypot's canaries.
"""
from __future__ import annotations

import json
import re

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .. import config, db
from ..patch import rules as rules_engine

app = FastAPI(title="Chameleon Edge demo app")

CANARY_ADMIN_PASSWORD = "CANARY-ADMIN-7f3a9c2e1b"
CANARY_API_KEY = "CANARY-APIKEY-9d4e6a1f2c"

PRODUCTS = [
    {"id": 1, "name": "blue shirt", "price": 19.99},
    {"id": 2, "name": "red shoes", "price": 49.99},
    {"id": 3, "name": "green hat", "price": 12.5},
]

USERS = {
    "admin": CANARY_ADMIN_PASSWORD,
    "jsmith": "hunter2",
}

SAFE_FILES = {
    "readme.txt": "Welcome to the demo shop.",
    "changelog.txt": "v1.0 initial release",
}

# Only returned when a request looks like it's trying to escape SAFE_FILES;
# content is fake, but the embedded token lets us detect the leak downstream.
CANARY_FILE_CONTENT = f"root:x:0:0:root:/root:/bin/bash\n# leaked api_key={CANARY_API_KEY}\n"

TRAVERSAL_HINT = re.compile(r"\.\./|%2e%2e|/etc/|\\windows\\", re.IGNORECASE)


def _active_rules() -> list[dict]:
    conn = db.get_connection(config.DB_PATH)
    try:
        db.init_db(conn)
        rows = conn.execute(
            "SELECT rule_json FROM patches WHERE status = 'approved' ORDER BY created_at"
        ).fetchall()
        return [json.loads(r["rule_json"]) for r in rows]
    finally:
        conn.close()


def _enforce(inputs: dict[str, str]) -> None:
    rule = rules_engine.blocked_by(_active_rules(), inputs)
    if rule:
        raise HTTPException(status_code=403, detail=f"blocked by rule {rule['id']}")


@app.get("/search")
def search(q: str = ""):
    _enforce({"q": q})
    ql = q.lower()
    return {"results": [p for p in PRODUCTS if ql in p["name"].lower()]}


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(req: LoginRequest):
    _enforce({"username": req.username, "password": req.password})
    ok = USERS.get(req.username) == req.password
    return {"ok": ok}


@app.get("/files")
def files(name: str = ""):
    _enforce({"name": name})
    if name in SAFE_FILES:
        return {"name": name, "content": SAFE_FILES[name]}
    if TRAVERSAL_HINT.search(name):
        return {"name": name, "content": CANARY_FILE_CONTENT}
    raise HTTPException(status_code=404, detail="file not found")


class ChatRequest(BaseModel):
    message: str


@app.post("/chat")
def chat(req: ChatRequest):
    _enforce({"message": req.message})
    return {"reply": f"Thanks for your message! (demo assistant) You said: {req.message[:200]}"}
