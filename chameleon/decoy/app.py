"""Decoy app: a fake copy of the shop, hosted on the Nano (port 8300).

Requests flagged as malicious are redirected here by the gateway. It serves
the same four endpoints as the real app, with the same response shapes, but
nothing here is real: every answer is written live by the honeypot model on
the Nano (Qwen3-Next-80B), seeded with this attacker's own fake credentials
(honeytokens), so the attack appears to work. Every payload is logged to the
attacker's session.

It shares no data with the real app. The session comes from the gateway's
redirect (?cs=...), the X-Chameleon-Session header, or a cookie; a visitor
who arrives with none -- someone who found the decoy directly -- gets a new
session.
"""
from __future__ import annotations

import uuid

from fastapi import FastAPI, Request, Response
from pydantic import BaseModel

from .. import db
from ..honeypot import session as honeypot_session
from ..targets import SESSION_HEADER, SESSION_PARAM

app = FastAPI(title="ShopLegacy")  # what an attacker sees in any error page or /docs probe


def _session(request: Request, conn) -> str:
    candidate = (request.headers.get(SESSION_HEADER) or request.query_params.get(SESSION_PARAM)
                 or request.cookies.get(SESSION_PARAM) or "")
    try:
        candidate = str(uuid.UUID(candidate))
    except ValueError:
        candidate = ""
    if candidate and conn.execute("SELECT 1 FROM sessions WHERE id = ?", (candidate,)).fetchone():
        return candidate
    return honeypot_session.start_session(session_type="decoy-direct", conn=conn)


def _reply(request: Request, response: Response, inputs: dict[str, str]) -> str:
    conn = db.get_connection()
    try:
        db.init_db(conn)
        session_id = _session(request, conn)
        response.set_cookie(SESSION_PARAM, session_id, httponly=True, samesite="lax")
        response.headers["X-Powered-By"] = "PHP/5.6.40"  # part of the costume
        payload = " | ".join(f"{k}={v}" for k, v in inputs.items())
        return honeypot_session.respond(session_id, field=",".join(inputs), payload=payload, conn=conn)
    finally:
        conn.close()


class LoginRequest(BaseModel):
    username: str = ""
    password: str = ""


class ChatRequest(BaseModel):
    message: str = ""


@app.post("/login")
def login(req: LoginRequest, request: Request, response: Response):
    text = _reply(request, response, {"username": req.username, "password": req.password})
    return {"ok": True, "user": "admin", "role": "superadmin", "message": text}


@app.get("/search")
def search(request: Request, response: Response, q: str = ""):
    return {"results": _reply(request, response, {"q": q})}


@app.get("/files")
def files(request: Request, response: Response, name: str = ""):
    return {"name": name, "content": _reply(request, response, {"name": name})}


@app.post("/chat")
def chat(req: ChatRequest, request: Request, response: Response):
    return {"reply": _reply(request, response, {"message": req.message})}


# The text an attacker reads in each endpoint's response.
REPLY_FIELD = {"login": "message", "search": "results", "files": "content", "chat": "reply"}
