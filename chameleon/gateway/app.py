"""Front-door gateway (port 8000): the address clients, and attackers, use.

Every request goes through chameleon.router (Jev first, then the Nano check
model and the approved patches), and then:
  - safe            -> proxied to the real app, response passed back as is;
  - malicious       -> 307 redirect to the decoy app on the Nano, carrying the
                       honeypot session, so the attacker's next steps all land
                       in the fake app (307 keeps the method and body, so a
                       redirected POST /login is replayed as a POST);
  - stolen honeytoken, or an attack an approved patch covers -> 403.
A patch job for a new attack starts in the background as the redirect goes out.

Try it:  curl -L 'http://127.0.0.1:8000/search?q=shoes'
         curl -L 'http://127.0.0.1:8000/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--'
"""
from __future__ import annotations

import urllib.parse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel

from .. import config, router
from ..targets import SESSION_PARAM, TARGETS, forward

app = FastAPI(title="ShopLegacy")


def _blocked(blocked: dict) -> JSONResponse:
    if blocked["why"] == "stolen_honeytoken":
        body = {"error": "ACCOUNT COMPROMISED: Stolen credentials detected.",
                "detail": "This account is a honeypot decoy. Your session has been traced and logged."}
    else:
        body = {"error": "Request blocked by security policy.", "rule": blocked.get("rule_id")}
    return JSONResponse(body, status_code=403)


def _handle(request: Request, target: str, inputs: dict[str, str]) -> Response:
    try:
        result = router.handle_request(inputs, respond=False)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="service temporarily unavailable") from exc

    if result["routed_to"] == "blocked":
        return _blocked(result["blocked"])

    _method, path, _fields = TARGETS[target]
    if result["routed_to"] == "honeypot":
        query = [(k, v) for k, v in request.query_params.multi_items() if k != SESSION_PARAM]
        query.append((SESSION_PARAM, result["session_id"]))
        return RedirectResponse(f"{config.DECOY_APP_URL}{path}?{urllib.parse.urlencode(query)}", status_code=307)

    try:
        upstream = forward(config.DEMO_APP_URL, target, inputs)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="upstream unavailable") from exc
    return Response(upstream.content, status_code=upstream.status_code,
                    media_type=upstream.headers.get("content-type"))


class LoginRequest(BaseModel):
    username: str = ""
    password: str = ""


class ChatRequest(BaseModel):
    message: str = ""


@app.post("/login")
def login(req: LoginRequest, request: Request):
    return _handle(request, "login", {"username": req.username, "password": req.password})


@app.get("/search")
def search(request: Request, q: str = ""):
    return _handle(request, "search", {"q": q})


@app.get("/files")
def files(request: Request, name: str = ""):
    return _handle(request, "files", {"name": name})


@app.post("/chat")
def chat(req: ChatRequest, request: Request):
    return _handle(request, "chat", {"message": req.message})
