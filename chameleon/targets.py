"""The four demo-app endpoints, shared by the dashboard, the gateway and the
decoy so a request is forwarded exactly the way the real app receives it."""
from __future__ import annotations

import httpx

# target: (method, path, fields)
TARGETS = {
    "login": ("POST", "/login", ("username", "password")),
    "search": ("GET", "/search", ("q",)),
    "files": ("GET", "/files", ("name",)),
    "chat": ("POST", "/chat", ("message",)),
}
BY_PATH = {path: name for name, (_m, path, _f) in TARGETS.items()}

# Header the gateway/dashboard use to tell the decoy which honeypot session a request belongs to.
SESSION_HEADER = "X-Chameleon-Session"
SESSION_PARAM = "cs"


def forward(base_url: str, target: str, inputs: dict[str, str], headers: dict | None = None,
            timeout: float = 10) -> httpx.Response:
    method, path, _ = TARGETS[target]
    if method == "GET":
        return httpx.get(f"{base_url}{path}", params=inputs, headers=headers, timeout=timeout)
    return httpx.post(f"{base_url}{path}", json=inputs, headers=headers, timeout=timeout)
