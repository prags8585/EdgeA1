"""Honeytokens: fake secrets the honeypot "leaks", unique per attacker session.

The honeypot plays along -- an attack appears to succeed and returns data --
but everything it can reveal is fabricated here, and every secret is unique to
that session. If any later request contains one of them (the attacker trying
the stolen admin password or API key), the front door knows immediately, and
knows which attack session it came from, even if the classifier sees nothing
suspicious in a normal-looking login.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import time

def issue(conn, session_id: str) -> dict:
    """Create this session's fake credentials and remember them as honeytokens."""
    suffix = secrets.token_hex(3)
    digits = f"{secrets.randbelow(10**8):08d}"
    creds = {
        "admin_password": f"Adm!n-{suffix}-2024",
        "api_key": f"sk_live_{secrets.token_hex(12)}",
        # 4111 1111 is a well-known test card prefix; 8 random digits keep it unique per session.
        "card": f"4111 1111 {digits[:4]} {digits[4:]}",
    }
    creds["password_hash"] = hashlib.sha1(creds["admin_password"].encode()).hexdigest()
    now = time.time()
    for kind in ("admin_password", "password_hash", "api_key", "card"):
        conn.execute(
            "INSERT INTO honeytokens (token, session_id, kind, username, ts) VALUES (?, ?, ?, ?, ?)",
            (creds[kind], session_id, kind, "admin", now),
        )
    conn.commit()
    return creds


def find_stolen(conn, inputs: dict[str, str]) -> dict | None:
    """The first honeytoken that appears anywhere in this request's inputs, if any."""
    text = " ".join(inputs.values())
    if not text.strip():
        return None
    for row in conn.execute("SELECT token, session_id, kind, username, ts FROM honeytokens"):
        if row["token"] in text:
            return dict(row)
    return None


def latest(conn) -> dict | None:
    """Most recently leaked admin credentials -- what a real attacker would copy
    out of the honeypot's reply. Used by the demo's Use_Stolen_Creds button."""
    row = conn.execute(
        "SELECT token, session_id, ts FROM honeytokens WHERE kind = 'admin_password' ORDER BY ts DESC LIMIT 1"
    ).fetchone()
    return None if row is None else {"username": "admin", "password": row["token"],
                                     "session_id": row["session_id"], "ts": row["ts"]}


# Labels only: the classifier says *malicious or not*; the patch writer and the
# dashboard want a readable attack type. A wrong label doesn't weaken the patch
# (the writer still sees the real payload); it just names it.
_TYPES = [
    ("path-traversal", re.compile(r"\.\./|\.\.\\|%2e%2e|/etc/(passwd|shadow)|boot\.ini|win\.ini", re.I)),
    ("xss", re.compile(r"<\s*script|onerror\s*=|onload\s*=|javascript:|<\s*img|<\s*svg", re.I)),
    ("cmdi", re.compile(r"[;|&`]\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh)\b|\$\(", re.I)),
    ("sqli", re.compile(r"'\s*(or|and)\s|union\s+select|--|;\s*drop\s|'\s*=\s*'|\bor\s+1\s*=\s*1", re.I)),
]


def attack_type(field: str, text: str) -> str:
    for name, pattern in _TYPES:
        if pattern.search(text):
            return name
    return "prompt-injection" if field == "message" else "other"
