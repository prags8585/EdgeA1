"""SQLite schema and helpers. Plain sqlite3, no ORM -- this is a 1-day build."""
from __future__ import annotations

import sqlite3
import time
import uuid
from pathlib import Path

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    inputs_hash TEXT NOT NULL,
    jev_score REAL,
    nano_score REAL,
    decision TEXT NOT NULL,        -- 'safe' | 'malicious'
    latency_ms REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    ts_start REAL NOT NULL,
    ts_end REAL,
    session_type TEXT NOT NULL,    -- 'web' | 'chat'
    status TEXT NOT NULL DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS attack_events (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    ts REAL NOT NULL,
    field TEXT,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS patches (
    id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    status TEXT NOT NULL,          -- 'proposed' | 'approved' | 'rejected' | 'rolled_back'
    attack_type TEXT,
    rule_json TEXT NOT NULL,
    writer_model TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS patch_events (
    id TEXT PRIMARY KEY,
    patch_id TEXT NOT NULL REFERENCES patches(id),
    stage TEXT NOT NULL,           -- 'replay_test' | 'normal_traffic_test' | 'verifier'
    result TEXT NOT NULL,          -- 'pass' | 'fail'
    reason TEXT,
    ts REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS llm_calls (
    id TEXT PRIMARY KEY,
    run_id TEXT,
    provider TEXT NOT NULL,        -- 'nano' | 'cloud'
    model TEXT NOT NULL,
    role TEXT NOT NULL,            -- 'honeypot' | 'writer' | 'verifier' | 'check'
    session_id TEXT,
    latency_ms REAL NOT NULL,
    in_tokens INTEGER NOT NULL DEFAULT 0,
    out_tokens INTEGER NOT NULL DEFAULT 0,
    est_cost_usd REAL NOT NULL DEFAULT 0,
    ok INTEGER NOT NULL,
    error TEXT,
    placement_reason TEXT,
    ts REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    started_at REAL NOT NULL,
    finished_at REAL,
    notes TEXT
);
"""


def get_connection(path: Path | str | None = None) -> sqlite3.Connection:
    db_path = Path(path or config.DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def log_llm_call(
    conn: sqlite3.Connection,
    *,
    provider: str,
    model: str,
    role: str,
    latency_ms: float,
    in_tokens: int = 0,
    out_tokens: int = 0,
    est_cost_usd: float = 0.0,
    ok: bool = True,
    error: str | None = None,
    session_id: str | None = None,
    run_id: str | None = None,
    placement_reason: str | None = None,
) -> str:
    call_id = str(uuid.uuid4())
    conn.execute(
        """INSERT INTO llm_calls
           (id, run_id, provider, model, role, session_id, latency_ms,
            in_tokens, out_tokens, est_cost_usd, ok, error, placement_reason, ts)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (call_id, run_id, provider, model, role, session_id, latency_ms,
         in_tokens, out_tokens, est_cost_usd, int(ok), error, placement_reason, time.time()),
    )
    conn.commit()
    return call_id
