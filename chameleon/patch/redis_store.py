"""Redis patch store: every generated patch, its Python code, and its test trail.

The pipeline records each attempt in SQLite as it goes (chameleon.patch.store);
every write is mirrored here, and Redis is where the finished patches live:
the front door reads the active rule set from it, and the four demo apps get
their code patches rendered from it. Keys (all under "chameleon:"):

  patch:<id>            hash: id, version, status, attack_type, field, type,
                        pattern, rule_json, python_code, app_files,
                        writer_model, created_at, updated_at, learned_from
  patch:<id>:events     list of JSON test results (replay, encoding, normal
                        traffic, ReDoS, verifier), oldest first
  patches:all           sorted set of every patch id, by creation time
  patches:active        sorted set of approved patches currently enforced
  channel "chameleon:patches"   a JSON message on every status change

A demo reset only empties patches:active: the history stays.

Redis is optional: with no REDIS_URL, or if the server is down, every call
here is a no-op and SQLite alone is used, so an outage never breaks requests.
"""
from __future__ import annotations

import json
import logging
import time

from .. import config

log = logging.getLogger(__name__)

PREFIX = "chameleon:"
_client = None
_disabled = False


def client():
    """The Redis client, or None when Redis isn't configured or reachable."""
    global _client, _disabled
    if _disabled or not config.REDIS_URL:
        return None
    if _client is None:
        import redis

        _client = redis.Redis.from_url(config.REDIS_URL, decode_responses=True,
                                       socket_timeout=0.5, socket_connect_timeout=0.5)
    return _client


def use(new_client) -> None:
    """Point the store at a given client (tests), or None to disable it."""
    global _client, _disabled
    _client, _disabled = new_client, new_client is None


def _safe(fn):
    def wrapper(*args, **kwargs):
        r = client()
        if r is None:
            return None
        try:
            return fn(r, *args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - the patch store must never break a request
            log.warning("redis patch store: %s: %s", type(exc).__name__, exc)
            return None
    return wrapper


def _key(patch_id: str, suffix: str = "") -> str:
    return f"{PREFIX}patch:{patch_id}{suffix}"


@_safe
def record_proposed(r, patch_id: str, version: int, rule: dict, writer_model: str, created_at: float) -> None:
    pipe = r.pipeline()
    pipe.hset(_key(patch_id), mapping={
        "id": patch_id, "version": version, "status": "proposed", "attack_type": rule.get("attack_type", ""),
        "field": rule.get("field", ""), "type": rule.get("type", ""), "pattern": rule.get("pattern", ""),
        "rule_json": json.dumps(rule), "writer_model": writer_model,
        "created_at": created_at, "updated_at": created_at,
    })
    pipe.zadd(f"{PREFIX}patches:all", {patch_id: created_at})
    pipe.execute()


@_safe
def record_event(r, patch_id: str, stage: str, result: str, reason: str | None, ts: float) -> None:
    r.rpush(_key(patch_id, ":events"), json.dumps({"stage": stage, "result": result, "reason": reason, "ts": ts}))


@_safe
def record_status(r, patch_id: str, status: str, extra: dict | None = None) -> None:
    now = time.time()
    pipe = r.pipeline()
    pipe.hset(_key(patch_id), mapping={"status": status, "updated_at": now, **(extra or {})})
    if status == "approved":
        created = r.hget(_key(patch_id), "created_at")
        pipe.zadd(f"{PREFIX}patches:active", {patch_id: float(created or now)})
    else:
        pipe.zrem(f"{PREFIX}patches:active", patch_id)
    pipe.publish(f"{PREFIX}patches", json.dumps({"id": patch_id, "status": status, "ts": now}))
    pipe.execute()


@_safe
def annotate(r, patch_id: str, **fields) -> None:
    """Attach extra facts to a patch (its rendered Python, the attack it came from...)."""
    r.hset(_key(patch_id), mapping={k: v if isinstance(v, (int, float)) else str(v) for k, v in fields.items()})


@_safe
def active_rules(r) -> list[dict]:
    ids = r.zrange(f"{PREFIX}patches:active", 0, -1)
    if not ids:
        return []
    pipe = r.pipeline()
    for pid in ids:
        pipe.hget(_key(pid), "rule_json")
    return [json.loads(raw) for raw in pipe.execute() if raw]


@_safe
def active_patches(r) -> list[dict]:
    """Full records of the enforced patches, oldest first."""
    ids = r.zrange(f"{PREFIX}patches:active", 0, -1)
    pipe = r.pipeline()
    for pid in ids:
        pipe.hgetall(_key(pid))
    return [rec for rec in pipe.execute() if rec]


@_safe
def patches(r, limit: int = 100) -> list[dict]:
    """Newest first, with each one's test trail."""
    ids = r.zrevrange(f"{PREFIX}patches:all", 0, limit - 1)
    pipe = r.pipeline()
    for pid in ids:
        pipe.hgetall(_key(pid))
        pipe.lrange(_key(pid, ":events"), 0, -1)
    out = pipe.execute()
    return [{**out[i], "events": [json.loads(e) for e in out[i + 1]]} for i in range(0, len(out), 2) if out[i]]


@_safe
def deactivate_all(r) -> int:
    """Demo reset: stop enforcing every patch, keep the history."""
    ids = r.zrange(f"{PREFIX}patches:active", 0, -1)
    pipe = r.pipeline()
    for pid in ids:
        pipe.hset(_key(pid), mapping={"status": "retired_by_reset", "updated_at": time.time()})
    pipe.delete(f"{PREFIX}patches:active")
    pipe.execute()
    return len(ids)


@_safe
def health(r) -> dict:
    return {"ok": bool(r.ping()), "patches": r.zcard(f"{PREFIX}patches:all"),
            "active": r.zcard(f"{PREFIX}patches:active")}
