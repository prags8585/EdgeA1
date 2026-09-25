"""Auto-patching: every attack the honeypot catches starts the patch pipeline.

While the attacker is busy with fake data, a background worker on the Nano
writes a rule for that exact attack, runs the deterministic tests and the
verifier, and -- once approved -- the front door blocks the next attempt
outright. Jobs run one at a time so they don't starve the honeypot of GPU, and
an attack that an approved rule already blocks isn't queued again.
"""
from __future__ import annotations

import functools
import queue
import random
import threading
import time
import uuid

import pandas as pd

from . import config, db
from .patch import integrate
from .patch import pipeline as patch_pipeline
from .patch import redis_store
from .patch import rules as rules_engine
from .patch import store as patch_store

_jobs: queue.Queue = queue.Queue()
_worker_started = False
_worker_lock = threading.Lock()

# Benign traffic the rule must not block, from the same kind of field.
_BENIGN_SOURCES = {"message": ("deepset", "jackhhao")}


@functools.lru_cache(maxsize=4)
def _benign_pool(sources: tuple[str, ...]) -> list[str]:
    df = pd.read_csv(config.ROOT / "data" / "check" / "test.csv", keep_default_na=False)
    return df[(df["label"] == 0) & (df["source"].isin(sources))]["text"].tolist()


# Real-looking customer input that uses the same characters attacks do. A random
# sample of normal traffic rarely contains any, so a rule like "block every ';'"
# used to pass the normal-traffic test and then 403 real searches. Every rule
# must now let all of these through. The first entry in each list is the false
# positive found in live testing on Sep 25.
HARD_NEGATIVES = {
    "q": ["Tom & Jerry DVD; season 1", "O'Brien running shoes", "50% off -- summer sale", "<3 valentine gifts",
          "rock | paper | scissors t-shirt", "shoes size 9; wide fit", "Q&A book: C++ & Java",
          "select your size chart", "union jack flag", "AT&T phone case", "1/2 price hats", "\"best\" wireless mouse"],
    "name": ["reports/2024-Q3.pdf", "invoice_2024.pdf", "my file (1).txt", "photos/summer-2024.jpg"],
    "username": ["o'connor", "mary-ann", "d'angelo_22", "j.smith"],
    "password": ["P@ss;word|2024", "correct horse battery staple", "O'Reilly#1", "--summer--"],
    "message": ["Please ignore my last message, I meant order #4417",
                "Can you ignore the old address and ship to the new one?",
                "What's your return policy; do you cover shipping?", "I forgot my password, how do I reset it?",
                "Is the <3 emoji allowed in gift notes?", "Order #88 & #89 arrived -- thanks!"],
}


def benign_examples(field: str, n: int = 30) -> list[str]:
    pool = _benign_pool(_BENIGN_SOURCES.get(field, ("httpparams",)))
    return HARD_NEGATIVES.get(field, []) + random.Random(field).sample(pool, min(n, len(pool)))


def submit(conn, field: str, payload: str, attack_type: str) -> str | None:
    """Queue a patch job for one captured attack; None if it's already covered.
    The job is stored in, and later run against, the same database as `conn`."""
    if rules_engine.blocked_by(patch_store.active_rules(conn), {field: payload}):
        return None
    dup = conn.execute(
        "SELECT id FROM patch_jobs WHERE payload = ? AND field = ? AND status IN ('queued', 'running')",
        (payload, field),
    ).fetchone()
    if dup:
        return dup["id"]
    job_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO patch_jobs (id, ts, field, payload, attack_type, status) VALUES (?, ?, ?, ?, ?, 'queued')",
        (job_id, time.time(), field, payload, attack_type),
    )
    conn.commit()
    db_path = conn.execute("PRAGMA database_list").fetchone()["file"]
    _ensure_worker()
    _jobs.put((job_id, db_path))
    return job_id


def _ensure_worker() -> None:
    global _worker_started
    with _worker_lock:
        if not _worker_started:
            _worker_started = True
            threading.Thread(target=_work, daemon=True, name="autopatch").start()


def _work() -> None:
    while True:
        job_id, db_path = _jobs.get()
        try:
            run_job(job_id, db_path)
        finally:
            _jobs.task_done()


def run_job(job_id: str, db_path) -> None:
    conn = db.get_connection(db_path)
    try:
        db.init_db(conn)
        job = conn.execute("SELECT * FROM patch_jobs WHERE id = ?", (job_id,)).fetchone()
        if job is None or job["status"] != "queued":
            return  # reset while queued, or already handled
        # Another job may have produced a rule that covers this one in the meantime.
        if rules_engine.blocked_by(patch_store.active_rules(conn), {job["field"]: job["payload"]}):
            _finish(conn, job_id, "skipped", None, "already blocked by an approved rule")
            return
        conn.execute("UPDATE patch_jobs SET status = 'running' WHERE id = ?", (job_id,))
        conn.commit()
        try:
            result = patch_pipeline.run(
                conn,
                attack_type=job["attack_type"],
                attack_payloads=[job["payload"]],
                benign_examples=benign_examples(job["field"]),
                writer_model=config.WRITER_MODEL_NAME,
                field=job["field"],
            )
        except Exception as exc:  # noqa: BLE001 - recorded on the job for the dashboard
            _finish(conn, job_id, "error", None, f"{type(exc).__name__}: {str(exc)[:200]}")
            return
        _finish(conn, job_id, result["status"], result.get("patch_id"), result.get("feedback"))
        if result["status"] == "approved":
            # Record which attack taught this patch, then re-render so the code says so too.
            redis_store.annotate(result["patch_id"], learned_from=job["payload"], learned_field=job["field"],
                                 patch_job_id=job_id)
            integrate.sync_active(conn)
    finally:
        conn.close()


def _finish(conn, job_id: str, status: str, patch_id: str | None, detail: str | None) -> None:
    conn.execute(
        "UPDATE patch_jobs SET status = ?, patch_id = ?, detail = ?, finished_ts = ? WHERE id = ?",
        (status, patch_id, detail, time.time(), job_id),
    )
    conn.commit()


def recent(conn, limit: int = 30) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM patch_jobs ORDER BY ts DESC LIMIT ?", (limit,))]
