import json
import shutil
from pathlib import Path

import fakeredis
import pytest

from chameleon import db
from chameleon.patch import integrate, redis_store, store

APPS = Path(__file__).parent.parent / "chameleon" / "apps"
RULE = {"id": "sqli-1", "field": "q", "type": "normalize_then_deny",
        "pattern": r"union\s+select", "description": "blocks UNION SELECT", "attack_type": "sqli"}


@pytest.fixture
def conn(tmp_path):
    c = db.get_connection(tmp_path / "p.db")
    db.init_db(c)
    return c


@pytest.fixture
def r():
    fake = fakeredis.FakeRedis(decode_responses=True)
    redis_store.use(fake)
    return fake


@pytest.fixture
def apps(tmp_path, monkeypatch):
    copy = tmp_path / "apps"
    shutil.copytree(APPS, copy, ignore=shutil.ignore_patterns("__pycache__"))
    monkeypatch.setattr(integrate.config, "APPS_DIR", copy)
    integrate.ENABLED = True
    return copy


def test_patch_lifecycle_is_mirrored_to_redis_and_rendered_into_the_right_app(conn, r, apps):
    pid = store.propose(conn, RULE, "writer")
    store.log_event(conn, pid, "replay_test", "pass")
    assert store.active_rules(conn) == []  # proposed isn't enforced

    store.set_status(conn, pid, "approved")

    assert store.active_rules(conn) == [RULE]
    rec = r.hgetall(f"chameleon:patch:{pid}")
    assert rec["status"] == "approved" and rec["app_files"] == "search_app.py"
    assert "def sqli_1_" in rec["python_code"]
    assert json.loads(r.lrange(f"chameleon:patch:{pid}:events", 0, -1)[0])["stage"] == "replay_test"
    assert pid in (apps / "search_app.py").read_text()
    assert pid not in (apps / "login_app.py").read_text()

    store.rollback(conn, pid)
    assert store.active_rules(conn) == []
    assert pid not in (apps / "search_app.py").read_text()
    assert integrate.EMPTY in (apps / "search_app.py").read_text()


def test_reset_retires_active_patches_but_keeps_history(conn, r):
    pid = store.propose(conn, RULE, "writer")
    store.set_status(conn, pid, "approved")
    assert redis_store.deactivate_all() == 1
    assert store.active_rules(conn) == []
    assert r.hget(f"chameleon:patch:{pid}", "status") == "retired_by_reset"
    assert [p["id"] for p in redis_store.patches()] == [pid]


def test_redis_outage_falls_back_to_sqlite(conn, r):
    pid = store.propose(conn, RULE, "writer")
    store.set_status(conn, pid, "approved")

    class Down:
        def __getattr__(self, _name):
            raise ConnectionError("redis down")
    redis_store.use(Down())
    assert store.active_rules(conn) == [RULE]


def test_backfill_copies_older_patches_once(conn, r):
    redis_store.use(None)
    pid = store.propose(conn, RULE, "writer")
    store.set_status(conn, pid, "approved")
    redis_store.use(r)
    assert store.backfill_redis(conn) == 1 and store.backfill_redis(conn) == 0
    assert store.active_rules(conn) == [RULE]


def test_rendered_code_cannot_be_injected_through_rule_fields(apps):
    hostile = {**RULE, "id": "x'); import os; os.system('id') #",
               "pattern": "'''\nimport os\n\"\"\"", "description": "\n__import__('os')\n"}
    integrate.sync([{"id": "p1", "rule_json": json.dumps(hostile), "learned_from": "a\nimport os"}], apps_dir=apps)
    source = (apps / "search_app.py").read_text()
    compile(source, "search_app.py", "exec")
    block = source[source.index(integrate.BEGIN):source.index(integrate.END)]
    assert "\nimport os" not in block and "\n__import__" not in block


def test_sync_is_idempotent(apps):
    patch = {"id": "p1", "rule_json": json.dumps(RULE)}
    integrate.sync([patch], apps_dir=apps)
    first = (apps / "search_app.py").read_text()
    integrate.sync([patch], apps_dir=apps)
    assert (apps / "search_app.py").read_text() == first and first.count("@patches.guard") == 1


def test_literal_round_trips_exactly():
    import ast
    for text in [r"union\s+select", r"a'b\"c", "ends with backslash\\", "'''\"\"\"", "new\nline", r"\.\./"]:
        assert ast.literal_eval(integrate.literal(text)) == text
