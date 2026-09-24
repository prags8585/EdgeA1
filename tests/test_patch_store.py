from chameleon import db
from chameleon.patch import store

RULE = {"id": "r1", "field": "q", "type": "regex_deny", "pattern": "x", "description": "d", "attack_type": "sqli"}


def _conn(tmp_path):
    conn = db.get_connection(tmp_path / "store.db")
    db.init_db(conn)
    return conn


def test_propose_increments_version_per_attack_type(tmp_path):
    conn = _conn(tmp_path)
    id1 = store.propose(conn, RULE, "writer-model")
    id2 = store.propose(conn, RULE, "writer-model")

    v1 = conn.execute("SELECT version FROM patches WHERE id = ?", (id1,)).fetchone()["version"]
    v2 = conn.execute("SELECT version FROM patches WHERE id = ?", (id2,)).fetchone()["version"]
    assert v1 == 1 and v2 == 2


def test_set_status_and_active_rules(tmp_path):
    conn = _conn(tmp_path)
    patch_id = store.propose(conn, RULE, "writer-model")

    assert store.active_rules(conn) == []

    store.set_status(conn, patch_id, "approved")
    assert store.active_rules(conn) == [RULE]

    store.rollback(conn, patch_id)
    assert store.active_rules(conn) == []


def test_log_event_records_stage_and_reason(tmp_path):
    conn = _conn(tmp_path)
    patch_id = store.propose(conn, RULE, "writer-model")

    store.log_event(conn, patch_id, "replay_test", "fail", "missed one payload")

    row = conn.execute("SELECT * FROM patch_events WHERE patch_id = ?", (patch_id,)).fetchone()
    assert row["stage"] == "replay_test"
    assert row["result"] == "fail"
    assert row["reason"] == "missed one payload"
