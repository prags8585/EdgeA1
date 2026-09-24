from chameleon import db


def test_init_db_creates_expected_tables(tmp_path):
    conn = db.get_connection(tmp_path / "test.db")
    db.init_db(conn)

    tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"requests", "sessions", "attack_events", "patches", "patch_events", "llm_calls", "runs"} <= tables


def test_log_llm_call_records_a_row(tmp_path):
    conn = db.get_connection(tmp_path / "test.db")
    db.init_db(conn)

    call_id = db.log_llm_call(
        conn, provider="nano", model="writer", role="writer",
        latency_ms=12.5, in_tokens=10, out_tokens=5, ok=True,
    )

    row = conn.execute("SELECT * FROM llm_calls WHERE id = ?", (call_id,)).fetchone()
    assert row["provider"] == "nano"
    assert row["in_tokens"] == 10
    assert row["ok"] == 1
