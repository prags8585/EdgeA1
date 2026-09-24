import json

import pandas as pd

from chameleon import db, fusion, llm
from chameleon.honeypot import session as honeypot_session
from chameleon.patch import verifier as patch_verifier
from chameleon.patch import writer as patch_writer
from chameleon.redteam import scenario

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd", "../../etc/shadow", "..%2f..%2fetc/passwd",
    "../../../../etc/hosts", "../../boot.ini", "../../../windows/win.ini",
]
BENIGN_TEXTS = ["blue shirt", "red shoes", "green hat", "search for a jacket", "size medium"]

GOOD_RULE = {
    "id": "path-traversal-1", "field": "name", "type": "normalize_then_deny",
    "pattern": r"\.\./", "description": "blocks path traversal", "attack_type": "path-traversal",
}


def _write_fixture_csvs(data_dir):
    rows = [{"text": t, "label": 0, "source": "test", "attack_type": "benign"} for t in BENIGN_TEXTS]
    rows += [{"text": t, "label": 1, "source": "test", "attack_type": "path-traversal"} for t in TRAVERSAL_PAYLOADS]
    df = pd.DataFrame(rows)
    df.to_csv(data_dir / "test.csv", index=False)
    df[df["attack_type"] == "path-traversal"].to_csv(data_dir / "heldout.csv", index=False)


def test_scenario_closes_the_loop_on_the_held_out_attack(tmp_path, monkeypatch):
    _write_fixture_csvs(tmp_path)
    conn = db.get_connection(tmp_path / "scenario.db")
    db.init_db(conn)

    # The Nano check model genuinely can't catch path traversal (0% held-out
    # recall, see HANDOFF.md section 13) -- simulate that blind spot exactly.
    monkeypatch.setattr(fusion, "check_nano", lambda inputs: {
        "malicious": False, "score": 0.05, "worst_input_index": 0, "latency_ms": 1.0,
    })
    # Avoid needing a live honeypot LLM for this test; the point here is the
    # detection/patch/re-detection loop, not honeypot chat quality.
    monkeypatch.setattr(honeypot_session, "respond", lambda *a, **k: "fake honeypot reply")
    # Avoid needing live writer/verifier LLMs; use a real, working rule so
    # the actual fusion + rules + patch-store integration gets exercised.
    monkeypatch.setattr(patch_writer, "write_rule", lambda *a, **k: GOOD_RULE)
    monkeypatch.setattr(patch_verifier, "verify", lambda *a, **k: {"approved": True, "reasons": [], "risks": []})

    result = scenario.run(
        conn, tmp_path,
        n_benign=3, n_sqli=0, n_prompt_injection=0, n_traversal=3,
    )

    assert result["wave1_detection_rate"] == 0.0
    assert result["patch_result"]["status"] == "approved"
    assert result["wave2_detection_rate"] == 1.0

    approved = conn.execute("SELECT COUNT(*) AS n FROM patches WHERE status = 'approved'").fetchone()["n"]
    assert approved == 1
