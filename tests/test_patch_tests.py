from chameleon.patch import tests as patch_tests

SQLI_RULE = {
    "id": "r1", "field": "q", "type": "regex_deny",
    "pattern": r"union\s+select", "description": "sqli", "attack_type": "sqli",
}


def test_replay_test_passes_when_rule_blocks_every_payload():
    assert patch_tests.replay_test(SQLI_RULE, ["1 union select null--", "2 UNION SELECT x"])


def test_replay_test_fails_when_one_payload_slips_through():
    assert not patch_tests.replay_test(SQLI_RULE, ["1 union select null--", "1; drop table users"])


def test_normal_traffic_test_passes_when_nothing_blocked():
    ok, fpr = patch_tests.normal_traffic_test(SQLI_RULE, ["blue shirt", "search for shoes"])
    assert ok and fpr == 0.0


def test_normal_traffic_test_fails_when_benign_text_matches():
    ok, fpr = patch_tests.normal_traffic_test(SQLI_RULE, ["please union select my favorites"])
    assert not ok and fpr == 1.0


def test_normal_traffic_test_passes_with_no_examples():
    ok, fpr = patch_tests.normal_traffic_test(SQLI_RULE, [])
    assert ok and fpr == 0.0
