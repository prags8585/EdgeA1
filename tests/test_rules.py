from chameleon.patch import rules

SQLI_RULE = {
    "id": "r1", "field": "*", "type": "regex_deny",
    "pattern": r"union\s+select|--", "description": "sqli", "attack_type": "sqli",
}
TRAVERSAL_RULE = {
    "id": "r2", "field": "name", "type": "normalize_then_deny",
    "pattern": r"\.\./", "description": "path traversal", "attack_type": "path-traversal",
}


def test_wildcard_rule_blocks_matching_field():
    assert rules.blocked_by([SQLI_RULE], {"q": "1 union select null--"}) == SQLI_RULE
    assert rules.blocked_by([SQLI_RULE], {"q": "blue shirt"}) is None


def test_field_scoped_rule_only_applies_to_its_field():
    assert rules.blocked_by([TRAVERSAL_RULE], {"name": "../../etc/passwd"}) == TRAVERSAL_RULE
    assert rules.blocked_by([TRAVERSAL_RULE], {"other": "../../etc/passwd"}) is None


def test_normalize_then_deny_catches_url_encoded_payload():
    encoded = {"name": "%2e%2e/%2e%2e/etc/passwd"}
    assert rules.blocked_by([TRAVERSAL_RULE], encoded) == TRAVERSAL_RULE


def test_no_rules_never_blocks():
    assert rules.blocked_by([], {"q": "1 union select null--"}) is None
