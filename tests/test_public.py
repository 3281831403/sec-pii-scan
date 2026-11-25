from pii.scan import DEFAULT_RULES, scan_batch, scan_table


def test_recognizes_mobile():
    table = {
        "phone": "13800138000",
        "order_no": "20231118001",
    }

    hits = scan_table(table, DEFAULT_RULES, [])

    assert [hit["kind"] for hit in hits] == ["mobile"]


def test_recognizes_id_card():
    table = {
        "identity": "11010519491231002X",
        "candidate": "110105194912310021",
    }

    hits = scan_table(table, DEFAULT_RULES, [])

    assert [(hit["kind"], hit["value"]) for hit in hits] == [
        ("id_card", "11010519491231002X")
    ]


def test_recognizes_email():
    table = {
        "email": "analyst@example.com",
        "broken": "analyst@example.com.",
    }

    hits = scan_table(table, DEFAULT_RULES, [])

    assert [hit["kind"] for hit in hits] == ["email"]


def test_hit_contains_field_path():
    table = {"contact.email": "analyst@example.com"}

    hits = scan_table(table, DEFAULT_RULES, [])

    assert len(hits) == 1
    assert hits[0].get("path") == "contact.email"


def test_batch_keeps_tables_independent():
    tables = {
        "users": {"phone": "13800138000"},
        "events": {"email": "ops@example.com"},
    }

    result = scan_batch(tables, DEFAULT_RULES)

    assert [hit["kind"] for hit in result["users"]] == ["mobile"]
    assert [hit["kind"] for hit in result["events"]] == ["email"]