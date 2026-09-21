#!/usr/bin/env python3
"""Tests for the transactional SQLite case and evidence lifecycle."""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://idx:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "pw")

from mcp_server.core import case_store


def test_create_and_get_case():
    case_store._cases.clear()
    c = case_store.create_case("Test Case", ["1.2.3.4"], "note")
    cid = c["case_id"]
    assert cid.startswith("case_")
    got = case_store.get_case(cid)
    assert got["title"] == "Test Case"
    assert got["srcips"] == ["1.2.3.4"]


def test_create_can_atomically_store_initial_evidence_with_provenance():
    case_store._cases.clear()
    created = case_store.create_case(
        "Initial evidence", ["198.51.100.5"], actor="soc-l1",
        initial_evidence=[{
            "evidence_type": "event", "title": "Rule match", "summary": "Observed fact",
            "source": "wazuh", "source_ref": "event-1", "payload": {"rule_id": "1001"},
            "provenance": {"index": "wazuh-alerts-*"}, "idempotency_key": "event-1",
        }],
    )
    assert created["revision"] == 1
    assert len(created["evidence"]) == 1
    assert created["evidence"][0]["provenance"]["source_ref"] == "event-1"
    assert created["audit_log"][0]["detail"]["initial_evidence"] == 1


def test_add_iocs_dedups():
    case_store._cases.clear()
    created = case_store.create_case("IOC test")
    cid = created["case_id"]
    case_store.add_iocs(cid, ["evil.com", "evil.com", "d41d8cd98f00b204e9800998ecf8427e"], created["revision"])
    assert case_store.get_case(cid)["iocs"] == ["d41d8cd98f00b204e9800998ecf8427e", "evil.com"]


def test_add_verdict_appends():
    case_store._cases.clear()
    created = case_store.create_case("Verdict test")
    cid = created["case_id"]
    case_store.add_verdict(cid, "5.6.7.8", "true_positive", "c2 beacon", created["revision"])
    got = case_store.get_case(cid)
    assert len(got["verdicts"]) == 1
    assert got["verdicts"][0]["verdict"] == "true_positive"
    assert "5.6.7.8" in got["srcips"]


def test_get_missing_case_is_none():
    case_store._cases.clear()
    assert case_store.get_case("case_nonexistent") is None


def test_list_cases():
    case_store._cases.clear()
    case_store.create_case("A")
    case_store.create_case("B")
    assert len(case_store.list_cases()) == 2


def test_case_lifecycle_fields_are_optional_and_persisted():
    case_store._cases.clear()
    created = case_store.create_case(
        "Lifecycle", ["1.1.1.1"], "analyst note", owner="soc-l2",
        sla_due="2026-09-16T10:00:00Z", status="contained",
        containment="Blocked source IP", closure_reason="Validated remediation",
    )
    stored = case_store.get_case(created["case_id"])
    assert stored["owner"] == "soc-l2"
    assert stored["sla_due"] == "2026-09-16T10:00:00Z"
    assert stored["status"] == "containment"
    assert stored["containment"] == "Blocked source IP"
    assert stored["closure_reason"] == "Validated remediation"


def test_stale_mutation_is_rejected_and_current_revision_is_reported():
    case_store._cases.clear()
    created = case_store.create_case("Concurrency")
    updated = case_store.add_note(created["case_id"], "first", created["revision"], "analyst-a")
    assert updated["revision"] == 2
    try:
        case_store.assign_case(created["case_id"], "soc-l2", "", 1, "lead")
    except case_store.CaseConflict as exc:
        assert exc.current_revision == 2
    else:
        raise AssertionError("stale update was accepted")


def test_evidence_requires_provenance_and_is_idempotent():
    case_store._cases.clear()
    created = case_store.create_case("Evidence")
    kwargs = {
        "evidence_type": "event", "title": "Wazuh alert", "summary": "Rule matched",
        "source": "wazuh", "source_ref": "event-123", "observed_at": None,
        "payload": {"rule_id": "1001"}, "provenance": {"index": "wazuh-alerts-*"},
        "entities": [{"type": "asset", "value": "edge-01"}],
        "idempotency_key": "wazuh:event-123", "actor": "soc-l1",
    }
    stored = case_store.add_evidence(created["case_id"], expected_revision=1, **kwargs)
    assert stored["revision"] == 2
    assert stored["evidence"][0]["source_ref"] == "event-123"
    assert stored["evidence"][0]["provenance"]["added_by"] == "soc-l1"
    duplicate = case_store.add_evidence(created["case_id"], expected_revision=2, **kwargs)
    assert duplicate["revision"] == 2
    assert len(duplicate["evidence"]) == 1


def test_full_lifecycle_is_audited_and_survives_new_connections():
    case_store._cases.clear()
    case = case_store.create_case("Lifecycle durability", actor="soc-l1")
    case = case_store.assign_case(case["case_id"], "soc-l2", "2026-10-01T00:00:00Z", 1, "lead")
    case = case_store.update_status(case["case_id"], "investigating", "accepted", 2, "soc-l2")
    case = case_store.record_containment(case["case_id"], "isolate endpoint", "success", 3, "soc-l2")
    case = case_store.resolve_case(case["case_id"], "credential reset and host rebuilt", 4, "soc-l2")
    case = case_store.close_case(case["case_id"], "remediation validated", 5, "lead")
    loaded = case_store.get_case(case["case_id"])
    assert loaded["status"] == "closed"
    assert loaded["revision"] == 6
    assert len(loaded["status_transitions"]) == 5
    assert [entry["action"] for entry in loaded["audit_log"]] == [
        "case_created", "case_assigned", "status_changed", "containment_recorded",
        "case_resolved", "case_closed",
    ]
    assert case_store.case_stats()["journal_mode"].lower() == "wal"


def test_list_paginates_and_filters_inside_sqlite():
    case_store._cases.clear()
    case_store.create_case("A")
    case_store.create_case("B")
    page = case_store.list_cases(limit=1, offset=1)
    assert len(page) == 1
    assert case_store.count_cases() == 2


def test_case_list_preserves_canonical_entities_for_local_correlation():
    case_store._cases.clear()
    created = case_store.create_case("CVE investigation")
    stored = case_store.add_evidence(
        created["case_id"], evidence_type="vulnerability", title="Affected package",
        summary="Exact CVE evidence", source="wazuh", source_ref="vuln-1",
        observed_at=None, payload={"cve": "CVE-2026-12345"},
        provenance={"index": "wazuh-states-vulnerabilities-*"},
        entities=[{"type": "cve", "value": "CVE-2026-12345"}],
        idempotency_key="vuln-1", expected_revision=1, actor="soc-l1",
    )
    listed = case_store.list_cases()
    assert listed[0]["case_id"] == stored["case_id"]
    assert {"type": "cve", "value": "CVE-2026-12345"} in listed[0]["entities"]


def test_closed_case_requires_reopen_operation():
    case_store._cases.clear()
    case = case_store.create_case("Reopen")
    case = case_store.close_case(case["case_id"], "validated", 1, "lead")
    try:
        case_store.update_status(case["case_id"], "investigating", "bypass", 2, "analyst")
    except case_store.InvalidTransition:
        pass
    else:
        raise AssertionError("closed case bypassed dedicated reopen operation")
    reopened = case_store.reopen_case(case["case_id"], "new evidence", 2, "analyst")
    assert reopened["status"] == "investigating"
    assert reopened["closure_reason"] == ""
