#!/usr/bin/env python3
"""Transactional incident and evidence lifecycle store.

SQLite is the source of truth. The legacy ``BLUETEAM_CASE_STORE`` JSONL file
is imported once, inside a transaction, and is never modified or deleted.
Reads are local database reads and never query Wazuh.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import tempfile
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

logger = logging.getLogger("blue_team_mcp.case_store")

_LEGACY_CASE_PATH = os.environ.get("BLUETEAM_CASE_STORE", "").strip()
_CONFIGURED_DB_PATH = os.environ.get("BLUETEAM_CASE_DB", "").strip()
_CASE_MAX = max(1, int(os.environ.get("BLUETEAM_CASE_MAX", "500")))
_lock = threading.RLock()


def _database_path() -> str:
    if _CONFIGURED_DB_PATH:
        return _CONFIGURED_DB_PATH
    if _LEGACY_CASE_PATH:
        legacy = Path(_LEGACY_CASE_PATH)
        if legacy.suffix.lower() in {".db", ".sqlite", ".sqlite3"}:
            return str(legacy)
        return str(legacy.with_suffix(".sqlite3"))
    # Isolated fallback for tests. Production sets BLUETEAM_CASE_DB.
    return str(Path(tempfile.gettempdir()) / f"blueteam_cases_{os.getpid()}.sqlite3")


_DB_PATH = _database_path()
_VALID_STATUSES = {"open", "triage", "investigating", "containment", "resolved", "closed"}
_STATUS_ALIASES = {"contained": "containment"}
_TRANSITIONS = {
    "open": {"triage", "investigating", "containment", "resolved", "closed"},
    "triage": {"open", "investigating", "containment", "resolved", "closed"},
    "investigating": {"triage", "containment", "resolved", "closed"},
    "containment": {"investigating", "resolved", "closed"},
    "resolved": {"investigating", "closed"},
    "closed": {"investigating"},
}


class CaseConflict(RuntimeError):
    """Raised when a client tries to mutate a stale case revision."""

    def __init__(self, current_revision: int):
        self.current_revision = int(current_revision)
        super().__init__(f"case revision is {self.current_revision}")


class InvalidTransition(ValueError):
    """Raised when a case lifecycle transition is not allowed."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso_timestamp(value: Any, fallback: str | None = None) -> str:
    raw = str(value or fallback or _now()).strip()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError):
        return fallback or _now()


def _new_id(prefix: str = "case") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def _canonical_status(value: str | None) -> str:
    raw = str(value or "open").strip().lower()
    status = _STATUS_ALIASES.get(raw, raw)
    if status not in _VALID_STATUSES:
        raise ValueError(f"unsupported case status: {status}")
    return status


def _json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _json_load(value: Any, fallback: Any) -> Any:
    if value in (None, ""):
        return fallback
    try:
        return json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return fallback


@contextmanager
def _connection(*, write: bool = False) -> Iterator[sqlite3.Connection]:
    path = Path(_DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(path), timeout=15, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=15000")
    if write:
        db.execute("BEGIN IMMEDIATE")
    try:
        yield db
        if write:
            db.commit()
    except Exception:
        if write:
            db.rollback()
        raise
    finally:
        db.close()


def _init_schema() -> None:
    with _lock, _connection() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                owner TEXT NOT NULL DEFAULT '',
                sla_due TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open',
                containment TEXT NOT NULL DEFAULT '',
                resolution TEXT NOT NULL DEFAULT '',
                closure_reason TEXT NOT NULL DEFAULT '',
                closed_at TEXT,
                revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1)
            );
            CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status, updated_at DESC);
            CREATE TABLE IF NOT EXISTS case_entities (
                case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                entity_type TEXT NOT NULL,
                entity_value TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT '',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                PRIMARY KEY(case_id, entity_type, entity_value)
            );
            CREATE INDEX IF NOT EXISTS idx_case_entities_value ON case_entities(entity_type, entity_value);
            CREATE TABLE IF NOT EXISTS case_evidence (
                evidence_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                evidence_type TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL,
                source_ref TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                added_at TEXT NOT NULL,
                added_by TEXT NOT NULL DEFAULT '',
                payload_json TEXT NOT NULL DEFAULT '{}',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                idempotency_key TEXT,
                UNIQUE(case_id, idempotency_key)
            );
            CREATE INDEX IF NOT EXISTS idx_case_evidence_time ON case_evidence(case_id, observed_at DESC);
            CREATE TABLE IF NOT EXISTS case_notes (
                note_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                author TEXT NOT NULL DEFAULT '',
                body TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_case_notes_time ON case_notes(case_id, created_at DESC);
            CREATE TABLE IF NOT EXISTS case_verdicts (
                verdict_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                srcip TEXT NOT NULL DEFAULT '',
                verdict TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                actor TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS case_transitions (
                transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                from_status TEXT,
                to_status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                actor TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_case_transitions_time ON case_transitions(case_id, created_at);
            CREATE TABLE IF NOT EXISTS case_assignments (
                assignment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                assigned_by TEXT NOT NULL DEFAULT '',
                owner TEXT NOT NULL,
                sla_due TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS case_containments (
                containment_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                actor TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL,
                result TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS case_audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL DEFAULT '',
                revision INTEGER NOT NULL,
                detail_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_case_audit_time ON case_audit(case_id, audit_id DESC);
            """
        )
    _migrate_legacy_jsonl()


def _legacy_records(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass
    records: list[dict[str, Any]] = []
    for line in raw.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def _insert_entity(db: sqlite3.Connection, case_id: str, entity_type: str, value: str,
                   source: str, observed_at: str) -> None:
    value = str(value or "").strip()[:2048]
    if not value:
        return
    db.execute(
        """INSERT INTO case_entities(case_id, entity_type, entity_value, source, first_seen, last_seen)
           VALUES(?,?,?,?,?,?)
           ON CONFLICT(case_id, entity_type, entity_value) DO UPDATE SET
             last_seen=excluded.last_seen,
             source=CASE WHEN excluded.source <> '' THEN excluded.source ELSE case_entities.source END""",
        (case_id, entity_type[:64], value, source[:120], observed_at, observed_at),
    )


def _insert_audit(db: sqlite3.Connection, case_id: str, action: str, actor: str,
                  revision: int, detail: dict[str, Any] | None = None, *, created_at: str | None = None) -> None:
    db.execute(
        "INSERT INTO case_audit(case_id,created_at,action,actor,revision,detail_json) VALUES(?,?,?,?,?,?)",
        (case_id, created_at or _now(), action[:64], actor[:120], revision, _json_dump(detail or {})),
    )


def _insert_legacy_case(db: sqlite3.Connection, record: dict[str, Any]) -> bool:
    case_id = str(record.get("case_id") or "").strip()[:64]
    if not case_id:
        return False
    created_at = _iso_timestamp(record.get("created_at"))[:64]
    updated_at = _iso_timestamp(record.get("updated_at"), created_at)[:64]
    status = _canonical_status(str(record.get("status") or "open"))
    revision = max(1, int(record.get("revision") or 1))
    cursor = db.execute(
        """INSERT OR IGNORE INTO cases
           (case_id,title,created_at,updated_at,owner,sla_due,status,containment,resolution,closure_reason,closed_at,revision)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (case_id, str(record.get("title") or case_id)[:200], created_at, updated_at,
         str(record.get("owner") or "")[:120], str(record.get("sla_due") or "")[:64], status,
         str(record.get("containment") or "")[:4000], str(record.get("resolution") or "")[:4000],
         str(record.get("closure_reason") or "")[:2000], record.get("closed_at"), revision),
    )
    if not cursor.rowcount:
        return False
    for srcip in record.get("srcips") or []:
        _insert_entity(db, case_id, "source_ip", str(srcip), "legacy_case_store", created_at)
    for ioc in record.get("iocs") or []:
        _insert_entity(db, case_id, "ioc", str(ioc), "legacy_case_store", created_at)
    notes = str(record.get("notes") or "").strip()
    if notes:
        db.execute("INSERT INTO case_notes VALUES(?,?,?,?,?)",
                   (_new_id("note"), case_id, created_at, "legacy_import", notes[:4000]))
    for verdict in record.get("verdicts") or []:
        if not isinstance(verdict, dict):
            continue
        ts = _iso_timestamp(verdict.get("ts"), created_at)[:64]
        srcip = str(verdict.get("srcip") or "")[:45]
        db.execute("INSERT INTO case_verdicts VALUES(?,?,?,?,?,?,?)",
                   (_new_id("verdict"), case_id, ts, srcip,
                    str(verdict.get("verdict") or "unknown")[:32],
                    str(verdict.get("notes") or "")[:1000], "legacy_import"))
        _insert_entity(db, case_id, "source_ip", srcip, "legacy_case_store", ts)
    db.execute(
        "INSERT INTO case_transitions(case_id,from_status,to_status,created_at,actor,reason) VALUES(?,?,?,?,?,?)",
        (case_id, None, status, created_at, "legacy_import", "Migrated from JSONL case store"),
    )
    _insert_audit(db, case_id, "legacy_import", "system", revision,
                  {"source": str(_LEGACY_CASE_PATH)}, created_at=updated_at)
    return True


def _migrate_legacy_jsonl() -> None:
    if not _LEGACY_CASE_PATH:
        return
    path = Path(_LEGACY_CASE_PATH)
    if not path.exists() or str(path) == _DB_PATH:
        return
    marker = f"legacy_migration:{path.resolve()}"
    try:
        records = _legacy_records(path)
        with _lock, _connection(write=True) as db:
            if db.execute("SELECT 1 FROM schema_meta WHERE key=?", (marker,)).fetchone():
                return
            imported = sum(1 for record in records if _insert_legacy_case(db, record))
            db.execute("INSERT INTO schema_meta(key,value,updated_at) VALUES(?,?,?)",
                       (marker, _json_dump({"records": len(records), "imported": imported}), _now()))
        logger.info("migrated %d/%d legacy cases into %s", imported, len(records), _DB_PATH)
    except (OSError, sqlite3.Error, ValueError, TypeError):
        logger.warning("legacy case migration failed: %s", path, exc_info=True)


def _case_row(db: sqlite3.Connection, case_id: str) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()


def _assert_revision(row: sqlite3.Row, expected_revision: int | None) -> int:
    current = int(row["revision"])
    if expected_revision is not None and current != int(expected_revision):
        raise CaseConflict(current)
    return current


def _hydrate_case(db: sqlite3.Connection, row: sqlite3.Row, *, include_audit: bool = True) -> dict[str, Any]:
    case = dict(row)
    entities = [dict(item) for item in db.execute(
        "SELECT entity_type,entity_value,source,first_seen,last_seen FROM case_entities WHERE case_id=? ORDER BY entity_type,entity_value",
        (row["case_id"],),
    )]
    case["entity_links"] = entities
    case["srcips"] = [item["entity_value"] for item in entities if item["entity_type"] == "source_ip"]
    case["iocs"] = [item["entity_value"] for item in entities if item["entity_type"] == "ioc"]
    notes = [dict(item) for item in db.execute(
        "SELECT note_id,created_at,author,body FROM case_notes WHERE case_id=? ORDER BY created_at,note_id",
        (row["case_id"],),
    )]
    case["note_entries"] = notes
    case["notes"] = "\n".join(item["body"] for item in notes)
    case["verdicts"] = [{"id": item["verdict_id"], "ts": item["created_at"],
                         "srcip": item["srcip"], "verdict": item["verdict"],
                         "notes": item["notes"], "actor": item["actor"]}
                        for item in db.execute(
                            "SELECT * FROM case_verdicts WHERE case_id=? ORDER BY created_at,verdict_id",
                            (row["case_id"],))]
    evidence = []
    for item in db.execute("SELECT * FROM case_evidence WHERE case_id=? ORDER BY observed_at DESC,evidence_id",
                           (row["case_id"],)):
        value = dict(item)
        value["payload"] = _json_load(value.pop("payload_json"), {})
        value["provenance"] = _json_load(value.pop("provenance_json"), {})
        evidence.append(value)
    case["evidence"] = evidence
    case["status_transitions"] = [dict(item) for item in db.execute(
        "SELECT transition_id,from_status,to_status,created_at,actor,reason FROM case_transitions WHERE case_id=? ORDER BY transition_id",
        (row["case_id"],))]
    case["assignments"] = [dict(item) for item in db.execute(
        "SELECT assignment_id,created_at,assigned_by,owner,sla_due FROM case_assignments WHERE case_id=? ORDER BY assignment_id",
        (row["case_id"],))]
    case["containment_history"] = [dict(item) for item in db.execute(
        "SELECT containment_id,created_at,actor,action,result FROM case_containments WHERE case_id=? ORDER BY created_at,containment_id",
        (row["case_id"],))]
    if include_audit:
        case["audit_log"] = [{**dict(item), "detail": _json_load(item["detail_json"], {})}
                             for item in db.execute(
                                 "SELECT audit_id,created_at,action,actor,revision,detail_json FROM case_audit WHERE case_id=? ORDER BY audit_id",
                                 (row["case_id"],))]
        for item in case["audit_log"]:
            item.pop("detail_json", None)
    return case


def _update_revision(db: sqlite3.Connection, case_id: str, current: int, action: str,
                     actor: str, detail: dict[str, Any] | None = None, **fields: Any) -> int:
    now = _now()
    fields = {**fields, "updated_at": now, "revision": current + 1}
    assignments = ",".join(f"{key}=?" for key in fields)
    values = list(fields.values()) + [case_id, current]
    cursor = db.execute(f"UPDATE cases SET {assignments} WHERE case_id=? AND revision=?", values)
    if cursor.rowcount != 1:
        latest = db.execute("SELECT revision FROM cases WHERE case_id=?", (case_id,)).fetchone()
        raise CaseConflict(int(latest["revision"]) if latest else current)
    _insert_audit(db, case_id, action, actor, current + 1, detail, created_at=now)
    return current + 1


def _mutate(case_id: str, expected_revision: int | None,
            callback: Callable[[sqlite3.Connection, sqlite3.Row, int], None]) -> dict[str, Any] | None:
    with _lock, _connection(write=True) as db:
        row = _case_row(db, case_id)
        if row is None:
            return None
        current = _assert_revision(row, expected_revision)
        callback(db, row, current)
    return get_case(case_id)


def create_case(title: str, srcips: list[str] | None = None, notes: str = "", *,
                owner: str = "", sla_due: str = "", status: str = "open",
                containment: str = "", closure_reason: str = "", actor: str = "system",
                initial_evidence: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    case_id = _new_id()
    now = _now()
    status = _canonical_status(status)
    with _lock, _connection(write=True) as db:
        db.execute(
            """INSERT INTO cases
               (case_id,title,created_at,updated_at,owner,sla_due,status,containment,resolution,closure_reason,closed_at,revision)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,1)""",
            (case_id, (title or "").strip()[:200] or case_id, now, now,
             (owner or "").strip()[:120], (sla_due or "").strip()[:64], status,
             (containment or "").strip()[:4000], "", (closure_reason or "").strip()[:2000],
             now if status == "closed" else None),
        )
        for srcip in sorted({str(value).strip() for value in srcips or [] if str(value).strip()}):
            _insert_entity(db, case_id, "source_ip", srcip, "case_create", now)
        if notes.strip():
            db.execute("INSERT INTO case_notes VALUES(?,?,?,?,?)",
                       (_new_id("note"), case_id, now, actor[:120], notes.strip()[:4000]))
        if owner.strip() or sla_due.strip():
            db.execute("INSERT INTO case_assignments(case_id,created_at,assigned_by,owner,sla_due) VALUES(?,?,?,?,?)",
                       (case_id, now, actor[:120], owner.strip()[:120], sla_due.strip()[:64]))
        evidence_count = 0
        for item in initial_evidence or []:
            if not isinstance(item, dict):
                continue
            source = str(item.get("source") or "").strip()[:120]
            source_ref = str(item.get("source_ref") or "").strip()[:500]
            if not source or not source_ref:
                raise ValueError("initial evidence source and source_ref are required")
            provenance = {**(item.get("provenance") if isinstance(item.get("provenance"), dict) else {}),
                          "source": source, "source_ref": source_ref,
                          "added_by": actor[:120], "added_at": now}
            db.execute(
                """INSERT INTO case_evidence
                   (evidence_id,case_id,evidence_type,title,summary,source,source_ref,observed_at,added_at,added_by,payload_json,provenance_json,idempotency_key)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (_new_id("evidence"), case_id, str(item.get("evidence_type") or "event")[:64],
                 str(item.get("title") or "Initial case evidence")[:200],
                 str(item.get("summary") or "")[:4000], source, source_ref,
                 _iso_timestamp(item.get("observed_at"), now)[:64], now, actor[:120],
                 _json_dump(item.get("payload") if isinstance(item.get("payload"), dict) else {}),
                 _json_dump(provenance), str(item.get("idempotency_key") or "").strip()[:200] or None),
            )
            evidence_count += 1
        db.execute("INSERT INTO case_transitions(case_id,from_status,to_status,created_at,actor,reason) VALUES(?,?,?,?,?,?)",
                   (case_id, None, status, now, actor[:120], "Case created"))
        _insert_audit(db, case_id, "case_created", actor, 1,
                      {"status": status, "initial_evidence": evidence_count}, created_at=now)
    case = get_case(case_id)
    assert case is not None
    return case


def add_iocs(case_id: str, iocs: list[str], expected_revision: int,
             actor: str = "system") -> dict[str, Any] | None:
    values = sorted({str(value).strip()[:2048] for value in iocs if str(value).strip()})

    def write(db: sqlite3.Connection, row: sqlite3.Row, current: int) -> None:
        existing = {item[0] for item in db.execute(
            "SELECT entity_value FROM case_entities WHERE case_id=? AND entity_type='ioc'", (case_id,))}
        added = [value for value in values if value not in existing]
        if not added:
            return
        now = _now()
        for value in added:
            _insert_entity(db, case_id, "ioc", value, "case_ioc", now)
        _update_revision(db, case_id, current, "iocs_added", actor, {"count": len(added)})

    return _mutate(case_id, expected_revision, write)


def add_verdict(case_id: str, srcip: str, verdict: str, notes: str = "",
                expected_revision: int = 0, actor: str = "system") -> dict[str, Any] | None:
    if expected_revision < 1:
        raise ValueError("expected_revision is required")
    def write(db: sqlite3.Connection, row: sqlite3.Row, current: int) -> None:
        now = _now()
        db.execute("INSERT INTO case_verdicts VALUES(?,?,?,?,?,?,?)",
                   (_new_id("verdict"), case_id, now, srcip[:45], verdict[:32], notes[:1000], actor[:120]))
        _insert_entity(db, case_id, "source_ip", srcip, "case_verdict", now)
        _update_revision(db, case_id, current, "verdict_added", actor, {"srcip": srcip, "verdict": verdict})

    return _mutate(case_id, expected_revision, write)


def assign_case(case_id: str, owner: str, sla_due: str, expected_revision: int,
                actor: str) -> dict[str, Any] | None:
    owner, sla_due = owner.strip()[:120], sla_due.strip()[:64]

    def write(db: sqlite3.Connection, row: sqlite3.Row, current: int) -> None:
        now = _now()
        db.execute("INSERT INTO case_assignments(case_id,created_at,assigned_by,owner,sla_due) VALUES(?,?,?,?,?)",
                   (case_id, now, actor[:120], owner, sla_due))
        _update_revision(db, case_id, current, "case_assigned", actor,
                         {"owner": owner, "sla_due": sla_due}, owner=owner, sla_due=sla_due)

    return _mutate(case_id, expected_revision, write)


def update_status(case_id: str, status: str, reason: str, expected_revision: int,
                  actor: str) -> dict[str, Any] | None:
    target = _canonical_status(status)
    if target in {"resolved", "closed"}:
        raise InvalidTransition(f"use the dedicated {target} operation")

    def write(db: sqlite3.Connection, row: sqlite3.Row, current: int) -> None:
        source = _canonical_status(row["status"])
        if target == source:
            return
        if source in {"resolved", "closed"}:
            raise InvalidTransition(f"use the dedicated reopen operation for a {source} case")
        if target not in _TRANSITIONS[source]:
            raise InvalidTransition(f"cannot transition case from {source} to {target}")
        now = _now()
        db.execute("INSERT INTO case_transitions(case_id,from_status,to_status,created_at,actor,reason) VALUES(?,?,?,?,?,?)",
                   (case_id, source, target, now, actor[:120], reason[:1000]))
        _update_revision(db, case_id, current, "status_changed", actor,
                         {"from": source, "to": target, "reason": reason[:1000]},
                         status=target, closed_at=now if target == "closed" else None)

    return _mutate(case_id, expected_revision, write)


def add_note(case_id: str, body: str, expected_revision: int, actor: str) -> dict[str, Any] | None:
    body = body.strip()[:4000]
    if not body:
        raise ValueError("note body is required")

    def write(db: sqlite3.Connection, row: sqlite3.Row, current: int) -> None:
        db.execute("INSERT INTO case_notes VALUES(?,?,?,?,?)", (_new_id("note"), case_id, _now(), actor[:120], body))
        _update_revision(db, case_id, current, "note_added", actor, {"length": len(body)})

    return _mutate(case_id, expected_revision, write)


def add_evidence(case_id: str, *, evidence_type: str, title: str, summary: str,
                 source: str, source_ref: str, observed_at: str | None,
                 payload: dict[str, Any] | None, provenance: dict[str, Any],
                 entities: list[dict[str, str]] | None, idempotency_key: str | None,
                 expected_revision: int, actor: str) -> dict[str, Any] | None:
    source, source_ref = source.strip()[:120], source_ref.strip()[:500]
    if not source or not source_ref:
        raise ValueError("evidence source and source_ref are required for provenance")

    def write(db: sqlite3.Connection, row: sqlite3.Row, current: int) -> None:
        if idempotency_key and db.execute(
                "SELECT 1 FROM case_evidence WHERE case_id=? AND idempotency_key=?",
                (case_id, idempotency_key[:200])).fetchone():
            return
        now = _now()
        observed = _iso_timestamp(observed_at, now)[:64]
        provenance_record = {**(provenance or {}), "source": source, "source_ref": source_ref,
                             "added_by": actor[:120], "added_at": now}
        db.execute(
            """INSERT INTO case_evidence
               (evidence_id,case_id,evidence_type,title,summary,source,source_ref,observed_at,added_at,added_by,payload_json,provenance_json,idempotency_key)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (_new_id("evidence"), case_id, evidence_type[:64], title.strip()[:200], summary.strip()[:4000],
             source, source_ref, observed, now, actor[:120], _json_dump(payload or {}),
             _json_dump(provenance_record), (idempotency_key or "").strip()[:200] or None),
        )
        for entity in entities or []:
            if isinstance(entity, dict):
                _insert_entity(db, case_id, str(entity.get("type") or "entity"),
                               str(entity.get("value") or ""), source, observed)
        _update_revision(db, case_id, current, "evidence_added", actor,
                         {"type": evidence_type[:64], "source": source, "source_ref": source_ref})

    return _mutate(case_id, expected_revision, write)


def record_containment(case_id: str, action: str, result: str, expected_revision: int,
                       actor: str) -> dict[str, Any] | None:
    action, result = action.strip()[:4000], result.strip()[:2000]
    if not action:
        raise ValueError("containment action is required")

    def write(db: sqlite3.Connection, row: sqlite3.Row, current: int) -> None:
        now = _now()
        db.execute("INSERT INTO case_containments VALUES(?,?,?,?,?,?)",
                   (_new_id("containment"), case_id, now, actor[:120], action, result))
        current_status = _canonical_status(row["status"])
        if current_status == "closed":
            raise InvalidTransition("reopen a closed case before recording containment")
        if current_status != "containment" and "containment" not in _TRANSITIONS[current_status]:
            raise InvalidTransition(f"cannot record containment while case is {current_status}")
        next_status = "containment"
        if next_status != current_status:
            db.execute("INSERT INTO case_transitions(case_id,from_status,to_status,created_at,actor,reason) VALUES(?,?,?,?,?,?)",
                       (case_id, current_status, next_status, now, actor[:120], "Containment recorded"))
        _update_revision(db, case_id, current, "containment_recorded", actor,
                         {"result": result}, containment=action, status=next_status)

    return _mutate(case_id, expected_revision, write)


def resolve_case(case_id: str, resolution: str, expected_revision: int,
                 actor: str) -> dict[str, Any] | None:
    resolution = resolution.strip()[:4000]
    if not resolution:
        raise ValueError("resolution is required")

    def write(db: sqlite3.Connection, row: sqlite3.Row, current: int) -> None:
        source = _canonical_status(row["status"])
        if source == "closed":
            raise InvalidTransition("reopen a closed case before resolving it again")
        now = _now()
        if source != "resolved":
            db.execute("INSERT INTO case_transitions(case_id,from_status,to_status,created_at,actor,reason) VALUES(?,?,?,?,?,?)",
                       (case_id, source, "resolved", now, actor[:120], resolution))
        _update_revision(db, case_id, current, "case_resolved", actor,
                         {"resolution": resolution}, status="resolved", resolution=resolution, closed_at=None)

    return _mutate(case_id, expected_revision, write)


def reopen_case(case_id: str, reason: str, expected_revision: int,
                actor: str) -> dict[str, Any] | None:
    reason = reason.strip()[:2000]
    if not reason:
        raise ValueError("reopen reason is required")

    def write(db: sqlite3.Connection, row: sqlite3.Row, current: int) -> None:
        source = _canonical_status(row["status"])
        if source not in {"resolved", "closed"}:
            raise InvalidTransition("only resolved or closed cases can be reopened")
        now = _now()
        db.execute("INSERT INTO case_transitions(case_id,from_status,to_status,created_at,actor,reason) VALUES(?,?,?,?,?,?)",
                   (case_id, source, "investigating", now, actor[:120], reason))
        _update_revision(db, case_id, current, "case_reopened", actor,
                         {"reason": reason}, status="investigating", resolution="",
                         closure_reason="", closed_at=None)

    return _mutate(case_id, expected_revision, write)


def close_case(case_id: str, closure_reason: str, expected_revision: int,
               actor: str) -> dict[str, Any] | None:
    closure_reason = closure_reason.strip()[:2000]
    if not closure_reason:
        raise ValueError("closure reason is required")

    def write(db: sqlite3.Connection, row: sqlite3.Row, current: int) -> None:
        source = _canonical_status(row["status"])
        if source == "closed":
            return
        now = _now()
        db.execute("INSERT INTO case_transitions(case_id,from_status,to_status,created_at,actor,reason) VALUES(?,?,?,?,?,?)",
                   (case_id, source, "closed", now, actor[:120], closure_reason))
        _update_revision(db, case_id, current, "case_closed", actor,
                         {"reason": closure_reason}, status="closed",
                         closure_reason=closure_reason, closed_at=now)

    return _mutate(case_id, expected_revision, write)


def get_case(case_id: str) -> dict[str, Any] | None:
    with _connection() as db:
        row = _case_row(db, case_id)
        return _hydrate_case(db, row) if row else None


def _summarize_cases(db: sqlite3.Connection, rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    summaries = {row["case_id"]: {**dict(row), "srcips": [], "iocs": [], "verdicts": [],
                                  "entities": [], "notes": "", "evidence_count": 0, "note_count": 0}
                 for row in rows}
    if not summaries:
        return []
    placeholders = ",".join("?" for _ in summaries)
    case_ids = tuple(summaries)
    for item in db.execute(
            f"SELECT case_id,entity_type,entity_value FROM case_entities WHERE case_id IN ({placeholders}) ORDER BY entity_value",
            case_ids):
        key = "srcips" if item["entity_type"] == "source_ip" else ("iocs" if item["entity_type"] == "ioc" else None)
        if key:
            summaries[item["case_id"]][key].append(item["entity_value"])
        summaries[item["case_id"]]["entities"].append({
            "type": item["entity_type"], "value": item["entity_value"],
        })
    for item in db.execute(
            f"""SELECT * FROM (
                    SELECT case_id,verdict_id,created_at,srcip,verdict,notes,actor,
                           ROW_NUMBER() OVER (PARTITION BY case_id ORDER BY created_at DESC,verdict_id DESC) AS rank
                    FROM case_verdicts WHERE case_id IN ({placeholders})
                ) WHERE rank=1""", case_ids):
        summaries[item["case_id"]]["verdicts"] = [{
            "id": item["verdict_id"], "ts": item["created_at"], "srcip": item["srcip"],
            "verdict": item["verdict"], "notes": item["notes"], "actor": item["actor"],
        }]
    for item in db.execute(
            f"""SELECT * FROM (
                    SELECT case_id,body,
                           ROW_NUMBER() OVER (PARTITION BY case_id ORDER BY created_at DESC,note_id DESC) AS rank
                    FROM case_notes WHERE case_id IN ({placeholders})
                ) WHERE rank=1""", case_ids):
        summaries[item["case_id"]]["notes"] = item["body"]
    for item in db.execute(
            f"SELECT case_id,COUNT(*) AS count FROM case_notes WHERE case_id IN ({placeholders}) GROUP BY case_id",
            case_ids):
        summaries[item["case_id"]]["note_count"] = int(item["count"])
    for item in db.execute(
            f"SELECT case_id,COUNT(*) AS count FROM case_evidence WHERE case_id IN ({placeholders}) GROUP BY case_id",
            case_ids):
        summaries[item["case_id"]]["evidence_count"] = int(item["count"])
    return [summaries[row["case_id"]] for row in rows]


def list_cases(*, start: str | None = None, end: str | None = None,
               limit: int | None = None, offset: int = 0) -> list[dict[str, Any]]:
    clauses, values = [], []
    if start:
        clauses.append("created_at >= ?")
        values.append(_iso_timestamp(start))
    if end:
        clauses.append("created_at < ?")
        values.append(_iso_timestamp(end))
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    page_limit = _CASE_MAX if limit is None else max(1, min(200, int(limit)))
    sql = f"SELECT * FROM cases{where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
    with _connection() as db:
        rows = db.execute(sql, (*values, page_limit, max(0, int(offset)))).fetchall()
        return _summarize_cases(db, rows)


def count_cases(*, start: str | None = None, end: str | None = None) -> int:
    clauses, values = [], []
    if start:
        clauses.append("created_at >= ?")
        values.append(_iso_timestamp(start))
    if end:
        clauses.append("created_at < ?")
        values.append(_iso_timestamp(end))
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    with _connection() as db:
        return int(db.execute(f"SELECT COUNT(*) FROM cases{where}", values).fetchone()[0])


def case_timeline(case_id: str) -> list[dict[str, Any]]:
    case = get_case(case_id)
    if not case:
        return []
    events: list[dict[str, Any]] = [{"ts": case["created_at"], "event": "case_created", "detail": case["title"]}]
    events.extend({"ts": item["ts"], "event": "verdict", "srcip": item["srcip"],
                   "verdict": item["verdict"], "detail": item["notes"]} for item in case["verdicts"])
    events.extend({"ts": item["observed_at"], "event": "evidence", "detail": item["title"],
                   "source": item["source"], "source_ref": item["source_ref"]} for item in case["evidence"])
    events.extend({"ts": item["created_at"], "event": "status", "detail": item["reason"],
                   "from_status": item["from_status"], "to_status": item["to_status"]}
                  for item in case["status_transitions"] if item["from_status"] is not None)
    events.sort(key=lambda item: (item.get("ts") or "", item.get("event") or ""))
    return events


def case_stats() -> dict[str, Any]:
    with _connection() as db:
        counts = {table: int(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in (
            "cases", "case_evidence", "case_notes", "case_entities", "case_transitions",
            "case_assignments", "case_audit")}
        journal_mode = str(db.execute("PRAGMA journal_mode").fetchone()[0])
    return {**counts, "path": _DB_PATH, "max": _CASE_MAX, "journal_mode": journal_mode,
            "persistent": bool(_CONFIGURED_DB_PATH or _LEGACY_CASE_PATH)}


def _reset_for_tests() -> None:
    """Clear case data while retaining schema; intentionally not part of the MCP API."""
    with _lock, _connection(write=True) as db:
        for table in ("case_audit", "case_containments", "case_assignments", "case_transitions",
                      "case_verdicts", "case_notes", "case_evidence", "case_entities", "cases"):
            db.execute(f"DELETE FROM {table}")


class _CompatibilityCases:
    """Old tests may clear this shim; no process-local case data lives here."""

    @staticmethod
    def clear() -> None:
        _reset_for_tests()


_cases = _CompatibilityCases()

_init_schema()
