#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Case management create, update, and query durable incident records.
A case groups a whole campaign/incident: srcips, IOCs, and analyst verdicts.
Populate it from `three_sum_correlation` triggers, `blueteam_pivot_suggest`
leads, and `blueteam_mark_investigated` verdicts so an investigation survives beyond a single tool call.
"""
from __future__ import annotations
import json
from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator
from mcp_server import mcp
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.core.redact import _redact_alert_data
from mcp_server.core import case_store


class InitialCaseEvidence(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    evidence_type: Literal["event", "provider", "analyst", "artifact", "query", "report"] = "event"
    title: str = Field(..., min_length=1, max_length=200)
    summary: str = Field(default="", max_length=4000)
    source: str = Field(..., min_length=1, max_length=120)
    source_ref: str = Field(..., min_length=1, max_length=500)
    observed_at: str | None = Field(default=None, max_length=64)
    payload: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, max_length=200)

    @field_validator("observed_at")
    @classmethod
    def valid_observed_at(cls, value: str | None) -> str | None:
        if value:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value

    @field_validator("payload", "provenance")
    @classmethod
    def bounded_json(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(json.dumps(value, ensure_ascii=False, default=str)) > 32768:
            raise ValueError("structured evidence field exceeds 32 KiB")
        return value


class CaseCreateInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    title: str = Field(..., min_length=1, max_length=200, description="Case title.")
    srcips: list[str] = Field(default=[], max_length=200,
        description="Source IPs to seed the case with.")
    notes: str = Field(default="", max_length=2000, description="Analyst notes.")
    owner: str = Field(default="", max_length=120, description="Assigned case owner.")
    sla_due: str = Field(default="", max_length=64, description="SLA due timestamp or date.")
    status: Literal["open", "triage", "investigating", "containment", "contained", "resolved", "closed"] = Field(default="open")
    containment: str = Field(default="", max_length=1000, description="Approved containment record.")
    closure_reason: str = Field(default="", max_length=1000, description="Closure rationale when available.")
    actor: str = Field(default="system", min_length=1, max_length=120)
    initial_evidence: list[InitialCaseEvidence] = Field(default_factory=list, max_length=20)


class CaseAddIocsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    case_id: str = Field(..., min_length=5, max_length=64)
    iocs: list[str] = Field(..., min_length=1, max_length=500,
        description="IOCs (IPs/domains/hashes) to attach.")
    expected_revision: int = Field(..., ge=1, description="Revision returned by case_get/list; rejects stale writes.")
    actor: str = Field(default="system", min_length=1, max_length=120)


class CaseAddVerdictInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    case_id: str = Field(..., min_length=5, max_length=64)
    srcip: str = Field(..., min_length=7, max_length=45)
    verdict: Literal["true_positive", "false_positive", "suspicious", "clean", "unknown"]
    notes: str = Field(default="", max_length=500)
    expected_revision: int = Field(..., ge=1, description="Revision returned by case_get/list; rejects stale writes.")
    actor: str = Field(default="system", min_length=1, max_length=120)


class CaseGetInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    case_id: str = Field(..., min_length=5, max_length=64)
    response_format: Literal["markdown", "json"] = Field(default="markdown")


class CaseListInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    response_format: Literal["markdown", "json"] = Field(default="markdown")
    paginated: bool = Field(default=False, description="Return {items,total,limit,offset}; legacy callers receive an array by default.")
    limit: int = Field(default=100, ge=1, le=200)
    offset: int = Field(default=0, ge=0, le=100000)
    start: str | None = Field(default=None, max_length=64, description="Optional inclusive ISO-8601 case creation bound.")
    end: str | None = Field(default=None, max_length=64, description="Optional exclusive ISO-8601 case creation bound.")

    @field_validator("start", "end")
    @classmethod
    def valid_bound(cls, value: str | None) -> str | None:
        if value is None:
            return None
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value


class VersionedCaseInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    case_id: str = Field(..., min_length=5, max_length=64)
    expected_revision: int = Field(..., ge=1, description="Current case revision; stale writes are rejected.")
    actor: str = Field(..., min_length=1, max_length=120, description="Human or automation identity performing the change.")


class CaseAssignInput(VersionedCaseInput):
    owner: str = Field(..., min_length=1, max_length=120)
    sla_due: str = Field(default="", max_length=64)


class CaseStatusInput(VersionedCaseInput):
    status: Literal["open", "triage", "investigating", "containment", "resolved", "closed"]
    reason: str = Field(..., min_length=1, max_length=1000)


class CaseNoteInput(VersionedCaseInput):
    body: str = Field(..., min_length=1, max_length=4000)


class EvidenceEntity(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    type: str = Field(..., min_length=1, max_length=64)
    value: str = Field(..., min_length=1, max_length=2048)


class CaseEvidenceInput(VersionedCaseInput):
    evidence_type: Literal["event", "provider", "analyst", "artifact", "query", "report"]
    title: str = Field(..., min_length=1, max_length=200)
    summary: str = Field(default="", max_length=4000)
    source: str = Field(..., min_length=1, max_length=120)
    source_ref: str = Field(..., min_length=1, max_length=500)
    observed_at: str | None = Field(default=None, max_length=64)
    payload: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)
    entities: list[EvidenceEntity] = Field(default_factory=list, max_length=100)
    idempotency_key: str | None = Field(default=None, max_length=200)

    @field_validator("observed_at")
    @classmethod
    def valid_observed_at(cls, value: str | None) -> str | None:
        if value:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value

    @field_validator("payload", "provenance")
    @classmethod
    def bounded_json(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(json.dumps(value, ensure_ascii=False, default=str)) > 32768:
            raise ValueError("structured evidence field exceeds 32 KiB")
        return value


class CaseContainmentInput(VersionedCaseInput):
    action: str = Field(..., min_length=1, max_length=4000)
    result: str = Field(default="", max_length=2000)


class CaseResolveInput(VersionedCaseInput):
    resolution: str = Field(..., min_length=1, max_length=4000)


class CaseReopenInput(VersionedCaseInput):
    reason: str = Field(..., min_length=1, max_length=2000)


class CaseCloseInput(VersionedCaseInput):
    closure_reason: str = Field(..., min_length=1, max_length=2000)


@mcp.tool(
    name="blueteam_case_create",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": False, "openWorldHint": False},
)
async def blueteam_case_create(params: CaseCreateInput) -> str:
    """Create a new investigation case (durable incident record).

    **Worked Examples**
    1. ``blueteam_case_create(title="APT campaign 2026-08", srcips=["103.107.116.202"])``
    """
    _audit_log("blueteam_case_create", {"title": params.title})
    case = case_store.create_case(params.title, params.srcips, params.notes, owner=params.owner,
        sla_due=params.sla_due, status=params.status, containment=params.containment,
        closure_reason=params.closure_reason, actor=params.actor,
        initial_evidence=[item.model_dump() for item in params.initial_evidence])
    return json.dumps(case, indent=2, ensure_ascii=False)


@mcp.tool(
    name="blueteam_case_add_iocs",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_case_add_iocs(params: CaseAddIocsInput) -> str:
    """Attach IOC to an existing case.
    **Worked Examples**
    1. ``blueteam_case_add_iocs(case_id="case_abc123", iocs=["evil.com"], expected_revision=3)``
    """
    _audit_log("blueteam_case_add_iocs", {"case_id": params.case_id})
    try:
        case = case_store.add_iocs(params.case_id, params.iocs, params.expected_revision, params.actor)
    except case_store.CaseConflict:
        current = case_store.get_case(params.case_id) or {}
        return json.dumps({"error": "revision_conflict", "case_id": params.case_id,
                           "current_revision": current.get("revision")}, indent=2)
    if not case:
        return json.dumps({"error": f"Case '{params.case_id}' not found."}, indent=2)
    return json.dumps({"case_id": params.case_id, "iocs": case["iocs"], "revision": case.get("revision")}, indent=2, ensure_ascii=False)


@mcp.tool(
    name="blueteam_case_add_verdict",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": False, "openWorldHint": False},
)
async def blueteam_case_add_verdict(params: CaseAddVerdictInput) -> str:
    """Record an investigation verdict against a srcip within a case.

    **Worked Examples**
    1. ``blueteam_case_add_verdict(case_id="case_abc123", srcip="103.107.116.202", verdict="true_positive", expected_revision=3)``
    """
    _audit_log("blueteam_case_add_verdict", {"case_id": params.case_id, "srcip": params.srcip})
    try:
        case = case_store.add_verdict(params.case_id, params.srcip, params.verdict, params.notes,
                                      params.expected_revision, params.actor)
    except case_store.CaseConflict:
        current = case_store.get_case(params.case_id) or {}
        return json.dumps({"error": "revision_conflict", "case_id": params.case_id,
                           "current_revision": current.get("revision")}, indent=2)
    if not case:
        return json.dumps({"error": f"Case '{params.case_id}' not found."}, indent=2)
    return json.dumps({"case_id": params.case_id, "verdicts": case["verdicts"], "revision": case.get("revision")}, indent=2, ensure_ascii=False)


def _mutation_result(case_id: str, operation) -> str:
    try:
        case = operation()
    except case_store.CaseConflict as exc:
        return json.dumps({"error": "revision_conflict", "case_id": case_id,
                           "current_revision": exc.current_revision}, indent=2)
    except (case_store.InvalidTransition, ValueError) as exc:
        return json.dumps({"error": "invalid_lifecycle_change", "case_id": case_id,
                           "detail": str(exc)}, indent=2)
    if not case:
        return json.dumps({"error": f"Case '{case_id}' not found."}, indent=2)
    return _truncate_if_needed(json.dumps(_redact_alert_data(case), indent=2, ensure_ascii=False))


@mcp.tool(
    name="blueteam_case_assign",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": False, "openWorldHint": False},
)
async def blueteam_case_assign(params: CaseAssignInput) -> str:
    """Assign a durable case and SLA using optimistic concurrency."""
    _audit_log("blueteam_case_assign", {"case_id": params.case_id, "actor": params.actor})
    return _mutation_result(params.case_id, lambda: case_store.assign_case(
        params.case_id, params.owner, params.sla_due, params.expected_revision, params.actor))


@mcp.tool(
    name="blueteam_case_update_status",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": False, "openWorldHint": False},
)
async def blueteam_case_update_status(params: CaseStatusInput) -> str:
    """Move a case through an audited lifecycle transition."""
    _audit_log("blueteam_case_update_status", {"case_id": params.case_id, "actor": params.actor})
    return _mutation_result(params.case_id, lambda: case_store.update_status(
        params.case_id, params.status, params.reason, params.expected_revision, params.actor))


@mcp.tool(
    name="blueteam_case_add_note",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": False, "openWorldHint": False},
)
async def blueteam_case_add_note(params: CaseNoteInput) -> str:
    """Append an immutable analyst note to a case."""
    _audit_log("blueteam_case_add_note", {"case_id": params.case_id, "actor": params.actor})
    return _mutation_result(params.case_id, lambda: case_store.add_note(
        params.case_id, params.body, params.expected_revision, params.actor))


@mcp.tool(
    name="blueteam_case_add_evidence",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_case_add_evidence(params: CaseEvidenceInput) -> str:
    """Attach bounded evidence with immutable source provenance and entity links."""
    _audit_log("blueteam_case_add_evidence", {"case_id": params.case_id, "source": params.source})
    return _mutation_result(params.case_id, lambda: case_store.add_evidence(
        params.case_id, evidence_type=params.evidence_type, title=params.title,
        summary=params.summary, source=params.source, source_ref=params.source_ref,
        observed_at=params.observed_at, payload=params.payload, provenance=params.provenance,
        entities=[item.model_dump() for item in params.entities],
        idempotency_key=params.idempotency_key, expected_revision=params.expected_revision,
        actor=params.actor))


@mcp.tool(
    name="blueteam_case_record_containment",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": False, "openWorldHint": False},
)
async def blueteam_case_record_containment(params: CaseContainmentInput) -> str:
    """Record an approved containment action and its result."""
    _audit_log("blueteam_case_record_containment", {"case_id": params.case_id, "actor": params.actor})
    return _mutation_result(params.case_id, lambda: case_store.record_containment(
        params.case_id, params.action, params.result, params.expected_revision, params.actor))


@mcp.tool(
    name="blueteam_case_resolve",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": False, "openWorldHint": False},
)
async def blueteam_case_resolve(params: CaseResolveInput) -> str:
    """Resolve a case while retaining it for closure review."""
    _audit_log("blueteam_case_resolve", {"case_id": params.case_id, "actor": params.actor})
    return _mutation_result(params.case_id, lambda: case_store.resolve_case(
        params.case_id, params.resolution, params.expected_revision, params.actor))


@mcp.tool(
    name="blueteam_case_reopen",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": False, "openWorldHint": False},
)
async def blueteam_case_reopen(params: CaseReopenInput) -> str:
    """Reopen a resolved or closed case with an audited reason."""
    _audit_log("blueteam_case_reopen", {"case_id": params.case_id, "actor": params.actor})
    return _mutation_result(params.case_id, lambda: case_store.reopen_case(
        params.case_id, params.reason, params.expected_revision, params.actor))


@mcp.tool(
    name="blueteam_case_close",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": False, "openWorldHint": False},
)
async def blueteam_case_close(params: CaseCloseInput) -> str:
    """Close a case with a mandatory closure reason."""
    _audit_log("blueteam_case_close", {"case_id": params.case_id, "actor": params.actor})
    return _mutation_result(params.case_id, lambda: case_store.close_case(
        params.case_id, params.closure_reason, params.expected_revision, params.actor))


@mcp.tool(
    name="blueteam_case_get",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_case_get(params: CaseGetInput) -> str:
    """Fetch a case by ID, with all its IOCs and verdicts.

    **Worked Examples**
    1. ``blueteam_case_get(case_id="case_abc123")``
    """
    _audit_log("blueteam_case_get", {"case_id": params.case_id})
    case = case_store.get_case(params.case_id)
    if not case:
        return json.dumps({"error": f"Case '{params.case_id}' not found."}, indent=2)
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(_redact_alert_data(case), indent=2, ensure_ascii=False))
    lines = [f"# 🗂️ Case — `{case['case_id']}`", "", f"**Title**: {case['title']}",
             f"**Created**: {case['created_at']}", f"**Updated**: {case['updated_at']}",
             f"**SrcIPs**: {', '.join('`' + i + '`' for i in case.get('srcips', [])) or '—'}",
             f"**IOCs**: {', '.join('`' + i + '`' for i in case.get('iocs', [])) or '—'}", ""]
    if case.get("notes"):
        lines += ["## Notes", case["notes"], ""]
    if case.get("verdicts"):
        lines.append("## Verdicts")
        for v in case["verdicts"]:
            lines.append(f"- `{v['srcip']}` — **{v['verdict']}**" +
                         (f" ({v['notes']})" if v.get("notes") else ""))
        lines.append("")
    timeline = case_store.case_timeline(case["case_id"])
    if timeline:
        lines.append("## Timeline")
        for e in timeline:
            ts = (e.get("ts") or "?")[:19]
            if e["event"] == "case_created":
                lines.append(f"- `{ts}` 🗂️ Case created - {e.get('detail','')}")
            elif e["event"] == "verdict":
                lines.append(f"- `{ts}` `{e.get('srcip', '')}` -> **{e.get('verdict', '')}**" +
                             (f" ({e['detail']})" if e.get("detail") else ""))
            elif e["event"] == "evidence":
                lines.append(f"- `{ts}` Evidence **{e.get('detail', '')}** from "
                             f"`{e.get('source', '')}` (`{e.get('source_ref', '')}`)")
            else:
                lines.append(f"- `{ts}` Status `{e.get('from_status', '')}` -> "
                             f"**{e.get('to_status', '')}**" +
                             (f" ({e['detail']})" if e.get("detail") else ""))
    return _truncate_if_needed("\n".join(lines))


@mcp.tool(
    name="blueteam_case_list",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_case_list(params: CaseListInput) -> str:
    """List all cases (most recent first).

    **Worked Examples**
    1. ``blueteam_case_list()``
    """
    _audit_log("blueteam_case_list", {})
    cases = case_store.list_cases(start=params.start, end=params.end,
                                  limit=params.limit, offset=params.offset)
    total = case_store.count_cases(start=params.start, end=params.end)
    if params.response_format == "json":
        summaries = []
        for case in cases:
            summary = {key: case[key] for key in (
                "case_id", "title", "created_at", "updated_at", "srcips", "iocs", "owner",
                "sla_due", "status", "containment", "resolution", "closure_reason", "closed_at",
                "notes", "revision"
            ) if key in case}
            verdicts = case.get("verdicts") or []
            summary["latest_verdict"] = verdicts[-1] if verdicts else None
            summary["evidence_count"] = int(case.get("evidence_count") or 0)
            summary["note_count"] = int(case.get("note_count") or 0)
            summaries.append(summary)
        response = ({"items": summaries, "total": total, "limit": params.limit, "offset": params.offset}
                    if params.paginated else summaries)
        return _truncate_if_needed(json.dumps(_redact_alert_data(response), indent=2, ensure_ascii=False))
    lines = ["# 🗂️ Cases", ""]
    if not cases:
        lines.append("*No cases yet.*")
    for c in cases[:50]:
        lines.append(f"- `{c['case_id']}` - {c['title']} "
                     f"({len(c.get('srcips', []))} srcips, {len(c.get('iocs', []))} IOCs)")
    return _truncate_if_needed("\n".join(lines))
