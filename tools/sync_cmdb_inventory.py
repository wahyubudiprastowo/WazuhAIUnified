#!/usr/bin/env python3
"""Build an authoritative CMDB identity baseline from the local dashboard's Wazuh agents.

Only observed agent identity and operating-system fields are written. Business
ownership, criticality, network zone, internet exposure, CPE, and patch state
are never inferred. Existing authoritative annotations are preserved.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV = ROOT / "mcp-dashboard" / "dashboard.env"
DEFAULT_OUTPUT = ROOT / "infokom-analysis" / "resource" / "assets.json"


def env_values(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip().strip('"').strip("'")
    return result


def existing_assets(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    rows = raw.get("assets") if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        raise ValueError("CMDB root must be an array or an object containing assets[]")
    return [dict(row) for row in rows if isinstance(row, dict)]


def is_authoritative(row: dict[str, Any]) -> bool:
    purpose = str(row.get("purpose") or "").strip().lower()
    return not (purpose.startswith("sample") or purpose.startswith("example") or row.get("template") is True
                or row.get("verified") is False)


def _identity_values(row: dict[str, Any]) -> set[str]:
    values = [row.get(key) for key in ("agent_id", "id", "name", "host", "hostname", "fqdn", "ip")]
    values.extend(row.get("aliases") or [])
    values.extend(row.get("ips") or [])
    return {str(value).strip().lower().rstrip(".") for value in values if str(value or "").strip()}


def merge_agents(agents: list[dict[str, Any]], current: list[dict[str, Any]], observed_at: str) -> list[dict[str, Any]]:
    authoritative = [row for row in current if is_authoritative(row)]
    index: dict[str, dict[str, Any]] = {}
    for row in authoritative:
        for value in _identity_values(row):
            index.setdefault(value, row)
    merged: list[dict[str, Any]] = []
    matched: set[int] = set()
    for agent in agents:
        if not isinstance(agent, dict) or not str(agent.get("id") or "").strip():
            continue
        identity = _identity_values({
            "agent_id": agent.get("id"), "name": agent.get("name"), "host": agent.get("name"),
            "ip": agent.get("ip"),
        })
        prior = next((index[value] for value in identity if value in index), None)
        row = dict(prior or {})
        if prior:
            matched.add(id(prior))
        name = str(agent.get("name") or "").strip()
        row.update({
            "agent_id": str(agent.get("id")).strip(),
            "name": name or row.get("name") or str(agent.get("id")),
            "host": name or row.get("host") or str(agent.get("id")),
            "source": "Wazuh agent inventory",
            "last_verified": observed_at,
            "verified": True,
        })
        if agent.get("ip"):
            row["ip"] = str(agent["ip"]).strip()
        aliases = list(dict.fromkeys([value for value in (row.get("aliases") or []) + ([name] if name else []) if value]))
        if aliases:
            row["aliases"] = aliases[:50]
        os_data = agent.get("os") if isinstance(agent.get("os"), dict) else {}
        row["os"] = {key: os_data.get(key) for key in ("name", "version", "platform", "arch") if os_data.get(key)}
        labels = agent.get("labels") if isinstance(agent.get("labels"), dict) else {}
        for field in ("owner", "criticality", "environment", "network_zone", "application"):
            if not row.get(field) and str(labels.get(field) or "").strip():
                row[field] = str(labels[field]).strip()
        if "internet_exposed" not in row and isinstance(labels.get("internet_exposed"), bool):
            row["internet_exposed"] = labels["internet_exposed"]
        merged.append(row)
    merged.extend(row for row in authoritative if id(row) not in matched)
    return sorted(merged, key=lambda row: (str(row.get("agent_id") or "~"), str(row.get("name") or "")))


def fetch_agents(base_url: str, token: str) -> tuple[list[dict[str, Any]], str]:
    request = urllib.request.Request(
        base_url.rstrip("/") + "/api/overview",
        data=json.dumps({"range": "24h"}).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        payload = json.load(response)
    agents = (payload.get("agents") or {}).get("items") or []
    if not isinstance(agents, list) or not agents:
        raise RuntimeError("Dashboard returned no Wazuh agent inventory; CMDB was not changed")
    return agents, str(payload.get("generated_at") or datetime.now(timezone.utc).isoformat())


def atomic_write(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(rows, handle, indent=2, ensure_ascii=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        # Dashboard runs as uid 1000 with gid 0. When the host command is run
        # as root, group-read keeps the read-only bind mount accessible.
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, default=DEFAULT_ENV)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--url", default="")
    parser.add_argument("--write", action="store_true", help="Atomically replace the local ignored CMDB file")
    args = parser.parse_args()
    values = env_values(args.env)
    port = values.get("DASHBOARD_HOST_PORT") or values.get("DASHBOARD_PORT") or "8088"
    base_url = args.url or f"http://127.0.0.1:{port}"
    token = values.get("DASHBOARD_ACCESS_TOKEN", "")
    agents, observed_at = fetch_agents(base_url, token)
    current = existing_assets(args.output)
    merged = merge_agents(agents, current, observed_at)
    summary = {
        "ok": True, "mode": "write" if args.write else "dry-run", "output": str(args.output),
        "observed_agents": len(agents), "retained_authoritative": sum(is_authoritative(row) for row in current),
        "excluded_sample_or_unverified": sum(not is_authoritative(row) for row in current),
        "result_assets": len(merged),
        "business_context_missing": {
            field: sum(not row.get(field) for row in merged)
            for field in ("owner", "criticality", "environment", "network_zone", "internet_exposed", "cpe")
        },
    }
    if args.write:
        atomic_write(args.output, merged)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
