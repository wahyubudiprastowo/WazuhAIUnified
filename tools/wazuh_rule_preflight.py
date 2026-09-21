#!/usr/bin/env python3
"""Idempotent preflight for third-party Wazuh rule and decoder bundles.

The default is deliberately read-only. Review a cloned candidate directory and
only use --apply after XML, identifiers, and representative log samples pass.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def _xml_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.xml") if path.is_file())


def _definitions(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        # Wazuh custom decoder files may contain several adjacent <decoder>
        # elements rather than a single XML document root. They are valid for
        # Wazuh, so parse them under a temporary root for inventory purposes.
        fragment = re.sub(r"<\?xml[^>]*\?>", "", raw, count=1).strip()
        root = ET.fromstring("<wazuh_preflight>" + fragment + "</wazuh_preflight>")
    rules, decoders = {}, {}
    for node in root.iter("rule"):
        key = (node.get("id") or "").strip()
        if key:
            rules[key] = hashlib.sha256(ET.tostring(node)).hexdigest()
    for node in root.iter("decoder"):
        key = (node.get("name") or "").strip()
        if key:
            decoders[key] = hashlib.sha256(ET.tostring(node)).hexdigest()
    return rules, decoders


def _inventory(paths: list[Path]) -> tuple[dict[str, str], dict[str, str], list[str]]:
    rules, decoders, errors = {}, {}, []
    for path in paths:
        try:
            file_rules, file_decoders = _definitions(path)
        except ET.ParseError as exc:
            errors.append(f"invalid XML: {path}: {exc}")
            continue
        for key, fingerprint in file_rules.items():
            if key in rules and rules[key] != fingerprint:
                errors.append(f"conflicting rule id {key}: {path}")
            rules[key] = fingerprint
        for key, fingerprint in file_decoders.items():
            if key in decoders and decoders[key] != fingerprint:
                errors.append(f"conflicting decoder name {key}: {path}")
            decoders[key] = fingerprint
    return rules, decoders, errors


def _git_commit(root: Path) -> str | None:
    """Return the reviewed checkout commit without invoking a shell."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.strip().lower()
    return value if result.returncode == 0 and len(value) == 40 else None


def preflight(existing: Path, candidate: Path, expected_commit: str = "") -> dict[str, object]:
    current_rules, current_decoders, errors = _inventory(_xml_files(existing))
    commit = _git_commit(candidate)
    expected = expected_commit.strip().lower()
    if expected and (len(expected) < 7 or not commit or not commit.startswith(expected)):
        errors.append("candidate checkout does not match the required pinned commit")
    candidate_files = _xml_files(candidate)
    plans = []
    for path in candidate_files:
        try:
            rules, decoders = _definitions(path)
        except ET.ParseError as exc:
            errors.append(f"invalid candidate XML: {path}: {exc}")
            continue
        duplicate_rules = sorted(key for key, value in rules.items() if current_rules.get(key) == value)
        duplicate_decoders = sorted(key for key, value in decoders.items() if current_decoders.get(key) == value)
        conflicting_rules = sorted(key for key, value in rules.items() if key in current_rules and current_rules[key] != value)
        conflicting_decoders = sorted(key for key, value in decoders.items() if key in current_decoders and current_decoders[key] != value)
        if conflicting_rules or conflicting_decoders:
            errors.append(f"conflict: {path}: rules={','.join(conflicting_rules) or '-'} decoders={','.join(conflicting_decoders) or '-'}")
        elif rules or decoders:
            plans.append({"path": path, "rules": sorted(rules), "decoders": sorted(decoders),
                          "duplicate_rules": duplicate_rules, "duplicate_decoders": duplicate_decoders,
                          "new": not (duplicate_rules == sorted(rules) and duplicate_decoders == sorted(decoders))})
    return {"errors": errors, "plans": plans, "candidate_commit": commit}


def _sample_test(executable: str, sample: Path) -> int:
    if not executable:
        return 0
    command = shutil.which(executable) or executable
    if not Path(command).exists() and not shutil.which(executable):
        print(f"sample test unavailable: {executable} not found", file=sys.stderr)
        return 2
    result = subprocess.run([command], input=sample.read_bytes(), stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=20, check=False)
    print(result.stdout.decode("utf-8", errors="replace")[:12_000])
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path, help="locally reviewed source bundle, e.g. a pinned git checkout")
    parser.add_argument("--existing", type=Path, default=Path("wazuh-stack/single-node/config/wazuh_cluster"))
    parser.add_argument("--expected-commit", default="", help="reviewed upstream Git commit (required with --apply)")
    parser.add_argument("--apply", action="store_true", help="copy only preflight-safe files into --existing")
    parser.add_argument("--sample-log", type=Path, help="representative log for optional wazuh-logtest")
    parser.add_argument("--wazuh-logtest", default="wazuh-logtest", help="path to Wazuh logtest binary")
    args = parser.parse_args()
    if args.apply and not args.expected_commit:
        parser.error("--apply requires --expected-commit from the reviewed upstream checkout")
    result = preflight(args.existing, args.candidate, args.expected_commit)
    print(f"candidate commit: {result['candidate_commit'] or 'not a Git checkout'}")
    for error in result["errors"]:
        print(error, file=sys.stderr)
    for plan in result["plans"]:
        print(f"{plan['path']}: {len(plan['rules'])} rules, {len(plan['decoders'])} decoders, new={plan['new']}")
    if result["errors"]:
        return 1
    if args.sample_log:
        status = _sample_test(args.wazuh_logtest, args.sample_log)
        if status:
            return status
    if args.apply:
        for plan in result["plans"]:
            if plan["new"]:
                source = plan["path"]
                destination = args.existing / source.name
                if destination.exists():
                    print(f"refusing overwrite: {destination}", file=sys.stderr)
                    return 1
                shutil.copy2(source, destination)
                print(f"installed: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
