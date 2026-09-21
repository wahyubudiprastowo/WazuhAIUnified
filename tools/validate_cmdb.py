#!/usr/bin/env python3
"""Validate the bounded CMDB contract without contacting Wazuh or providers."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-dashboard"))
from cve_exposure import normalize_cmdb_asset  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default=str(ROOT / "infokom-analysis" / "resource" / "assets.json"))
    args = parser.parse_args()
    path = Path(args.path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc), "file": str(path)}))
        return 2
    rows = raw.get("assets") if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        print(json.dumps({"ok": False, "error": "CMDB root must be an array or assets[]", "file": str(path)}))
        return 2
    valid = [asset for asset in (normalize_cmdb_asset(item) for item in rows) if asset]
    authoritative = [asset for asset in valid if asset.get("authoritative", True)]
    coverage = Counter()
    for asset in authoritative:
        components = asset.get("components") or []
        for field in ("owner", "criticality", "environment", "network_zone", "application", "vendor", "version", "cpe"):
            if asset.get(field) or any(component.get(field) for component in components if isinstance(component, dict)):
                coverage[field] += 1
        if (asset.get("patch_state") not in (None, "", "unknown") or
                any(component.get("patch_state") not in (None, "", "unknown") for component in components if isinstance(component, dict))):
            coverage["patch_state"] += 1
        coverage["components"] += len(components)
    print(json.dumps({
        "ok": len(valid) == len(rows), "file": str(path), "input_assets": len(rows), "valid_assets": len(valid),
        "invalid_assets": len(rows) - len(valid),
        "authoritative_assets": len(authoritative),
        "sample_assets": sum(asset.get("quality_status") == "sample" for asset in valid),
        "unverified_assets": sum(asset.get("quality_status") == "unverified" for asset in valid),
        "coverage": dict(sorted(coverage.items())),
        "missing": {field: len(authoritative) - coverage[field] for field in ("owner", "criticality", "environment", "network_zone", "application", "vendor", "version", "cpe", "patch_state")},
        "note": ("This validates supplied CMDB evidence only; it does not infer owner, CPE, patch state, or business criticality. "
                 "Sample/template rows are retained for editing but excluded from runtime correlation."),
    }, indent=2))
    return 0 if len(valid) == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
