#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="/opt/wazuh-mcp-unified/syslog-ingest"
APP="/usr/local/lib/wazuh-syslog"
SPLITTER="$APP/device_splitter.py"
SERVICE="wazuh-device-splitter"

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="/opt/wazuh-mcp-unified/backups/device-splitter-$STAMP"

mkdir -p "$BACKUP" "$APP" "$ROOT/network-devices"

if [[ -f "$SPLITTER" ]]; then
    cp -a "$SPLITTER" "$BACKUP/"
fi

if [[ -f /usr/local/bin/devicectl ]]; then
    cp -a /usr/local/bin/devicectl "$BACKUP/"
fi

echo "============================================"
echo " WAZUH DEVICE DISCOVERY UPGRADE"
echo "============================================"
echo "Backup: $BACKUP"

cat > "$SPLITTER" <<'PY'
#!/usr/bin/env python3

import ipaddress
import json
import os
import re
import time

from collections import deque
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path("/opt/wazuh-mcp-unified/syslog-ingest")

ARCHIVE = ROOT / "archives" / "archives.json"
OUTPUT = ROOT / "network-devices"

REGISTRY = ROOT / "devices.json"
DISCOVERED = ROOT / "discovered-devices.json"
STATE = ROOT / ".device-splitter-state.json"

MAX_SAMPLE_LINES = 20


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_json(path, default):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def save_json_atomic(path, data):
    temp = Path(str(path) + ".tmp")

    temp.write_text(
        json.dumps(
            data,
            indent=2,
            sort_keys=True,
        )
    )

    os.replace(temp, path)


def safe_name(value):
    value = str(value or "").strip()

    value = re.sub(
        r"[^A-Za-z0-9_.-]+",
        "_",
        value,
    )

    return value[:120] or "unknown"


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def detect_vendor(message):
    msg = message.lower()

    # Fortinet / FortiGate
    if (
        "fortigate" in msg
        or "fortinet" in msg
        or re.search(r"\bdevid=['\"]?fg", msg)
        or (
            "devname=" in msg
            and "type=" in msg
            and "subtype=" in msg
        )
    ):
        return "fortigate"

    # Cisco ASA / IOS / NX-OS
    if (
        "cisco" in msg
        or "%asa-" in msg
        or "%ftd-" in msg
        or "%link-" in msg
        or "%lineproto-" in msg
        or "%sys-" in msg
        or "%sec-" in msg
    ):
        return "cisco"

    # MikroTik RouterOS
    if (
        "mikrotik" in msg
        or "routeros" in msg
    ):
        return "mikrotik"

    # Palo Alto
    if (
        "palo alto" in msg
        or "pan-os" in msg
        or "panorama" in msg
    ):
        return "paloalto"

    # Juniper
    if (
        "juniper" in msg
        or "junos" in msg
    ):
        return "juniper"

    # Our development marker
    if "dg-syslog" in msg:
        return "generic"

    return "unknown"


def extract_name(message):
    patterns = (
        r'\bdevice="?([^"\s]+)',
        r'\bdevname="?([^"\s]+)',
        r'\bhostname="?([^"\s]+)',
        r'\bhost="?([^"\s]+)',
    )

    for pattern in patterns:
        match = re.search(
            pattern,
            message,
            flags=re.I,
        )

        if match:
            return safe_name(
                match.group(1)
            )

    return None


def append_sample(path, raw):
    existing = deque(
        maxlen=MAX_SAMPLE_LINES
    )

    if path.exists():
        try:
            with path.open(
                "r",
                encoding="utf-8",
                errors="replace",
            ) as handle:

                for line in handle:
                    existing.append(
                        line.rstrip("\n")
                    )

        except Exception:
            pass

    raw = raw.strip()

    if raw and raw not in existing:
        existing.append(raw)

    with path.open(
        "w",
        encoding="utf-8",
    ) as handle:

        for line in existing:
            handle.write(
                line + "\n"
            )


def process_event(event):
    agent = event.get("agent") or {}

    # Agent 000 = manager/local/remote syslog.
    # We still require location to be an IP below,
    # preventing normal EventChannel logs from being
    # classified as network devices.
    if str(agent.get("id", "")) != "000":
        return

    source_ip = str(
        event.get("location", "")
    ).strip()

    if not is_valid_ip(source_ip):
        return

    full_log = str(
        event.get("full_log", "")
    )

    registry = load_json(
        REGISTRY,
        {}
    )

    configured = registry.get(
        source_ip,
        {}
    )

    auto_vendor = detect_vendor(
        full_log
    )

    vendor = safe_name(
        configured.get("vendor")
        or auto_vendor
    ).lower()

    auto_name = extract_name(
        full_log
    )

    name = safe_name(
        configured.get("name")
        or auto_name
        or source_ip
    )

    timestamp = event.get(
        "timestamp"
    )

    try:
        dt = datetime.fromisoformat(
            timestamp.replace(
                "Z",
                "+00:00",
            )
        )

        day = dt.strftime(
            "%Y-%m-%d"
        )

    except Exception:
        day = datetime.now(
            timezone.utc
        ).strftime(
            "%Y-%m-%d"
        )

    target_dir = (
        OUTPUT
        / vendor
        / name
    )

    target_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    event_file = (
        target_dir
        / f"{day}.jsonl"
    )

    enriched = dict(event)

    enriched["_device"] = {
        "source_ip": source_ip,
        "name": name,
        "vendor": vendor,
        "auto_vendor": auto_vendor,
        "configured":
            source_ip in registry,
    }

    with event_file.open(
        "a",
        encoding="utf-8",
    ) as handle:

        handle.write(
            json.dumps(
                enriched,
                separators=(",", ":"),
            )
            + "\n"
        )

    append_sample(
        target_dir / "samples.log",
        full_log,
    )

    discovered = load_json(
        DISCOVERED,
        {}
    )

    now = utc_now()

    info = discovered.get(
        source_ip,
        {}
    )

    if not info:
        info = {
            "first_seen": now,
            "events": 0,
        }

    info["last_seen"] = now

    info["events"] = (
        int(info.get("events", 0))
        + 1
    )

    info["vendor"] = vendor
    info["auto_vendor"] = auto_vendor
    info["name"] = name

    info["configured"] = (
        source_ip in registry
    )

    info["directory"] = str(
        target_dir
    )

    info["sample_file"] = str(
        target_dir / "samples.log"
    )

    discovered[source_ip] = info

    save_json_atomic(
        DISCOVERED,
        discovered,
    )


def run():
    OUTPUT.mkdir(
        parents=True,
        exist_ok=True,
    )

    print(
        f"Watching: {ARCHIVE}",
        flush=True,
    )

    state = load_json(
        STATE,
        {},
    )

    offset = int(
        state.get(
            "offset",
            0,
        )
    )

    inode = state.get(
        "inode"
    )

    while True:
        if not ARCHIVE.exists():
            time.sleep(2)
            continue

        try:
            stat = ARCHIVE.stat()
        except FileNotFoundError:
            time.sleep(2)
            continue

        current_inode = stat.st_ino

        if (
            inode is not None
            and current_inode != inode
        ):
            print(
                "Archive rotation detected",
                flush=True,
            )

            offset = 0

        if stat.st_size < offset:
            offset = 0

        inode = current_inode

        try:
            with ARCHIVE.open(
                "r",
                encoding="utf-8",
                errors="replace",
            ) as handle:

                handle.seek(offset)

                while True:
                    line = handle.readline()

                    if not line:
                        break

                    offset = handle.tell()

                    try:
                        process_event(
                            json.loads(line)
                        )

                    except json.JSONDecodeError:
                        continue

                    except Exception as exc:
                        print(
                            f"event error: {exc}",
                            flush=True,
                        )

            save_json_atomic(
                STATE,
                {
                    "inode": inode,
                    "offset": offset,
                },
            )

        except Exception as exc:
            print(
                f"read error: {exc}",
                flush=True,
            )

        time.sleep(1)


if __name__ == "__main__":
    run()
PY

chmod 755 "$SPLITTER"

# ---------------------------------------------------------
# Better devicectl
# ---------------------------------------------------------

cat > /usr/local/bin/devicectl <<'PY'
#!/usr/bin/env python3

import json
import os
import sys

from pathlib import Path


ROOT = Path(
    "/opt/wazuh-mcp-unified/syslog-ingest"
)

REGISTRY = ROOT / "devices.json"

DISCOVERED = (
    ROOT
    / "discovered-devices.json"
)


def load(path):
    try:
        return json.loads(
            path.read_text()
        )
    except Exception:
        return {}


def save(path, data):
    temp = Path(
        str(path) + ".tmp"
    )

    temp.write_text(
        json.dumps(
            data,
            indent=2,
            sort_keys=True,
        )
    )

    os.replace(
        temp,
        path,
    )


def usage():
    print("""
devicectl commands

  devicectl discovered
  devicectl list
  devicectl show <IP>
  devicectl samples <IP>
  devicectl add <IP> <NAME> <VENDOR>
  devicectl remove <IP>

Examples:

  devicectl discovered

  devicectl samples 192.0.2.10

  devicectl add \
    192.0.2.10 \
    FGT-EDGE-01 \
    fortigate
""")


args = sys.argv[1:]

if not args:
    usage()
    raise SystemExit(1)


cmd = args[0]

registry = load(
    REGISTRY
)

discovered = load(
    DISCOVERED
)


if cmd == "discovered":

    print(
        f"{'IP':<18}"
        f"{'NAME':<25}"
        f"{'VENDOR':<13}"
        f"{'EVENTS':<10}"
        f"{'CONFIG':<9}"
        f"LAST SEEN"
    )

    print("-" * 110)

    for ip, info in sorted(
        discovered.items()
    ):

        print(
            f"{ip:<18}"
            f"{str(info.get('name','-')):<25}"
            f"{str(info.get('vendor','-')):<13}"
            f"{str(info.get('events',0)):<10}"
            f"{str(info.get('configured',False)):<9}"
            f"{info.get('last_seen','-')}"
        )


elif cmd == "list":

    print(
        f"{'IP':<18}"
        f"{'NAME':<30}"
        f"{'VENDOR'}"
    )

    print("-" * 65)

    for ip, info in sorted(
        registry.items()
    ):

        print(
            f"{ip:<18}"
            f"{str(info.get('name','-')):<30}"
            f"{info.get('vendor','-')}"
        )


elif cmd == "show":

    if len(args) != 2:
        usage()
        raise SystemExit(1)

    ip = args[1]

    print(
        json.dumps(
            {
                "registry":
                    registry.get(ip),
                "discovered":
                    discovered.get(ip),
            },
            indent=2,
        )
    )


elif cmd == "samples":

    if len(args) != 2:
        usage()
        raise SystemExit(1)

    ip = args[1]

    info = discovered.get(
        ip
    )

    if not info:
        print(
            f"No discovered device: {ip}"
        )
        raise SystemExit(1)

    sample_file = info.get(
        "sample_file"
    )

    if not sample_file:
        print(
            "No sample file available"
        )
        raise SystemExit(1)

    path = Path(
        sample_file
    )

    if not path.exists():
        print(
            f"Sample file missing: {path}"
        )
        raise SystemExit(1)

    print(
        path.read_text(
            errors="replace"
        )
    )


elif cmd == "add":

    if len(args) != 4:
        usage()
        raise SystemExit(1)

    ip = args[1]
    name = args[2]
    vendor = args[3].lower()

    registry[ip] = {
        "name": name,
        "vendor": vendor,
    }

    save(
        REGISTRY,
        registry,
    )

    print(
        f"[OK] {ip} -> "
        f"{vendor}/{name}"
    )


elif cmd == "remove":

    if len(args) != 2:
        usage()
        raise SystemExit(1)

    ip = args[1]

    registry.pop(
        ip,
        None,
    )

    save(
        REGISTRY,
        registry,
    )

    print(
        f"[OK] Removed {ip}"
    )


else:
    usage()
    raise SystemExit(1)
PY

chmod 755 \
/usr/local/bin/devicectl

# Reset offset so current archive is re-scanned.
# This does NOT touch Wazuh itself.
rm -f \
"$ROOT/.device-splitter-state.json"

systemctl restart \
wazuh-device-splitter

sleep 5

echo
echo "=== SERVICE ==="

systemctl \
--no-pager \
--full \
status wazuh-device-splitter \
| head -20

echo
echo "=== DISCOVERED ==="

devicectl discovered || true

echo
echo "=== DIRECTORY ==="

find \
"$ROOT/network-devices" \
-maxdepth 3 \
-type d \
| sort

echo
echo "============================================"
echo " UPGRADE COMPLETE"
echo "============================================"
