#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="/opt/wazuh-mcp-unified/syslog-ingest"
APP="/usr/local/lib/wazuh-syslog"
SERVICE="/etc/systemd/system/wazuh-device-splitter.service"

mkdir -p \
  "$ROOT/network-devices" \
  "$APP"

touch "$ROOT/devices.json"

if [[ ! -s "$ROOT/devices.json" ]]; then
    echo '{}' > "$ROOT/devices.json"
fi

# ============================================================
# DEVICE SPLITTER
# ============================================================

cat > "$APP/device_splitter.py" <<'PY'
#!/usr/bin/env python3

import json
import os
import re
import time
import ipaddress
from pathlib import Path
from datetime import datetime


ROOT = Path(
    "/opt/wazuh-mcp-unified/syslog-ingest"
)

ARCHIVE = ROOT / "archives" / "archives.json"

OUTPUT = ROOT / "network-devices"

REGISTRY = ROOT / "devices.json"

DISCOVERED = ROOT / "discovered-devices.json"

STATE = ROOT / ".device-splitter-state.json"


def load_json(path, default):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def save_json_atomic(path, data):
    temp = path.with_suffix(path.suffix + ".tmp")

    temp.write_text(
        json.dumps(
            data,
            indent=2,
            sort_keys=True
        )
    )

    os.replace(temp, path)


def safe_name(value):
    value = str(value).strip()

    value = re.sub(
        r"[^A-Za-z0-9_.-]+",
        "_",
        value
    )

    return value[:120] or "unknown"


def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def auto_vendor(message):
    lower = message.lower()

    # --------------------------------------------------------
    # Fortinet / FortiGate
    # --------------------------------------------------------

    if (
        "fortigate" in lower
        or "fortinet" in lower
        or re.search(r"\bdevid=fg", lower)
        or (
            "devname=" in lower
            and "type=" in lower
            and "subtype=" in lower
        )
    ):
        return "fortigate"

    # --------------------------------------------------------
    # Cisco
    # --------------------------------------------------------

    if (
        "cisco" in lower
        or "%asa-" in lower
        or "%link-" in lower
        or "%sec-" in lower
        or "%sys-" in lower
    ):
        return "cisco"

    # --------------------------------------------------------
    # MikroTik
    # --------------------------------------------------------

    if (
        "mikrotik" in lower
        or "routeros" in lower
    ):
        return "mikrotik"

    # --------------------------------------------------------
    # Palo Alto
    # --------------------------------------------------------

    if (
        "palo alto" in lower
        or "pan-os" in lower
        or "panorama" in lower
    ):
        return "paloalto"

    # --------------------------------------------------------
    # Our generic laboratory format
    # --------------------------------------------------------

    if "dg-syslog" in lower:
        return "generic"

    return "unknown"


def extract_device_name(message):
    patterns = [
        r'\bdevice="?([^"\s]+)',
        r'\bdevname="?([^"\s]+)',
        r'\bhostname="?([^"\s]+)',
        r'\bhost="?([^"\s]+)',
    ]

    for pattern in patterns:
        match = re.search(
            pattern,
            message,
            flags=re.I
        )

        if match:
            return safe_name(
                match.group(1)
            )

    return None


def process_event(event):
    agent = event.get("agent") or {}

    # Network/syslog events received directly by manager normally
    # appear as agent 000.
    if str(agent.get("id", "")) != "000":
        return

    source = str(
        event.get("location", "")
    ).strip()

    # EventChannel, localfile, etc. are not network device IPs.
    if not valid_ip(source):
        return

    full_log = str(
        event.get("full_log", "")
    )

    registry = load_json(
        REGISTRY,
        {}
    )

    configured = registry.get(
        source,
        {}
    )

    vendor = safe_name(
        configured.get("vendor")
        or auto_vendor(full_log)
    ).lower()

    device_name = (
        configured.get("name")
        or extract_device_name(full_log)
        or source
    )

    device_name = safe_name(
        device_name
    )

    timestamp = event.get(
        "timestamp"
    )

    try:
        date = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        ).strftime("%Y-%m-%d")
    except Exception:
        date = datetime.utcnow().strftime(
            "%Y-%m-%d"
        )

    target_dir = (
        OUTPUT
        / vendor
        / device_name
    )

    target_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    destination = (
        target_dir
        / f"{date}.jsonl"
    )

    enriched = dict(event)

    enriched["_device"] = {
        "source_ip": source,
        "name": device_name,
        "vendor": vendor,
        "configured": source in registry,
    }

    with destination.open(
        "a",
        encoding="utf-8"
    ) as handle:

        handle.write(
            json.dumps(
                enriched,
                separators=(",", ":")
            )
            + "\n"
        )

    discovered = load_json(
        DISCOVERED,
        {}
    )

    now = datetime.utcnow().isoformat() + "Z"

    if source not in discovered:
        discovered[source] = {
            "first_seen": now,
            "last_seen": now,
            "vendor": vendor,
            "name": device_name,
            "events": 1,
        }

    else:
        discovered[source]["last_seen"] = now

        discovered[source]["events"] = (
            discovered[source].get(
                "events",
                0
            )
            + 1
        )

        # If vendor became known later, upgrade it.
        if (
            discovered[source].get(
                "vendor"
            )
            == "unknown"
            and vendor != "unknown"
        ):
            discovered[source][
                "vendor"
            ] = vendor

        if (
            discovered[source].get(
                "name"
            )
            == source
            and device_name != source
        ):
            discovered[source][
                "name"
            ] = device_name

    save_json_atomic(
        DISCOVERED,
        discovered
    )


def run():
    OUTPUT.mkdir(
        parents=True,
        exist_ok=True
    )

    print(
        f"Watching {ARCHIVE}",
        flush=True
    )

    current_inode = None
    offset = 0

    state = load_json(
        STATE,
        {}
    )

    offset = int(
        state.get(
            "offset",
            0
        )
    )

    current_inode = state.get(
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

        inode = stat.st_ino

        # New/rotated file.
        if (
            current_inode is not None
            and inode != current_inode
        ):
            print(
                "Archive rotation detected",
                flush=True
            )

            offset = 0

        # Truncated file.
        if stat.st_size < offset:
            offset = 0

        current_inode = inode

        try:
            with ARCHIVE.open(
                "r",
                encoding="utf-8",
                errors="replace"
            ) as handle:

                handle.seek(
                    offset
                )

                while True:

                    line = handle.readline()

                    if not line:
                        break

                    offset = handle.tell()

                    try:
                        event = json.loads(
                            line
                        )

                        process_event(
                            event
                        )

                    except json.JSONDecodeError:
                        pass

                    except Exception as exc:
                        print(
                            f"Event error: {exc}",
                            flush=True
                        )

                save_json_atomic(
                    STATE,
                    {
                        "inode": current_inode,
                        "offset": offset,
                    }
                )

        except Exception as exc:
            print(
                f"Read error: {exc}",
                flush=True
            )

        time.sleep(1)


if __name__ == "__main__":
    run()
PY

chmod 755 \
  "$APP/device_splitter.py"

# ============================================================
# DEVICECTL
# ============================================================

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

DISCOVERED = ROOT / "discovered-devices.json"


def load(path):
    try:
        return json.loads(
            path.read_text()
        )
    except Exception:
        return {}


def save(path, data):
    temp = path.with_suffix(
        ".tmp"
    )

    temp.write_text(
        json.dumps(
            data,
            indent=2,
            sort_keys=True
        )
    )

    os.replace(
        temp,
        path
    )


def usage():
    print("""
Usage:

  devicectl list

  devicectl discovered

  devicectl show <IP>

  devicectl add <IP> <NAME> <VENDOR>

  devicectl remove <IP>

Examples:

  devicectl add \
    192.0.2.10 \
    FGT-EDGE-01 \
    fortigate

  devicectl add \
    198.51.100.20 \
    RTR-CORE-01 \
    cisco
""")


args = sys.argv[1:]

if not args:
    usage()
    raise SystemExit(1)


command = args[0]

registry = load(
    REGISTRY
)

discovered = load(
    DISCOVERED
)


if command == "list":

    print(
        f"{'IP':<18}"
        f"{'NAME':<28}"
        f"{'VENDOR':<15}"
    )

    print("-" * 61)

    for ip, info in sorted(
        registry.items()
    ):
        print(
            f"{ip:<18}"
            f"{info.get('name','-'):<28}"
            f"{info.get('vendor','-'):<15}"
        )


elif command == "discovered":

    print(
        f"{'IP':<18}"
        f"{'NAME':<28}"
        f"{'VENDOR':<15}"
        f"{'EVENTS':<10}"
        f"{'CONFIGURED'}"
    )

    print("-" * 90)

    for ip, info in sorted(
        discovered.items()
    ):

        configured = (
            "yes"
            if ip in registry
            else "no"
        )

        print(
            f"{ip:<18}"
            f"{info.get('name','-'):<28}"
            f"{info.get('vendor','-'):<15}"
            f"{info.get('events',0):<10}"
            f"{configured}"
        )


elif command == "show":

    if len(args) != 2:
        usage()
        raise SystemExit(1)

    ip = args[1]

    print(
        json.dumps(
            {
                "configured":
                    registry.get(ip),
                "discovered":
                    discovered.get(ip),
            },
            indent=2
        )
    )


elif command == "add":

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
        registry
    )

    print(
        f"[OK] Device registered: "
        f"{ip} -> {vendor}/{name}"
    )


elif command == "remove":

    if len(args) != 2:
        usage()
        raise SystemExit(1)

    ip = args[1]

    if ip in registry:
        registry.pop(
            ip
        )

        save(
            REGISTRY,
            registry
        )

        print(
            f"[OK] Removed {ip}"
        )

    else:
        print(
            f"[INFO] {ip} not configured"
        )


else:
    usage()
    raise SystemExit(1)
PY

chmod 755 \
  /usr/local/bin/devicectl

# ============================================================
# SYSTEMD
# ============================================================

cat > "$SERVICE" <<'UNIT'
[Unit]
Description=Wazuh Syslog Device Auto Splitter
After=docker.service
Wants=docker.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/lib/wazuh-syslog/device_splitter.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload

systemctl enable \
  --now \
  wazuh-device-splitter.service

sleep 3

echo
echo "========================================"
echo " DEVICE SPLITTER STATUS"
echo "========================================"

systemctl \
  --no-pager \
  --full \
  status wazuh-device-splitter.service \
  | head -20

echo
echo "========================================"
echo " DISCOVERED DEVICES"
echo "========================================"

devicectl discovered || true

echo
echo "========================================"
echo " OUTPUT DIRECTORY"
echo "========================================"

find "$ROOT/network-devices" \
  -maxdepth 3 \
  -type d \
  -print \
  | sort

echo
echo "========================================"
echo " INSTALL COMPLETE"
echo "========================================"

echo
echo "Commands:"
echo "  devicectl discovered"
echo "  devicectl list"
echo "  devicectl show <IP>"
echo "  devicectl add <IP> <NAME> <VENDOR>"
echo
