#!/usr/bin/env bash
set -Eeuo pipefail

BASE="/opt/wazuh-mcp-unified/wazuh-stack/single-node"
CONF="$BASE/config/wazuh_cluster/wazuh_manager.conf"
MANAGER="single-node-wazuh.manager-1"

DEVICE_IP="${1:-${DEVICE_IP:-}}"

if [[ -z "$DEVICE_IP" ]]; then
    echo "Usage: $0 <device-ip>"
    echo "Or set DEVICE_IP in the environment."
    exit 2
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="/opt/wazuh-mcp-unified/backups/syslog-allow-$STAMP"

mkdir -p "$BACKUP"

cp -a "$CONF" \
"$BACKUP/wazuh_manager.conf"

echo "========================================"
echo " ADD SYSLOG DEVICE"
echo "========================================"
echo "Device IP : $DEVICE_IP"
echo "Backup    : $BACKUP"

python3 - "$CONF" "$DEVICE_IP" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
device_ip = sys.argv[2]

text = path.read_text()

blocks = list(
    re.finditer(
        r"<remote>.*?</remote>",
        text,
        flags=re.S | re.I,
    )
)

changed = False

for match in reversed(blocks):

    block = match.group(0)

    if not re.search(
        r"<connection>\s*syslog\s*</connection>",
        block,
        flags=re.I,
    ):
        continue

    if re.search(
        rf"<allowed-ips>\s*{re.escape(device_ip)}\s*</allowed-ips>",
        block,
        flags=re.I,
    ):
        continue

    pos = block.rfind("</remote>")

    new_block = (
        block[:pos]
        + f"  <allowed-ips>{device_ip}</allowed-ips>\n"
        + block[pos:]
    )

    text = (
        text[:match.start()]
        + new_block
        + text[match.end():]
    )

    changed = True


if changed:
    path.write_text(text)
    print(f"[OK] Added {device_ip}")
else:
    print(f"[INFO] {device_ip} already configured")
PY

echo
echo "=== CURRENT SYSLOG CONFIG ==="

grep -n -A10 -B2 \
'<connection>syslog</connection>' \
"$CONF"

echo
echo "=== RESTART WAZUH SERVICES INSIDE CONTAINER ==="

docker exec "$MANAGER" \
/var/ossec/bin/wazuh-control restart

sleep 12

echo
echo "=== CHECK MANAGER ==="

docker exec "$MANAGER" sh -c '
ps aux |
grep -E "[w]azuh-remoted|[w]azuh-analysisd|[w]azuh-apid"
'

echo
echo "=== WAIT FOR SYSLOG FROM DEVICE ==="

sleep 10

echo
echo "=== SEARCH RAW ARCHIVE ==="

docker exec "$MANAGER" \
grep -F "$DEVICE_IP" /var/ossec/logs/archives/archives.json \
2>/dev/null | tail -5 || true

echo
echo "=== HOST ARCHIVE ==="

grep -F "$DEVICE_IP" \
/opt/wazuh-mcp-unified/syslog-ingest/archives/archives.json \
2>/dev/null |
tail -5 || true

echo
echo "=== DEVICE SPLITTER ==="

systemctl restart wazuh-device-splitter

sleep 5

devicectl discovered || true

echo
echo "========================================"
echo " DONE"
echo "========================================"
