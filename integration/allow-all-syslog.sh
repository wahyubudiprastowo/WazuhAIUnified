#!/usr/bin/env bash
set -Eeuo pipefail

BASE="/opt/wazuh-mcp-unified/wazuh-stack/single-node"
CONF="$BASE/config/wazuh_cluster/wazuh_manager.conf"
MANAGER="single-node-wazuh.manager-1"

if [[ -f "$BASE/docker-compose.yml" ]]; then
    COMPOSE="$BASE/docker-compose.yml"
else
    COMPOSE="$BASE/docker-compose.yaml"
fi

OVERRIDE="$BASE/docker-compose.syslog.yml"

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="/opt/wazuh-mcp-unified/backups/syslog-allow-all-$STAMP"

mkdir -p "$BACKUP"
cp -a "$CONF" "$BACKUP/wazuh_manager.conf"

echo "=========================================="
echo " WAZUH ALLOW ALL SYSLOG IPV4"
echo "=========================================="
echo "Backup: $BACKUP"

python3 - "$CONF" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text()

pattern = re.compile(
    r"<remote>.*?</remote>",
    flags=re.S | re.I
)

changed = 0

def patch(match):
    global changed

    block = match.group(0)

    if not re.search(
        r"<connection>\s*syslog\s*</connection>",
        block,
        flags=re.I
    ):
        return block

    # Remove all existing allowed-ips entries
    block = re.sub(
        r"\s*<allowed-ips>.*?</allowed-ips>",
        "",
        block,
        flags=re.I
    )

    # Insert one allow-all entry before closing remote
    block = block.replace(
        "</remote>",
        "    <allowed-ips>0.0.0.0/0</allowed-ips>\n"
        "  </remote>"
    )

    changed += 1
    return block


new_text = pattern.sub(
    patch,
    text
)

if changed == 0:
    raise SystemExit(
        "ERROR: no Syslog <remote> blocks found"
    )

path.write_text(new_text)

print(
    f"[OK] Patched {changed} Syslog listener(s)"
)
PY

echo
echo "=== CONFIG RESULT ==="

grep -n -A8 -B2 \
'<connection>syslog</connection>' \
"$CONF"

echo
echo "=== COMPOSE VALIDATION ==="

docker compose \
    -f "$COMPOSE" \
    -f "$OVERRIDE" \
    config >/dev/null

echo "[OK] Compose valid"

echo
echo "=== RECREATE MANAGER ONLY ==="

docker compose \
    -f "$COMPOSE" \
    -f "$OVERRIDE" \
    up -d \
    --no-deps \
    --force-recreate \
    wazuh.manager

echo "Waiting for manager..."
sleep 15

echo
echo "=== ACTIVE CONFIG ==="

docker exec "$MANAGER" \
grep -n -A8 -B2 \
'<connection>syslog</connection>' \
/var/ossec/etc/ossec.conf

echo
echo "=== CHECK PORTS ==="

ss -lunp | grep ':514 ' || true
ss -lntp | grep ':514 ' || true

echo
echo "=== RECENT SYSLOG REJECTION ==="

docker exec "$MANAGER" sh -c '
tail -n 100 /var/ossec/logs/ossec.log |
grep -E "not allowed" ||
true
'

echo
echo "Set DEVICE_IP and use allow-syslog-device.sh to verify one device."

echo
echo "=== DEVICE DISCOVERY ==="

systemctl restart wazuh-device-splitter

sleep 4

devicectl discovered || true

echo
echo "=========================================="
echo " DONE"
echo "=========================================="
