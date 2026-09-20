#!/usr/bin/env bash
set -Eeuo pipefail

BASE="/opt/wazuh-mcp-unified/wazuh-stack/single-node"
ROOT="/opt/wazuh-mcp-unified/syslog-ingest"
BACKUPS="/opt/wazuh-mcp-unified/backups"
MANAGER="single-node-wazuh.manager-1"
MANAGER_CONF="$BASE/config/wazuh_cluster/wazuh_manager.conf"

ALLOWED_NET="${ALLOWED_NET:-${1:-}}"

if [[ -z "$ALLOWED_NET" ]]; then
    echo "Usage: ALLOWED_NET=<trusted-cidr> $0"
    echo "Or pass the trusted CIDR as the first argument."
    exit 2
fi

if [[ -f "$BASE/docker-compose.yml" ]]; then
    COMPOSE="$BASE/docker-compose.yml"
elif [[ -f "$BASE/docker-compose.yaml" ]]; then
    COMPOSE="$BASE/docker-compose.yaml"
else
    echo "ERROR: compose file not found"
    exit 1
fi

OVERRIDE="$BASE/docker-compose.syslog.yml"

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="$BACKUPS/syslog-foundation-$STAMP"

echo "========================================"
echo " WAZUH SYSLOG FOUNDATION"
echo "========================================"

mkdir -p \
    "$ROOT/archives" \
    "$ROOT/decoders" \
    "$ROOT/rules" \
    "$ROOT/samples" \
    "$BACKUP"

cp -a "$MANAGER_CONF" \
    "$BACKUP/wazuh_manager.conf"

echo "[OK] Backup: $BACKUP"

# ------------------------------------------------
# 1. Enable raw JSON archive
# ------------------------------------------------

python3 - "$MANAGER_CONF" "$ALLOWED_NET" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
allowed = sys.argv[2]

text = path.read_text()

# Enable JSON archive only.
if "<logall_json>no</logall_json>" in text:
    text = text.replace(
        "<logall_json>no</logall_json>",
        "<logall_json>yes</logall_json>",
        1,
    )
elif "<logall_json>yes</logall_json>" not in text:
    marker = "<alerts_log>yes</alerts_log>"
    if marker not in text:
        raise SystemExit(
            "ERROR: unable to locate global logging block"
        )

    text = text.replace(
        marker,
        marker + "\n    <logall_json>yes</logall_json>",
        1,
    )

def has_syslog(proto):
    pattern = (
        r"<remote>.*?"
        r"<connection>\s*syslog\s*</connection>.*?"
        rf"<protocol>\s*{proto}\s*</protocol>.*?"
        r"</remote>"
    )
    return bool(
        re.search(
            pattern,
            text,
            flags=re.S | re.I,
        )
    )

blocks = []

for proto in ("udp", "tcp"):
    if not has_syslog(proto):
        blocks.append(
f"""
  <!-- Digiserve network-device Syslog {proto.upper()} -->
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>{proto}</protocol>
    <allowed-ips>{allowed}</allowed-ips>
  </remote>
"""
        )

if blocks:
    pos = text.rfind("</ossec_config>")

    if pos == -1:
        raise SystemExit(
            "ERROR: </ossec_config> not found"
        )

    text = (
        text[:pos]
        + "\n"
        + "".join(blocks)
        + "\n"
        + text[pos:]
    )

path.write_text(text)

print("[OK] logall_json enabled")
print("[OK] Syslog UDP/TCP configuration checked")
PY

# ------------------------------------------------
# 2. Generic test decoder
# ------------------------------------------------

cat > "$ROOT/decoders/99-dg-network-device.xml" <<'XML'
<decoder name="dg-network-device">
  <program_name>^DG-SYSLOG$</program_name>
  <regex type="pcre2">^device=([^\s]+)\s+vendor=([^\s]+)\s+srcip=([^\s]+)\s+dstip=([^\s]+)\s+action=([^\s]+)</regex>
  <order>device_name,device_vendor,srcip,dstip,action</order>
</decoder>
XML

# ------------------------------------------------
# 3. Generic rules
# ------------------------------------------------

cat > "$ROOT/rules/99-dg-network-device.xml" <<'XML'
<group name="local,syslog,network_device,">

  <rule id="100100" level="3">
    <decoded_as>dg-network-device</decoded_as>
    <description>Network device syslog received from $(device_name) [$(device_vendor)]</description>
    <group>syslog,network_device,</group>
  </rule>

  <rule id="100101" level="6">
    <if_sid>100100</if_sid>
    <field name="action" type="pcre2">(?i)^(deny|drop|blocked)$</field>
    <description>Network device blocked traffic: $(device_name) $(srcip) -> $(dstip)</description>
    <group>syslog,network_device,firewall_drop,</group>
  </rule>

</group>
XML

# ------------------------------------------------
# 4. Permissions
# ------------------------------------------------

WAZUH_UID="$(docker exec "$MANAGER" id -u wazuh)"
WAZUH_GID="$(docker exec "$MANAGER" id -g wazuh)"

chown -R \
    "$WAZUH_UID:$WAZUH_GID" \
    "$ROOT/archives"

chmod 750 "$ROOT/archives"
chmod 755 "$ROOT/decoders" "$ROOT/rules"
chmod 644 \
    "$ROOT/decoders/99-dg-network-device.xml" \
    "$ROOT/rules/99-dg-network-device.xml"

# ------------------------------------------------
# 5. Compose override
#    Base compose is NOT modified.
# ------------------------------------------------

TCP_PORT=""

if ! grep -Eq \
    '514:514/tcp' \
    "$COMPOSE"
then

TCP_PORT='
    ports:
      - "514:514/tcp"'
fi

cat > "$OVERRIDE" <<EOF
services:
  wazuh.manager:${TCP_PORT}
    volumes:
      - "$ROOT/archives:/var/ossec/logs/archives"
      - "$ROOT/decoders/99-dg-network-device.xml:/var/ossec/etc/decoders/99-dg-network-device.xml:ro"
      - "$ROOT/rules/99-dg-network-device.xml:/var/ossec/etc/rules/99-dg-network-device.xml:ro"
EOF

# ------------------------------------------------
# 6. Validate Compose BEFORE touching container
# ------------------------------------------------

docker compose \
    -f "$COMPOSE" \
    -f "$OVERRIDE" \
    config >/dev/null

echo "[OK] Compose configuration valid"

# ------------------------------------------------
# 7. Recreate Manager only
# ------------------------------------------------

docker compose \
    -f "$COMPOSE" \
    -f "$OVERRIDE" \
    up -d \
    --force-recreate \
    wazuh.manager

echo "Waiting for manager..."
sleep 15

if ! docker inspect "$MANAGER" \
    --format '{{.State.Running}}' \
    | grep -q true
then

    echo "ERROR: Manager did not start."
    echo "Restoring previous configuration..."

    cp -a \
        "$BACKUP/wazuh_manager.conf" \
        "$MANAGER_CONF"

    docker compose \
        -f "$COMPOSE" \
        up -d \
        --force-recreate \
        wazuh.manager

    exit 1
fi

# ------------------------------------------------
# 8. Validate Wazuh analysis config
# ------------------------------------------------

echo
echo "=== WAZUH ANALYSIS CONFIG TEST ==="

docker exec "$MANAGER" \
    /var/ossec/bin/wazuh-analysisd -t \
    || true

# ------------------------------------------------
# 9. Offline decoder test
# ------------------------------------------------

TEST='Aug 21 16:55:00 lab-router DG-SYSLOG: device=LAB-RTR-01 vendor=generic srcip=198.51.100.23 dstip=203.0.113.10 action=deny'

echo
echo "=== WAZUH LOGTEST ==="

printf '%s\n' "$TEST" |
docker exec -i "$MANAGER" \
    /var/ossec/bin/wazuh-logtest \
    2>/dev/null \
    | tail -n 30 \
    || true

# ------------------------------------------------
# 10. Send actual UDP syslog
# ------------------------------------------------

echo
echo "=== SEND REAL SYSLOG ==="

# Wazuh manager host that receives the syslog test egress (default: localhost).
SYSLOG_HOST="${SYSLOG_HOST:-127.0.0.1}"

logger \
    -n "$SYSLOG_HOST" \
    -P 514 \
    -d \
    -t DG-SYSLOG \
    "device=LAB-RTR-01 vendor=generic srcip=198.51.100.23 dstip=203.0.113.10 action=deny"

echo "[OK] Test Syslog sent"

sleep 8

echo
echo "=== LOOK FOR TEST ALERT ==="

docker exec "$MANAGER" \
    sh -c \
    'grep -F "LAB-RTR-01" /var/ossec/logs/alerts/alerts.json | tail -3' \
    || true

echo
echo "=== RAW ARCHIVE DIRECTORY ==="

ls -lah "$ROOT/archives" || true

echo
echo "========================================"
echo " DONE"
echo "========================================"
echo
echo "Host raw archive:"
echo "$ROOT/archives"
echo
echo "Decoder:"
echo "$ROOT/decoders/99-dg-network-device.xml"
echo
echo "Rules:"
echo "$ROOT/rules/99-dg-network-device.xml"
echo
echo "Compose override:"
echo "$OVERRIDE"
echo
echo "Allowed network:"
echo "$ALLOWED_NET"
