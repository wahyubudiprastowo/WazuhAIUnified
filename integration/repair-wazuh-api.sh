#!/usr/bin/env bash
set -Eeuo pipefail

BASE="/opt/wazuh-mcp-unified/wazuh-stack/single-node"

MANAGER="single-node-wazuh.manager-1"
DASHBOARD="single-node-wazuh.dashboard-1"

if [[ -f "$BASE/docker-compose.yml" ]]; then
    COMPOSE="$BASE/docker-compose.yml"
else
    COMPOSE="$BASE/docker-compose.yaml"
fi

OVERRIDE="$BASE/docker-compose.syslog.yml"

echo "================================================"
echo " WAZUH MANAGER API RECOVERY"
echo "================================================"

# ------------------------------------------------
# Helpers
# ------------------------------------------------

get_env() {
    local container="$1"
    local key="$2"

    docker inspect "$container" \
        --format '{{range .Config.Env}}{{println .}}{{end}}' \
        | awk -F= -v k="$key" '
            $1 == k {
                sub(/^[^=]*=/, "")
                print
                exit
            }
        '
}

api_http_code() {
    curl -sk \
        --connect-timeout 5 \
        --max-time 10 \
        -o /dev/null \
        -w '%{http_code}' \
        https://127.0.0.1:55000/ \
        2>/dev/null || true
}

auth_http_code() {
    local user="$1"
    local pass="$2"

    curl -sk \
        --connect-timeout 5 \
        --max-time 10 \
        -u "$user:$pass" \
        -X POST \
        -o /tmp/wazuh-auth-test.$$ \
        -w '%{http_code}' \
        'https://127.0.0.1:55000/security/user/authenticate?raw=true' \
        2>/dev/null || true

    rm -f /tmp/wazuh-auth-test.$$
}

# ------------------------------------------------
# 1. Containers
# ------------------------------------------------

echo
echo "=== 1. CONTAINER STATUS ==="

docker ps \
    --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' \
    | grep -E \
      'single-node-wazuh.(manager|dashboard|indexer)-1' \
    || true

# ------------------------------------------------
# 2. API process
# ------------------------------------------------

echo
echo "=== 2. MANAGER API PROCESS ==="

docker exec "$MANAGER" sh -c '
ps aux |
grep -Ei "[w]azuh-apid|api/scripts|wazuh.*api" ||
true
'

echo
echo "=== 3. PORT 55000 ==="

docker exec "$MANAGER" sh -c '
ss -lntp 2>/dev/null |
grep ":55000 " ||
netstat -lntp 2>/dev/null |
grep ":55000 " ||
true
'

CODE="$(api_http_code)"

echo
echo "Host -> Manager API HTTP: ${CODE:-000}"

# ------------------------------------------------
# 3. If API unreachable, restart Wazuh internally
# ------------------------------------------------

if [[ -z "$CODE" || "$CODE" == "000" ]]; then

    echo
    echo "[WARN] Manager API is unreachable."
    echo "[ACTION] Restarting Wazuh internal services only..."

    docker exec "$MANAGER" \
        /var/ossec/bin/wazuh-control restart

    sleep 15

    CODE="$(api_http_code)"

    echo "After wazuh-control restart HTTP: ${CODE:-000}"
fi

# ------------------------------------------------
# 4. Still dead? Recreate ONLY manager
# ------------------------------------------------

if [[ -z "$CODE" || "$CODE" == "000" ]]; then

    echo
    echo "[WARN] API still unreachable."
    echo "[ACTION] Recreating manager container only."
    echo "         Dashboard/Indexer will NOT be recreated."

    docker compose \
        -f "$COMPOSE" \
        -f "$OVERRIDE" \
        up -d \
        --no-deps \
        --force-recreate \
        wazuh.manager

    sleep 20

    CODE="$(api_http_code)"

    echo "After manager recreate HTTP: ${CODE:-000}"
fi

# ------------------------------------------------
# 5. Stop here if API itself is still dead
# ------------------------------------------------

if [[ -z "$CODE" || "$CODE" == "000" ]]; then

    echo
    echo "================================================"
    echo " API STILL UNREACHABLE"
    echo "================================================"

    echo
    echo "=== MANAGER LOG ==="

    docker logs "$MANAGER" \
        --tail 150 2>&1 \
        | tail -150

    echo
    echo "=== WAZUH API LOG ==="

    docker exec "$MANAGER" sh -c '
    if [ -f /var/ossec/logs/api.log ]; then
        tail -n 150 /var/ossec/logs/api.log
    else
        echo "api.log not found"
    fi
    ' || true

    exit 1
fi

echo
echo "[OK] Manager API TCP/HTTPS is reachable."

# ------------------------------------------------
# 6. Dashboard -> manager DNS
# ------------------------------------------------

echo
echo "=== 4. DASHBOARD DNS ==="

docker exec "$DASHBOARD" sh -c '
getent hosts wazuh.manager || true
'

# ------------------------------------------------
# 7. Dashboard -> manager network
# ------------------------------------------------

echo
echo "=== 5. DASHBOARD -> MANAGER API ==="

docker exec "$DASHBOARD" sh -c '
if command -v curl >/dev/null 2>&1; then

    CODE=$(curl -sk \
        --connect-timeout 5 \
        --max-time 10 \
        -o /dev/null \
        -w "%{http_code}" \
        https://wazuh.manager:55000/ \
        2>/dev/null || true)

    echo "Dashboard -> wazuh.manager:55000 HTTP=${CODE:-000}"

else
    echo "curl not available in dashboard container"
fi
'

# ------------------------------------------------
# 8. Read API credentials from container ENV
#    DO NOT PRINT THEM
# ------------------------------------------------

echo
echo "=== 6. API CREDENTIAL CONSISTENCY ==="

MUSER="$(get_env "$MANAGER" API_USERNAME)"
MPASS="$(get_env "$MANAGER" API_PASSWORD)"

DUSER="$(get_env "$DASHBOARD" API_USERNAME)"
DPASS="$(get_env "$DASHBOARD" API_PASSWORD)"

echo "Manager API username configured : $([[ -n "$MUSER" ]] && echo YES || echo NO)"
echo "Manager API password configured : $([[ -n "$MPASS" ]] && echo YES || echo NO)"

echo "Dashboard API username configured: $([[ -n "$DUSER" ]] && echo YES || echo NO)"
echo "Dashboard API password configured: $([[ -n "$DPASS" ]] && echo YES || echo NO)"

if [[ -n "$MUSER" && -n "$DUSER" && "$MUSER" == "$DUSER" ]]; then
    echo "Username manager/dashboard      : MATCH"
else
    echo "Username manager/dashboard      : MISMATCH"
fi

if [[ -n "$MPASS" && -n "$DPASS" && "$MPASS" == "$DPASS" ]]; then
    echo "Password manager/dashboard      : MATCH"
else
    echo "Password manager/dashboard      : MISMATCH"
fi

# ------------------------------------------------
# 9. Authenticate using Dashboard credentials
# ------------------------------------------------

AUTH_CODE="000"

if [[ -n "$DUSER" && -n "$DPASS" ]]; then
    AUTH_CODE="$(auth_http_code "$DUSER" "$DPASS")"
fi

echo
echo "Dashboard credentials -> API auth HTTP: $AUTH_CODE"

# ------------------------------------------------
# 10. Credentials valid = restart dashboard only
# ------------------------------------------------

if [[ "$AUTH_CODE" == "200" ]]; then

    echo
    echo "[OK] Dashboard API credentials are valid."
    echo "[ACTION] Restarting Dashboard only..."

    docker restart "$DASHBOARD" >/dev/null

    sleep 15

    echo
    echo "Dashboard restarted."

else

    echo
    echo "[WARN] Dashboard credentials could not authenticate."

    # Also test manager-side configured credentials.
    MANAGER_AUTH_CODE="000"

    if [[ -n "$MUSER" && -n "$MPASS" ]]; then
        MANAGER_AUTH_CODE="$(auth_http_code "$MUSER" "$MPASS")"
    fi

    echo "Manager configured credentials auth HTTP: $MANAGER_AUTH_CODE"

    if [[ "$MANAGER_AUTH_CODE" == "200" ]]; then

        echo
        echo "[DIAGNOSIS]"
        echo "Manager API credentials work,"
        echo "but Dashboard credentials do not."
        echo
        echo "Recreating Dashboard from Compose configuration..."

        docker compose \
            -f "$COMPOSE" \
            -f "$OVERRIDE" \
            up -d \
            --no-deps \
            --force-recreate \
            wazuh.dashboard

        sleep 15

    else

        echo
        echo "[DIAGNOSIS]"
        echo "API is reachable but configured API authentication fails."
        echo "No password changes have been made."
    fi
fi

# ------------------------------------------------
# 11. Final tests
# ------------------------------------------------

echo
echo "================================================"
echo " FINAL CHECK"
echo "================================================"

echo
echo "Manager API:"
FINAL_API="$(api_http_code)"
echo "HTTP=${FINAL_API:-000}"

echo
echo "Containers:"
docker ps \
    --format 'table {{.Names}}\t{{.Status}}' \
    | grep -E \
      'single-node-wazuh.(manager|dashboard|indexer)-1' \
    || true

echo
echo "Manager API process:"
docker exec "$MANAGER" sh -c '
ps aux |
grep -Ei "[w]azuh-apid|api/scripts|wazuh.*api" |
head -5 ||
true
'

echo
echo "Recent Dashboard API errors:"
docker logs "$DASHBOARD" \
    --since 10m 2>&1 \
    | grep -Ei \
      'wazuh.manager|55000|ECONN|connect|authentication|401|403|api.*error' \
    | tail -50 \
    || true

echo
echo "Recent Manager API errors:"
docker exec "$MANAGER" sh -c '
if [ -f /var/ossec/logs/api.log ]; then
    tail -n 80 /var/ossec/logs/api.log
fi
' || true

echo
echo "================================================"
echo " RECOVERY FINISHED"
echo "================================================"
