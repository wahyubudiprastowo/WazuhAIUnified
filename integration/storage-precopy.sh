#!/usr/bin/env bash
set -euo pipefail
test "$(id -u)" = 0
base=/data/wazuh-storage
test "$(findmnt -n -o UUID --target "$base")" = 1c166263-3587-48e4-8098-9f9b9456003b
mkdir -p "$base/app-data" "$base/migration-backups"
paths=(syslog-ingest infokom-analysis/runtime hld-platform/runtime hld-platform/soar-audit hld-platform/pam-audit)
for path in "${paths[@]}"; do
  source="/opt/wazuh-mcp-unified/$path"
  test -d "$source"
  if mountpoint -q "$source"; then
    printf 'Source already mounted: %s; inspect before repeating migration.\n' "$source" >&2
    exit 1
  fi
  mkdir -p "$base/app-data/$path"
  printf 'Copying %s\n' "$path"
  # Initial live copy; a stopped-service final sync is mandatory before switching.
  rsync -aHAX --numeric-ids --info=stats2 "$source/" "$base/app-data/$path/"
done
mkdir -p "$base/containerd"
rsync -aHAXx --numeric-ids --info=stats2 /var/lib/containerd/ "$base/containerd/"
mkdir -p "$base/migration-backups/docker.bak-20260907-080607"
rsync -aHAXx --numeric-ids --info=stats2 /var/lib/docker.bak-20260907-080607/ "$base/migration-backups/docker.bak-20260907-080607/"
