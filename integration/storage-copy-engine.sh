#!/usr/bin/env bash
set -euo pipefail
test "$(id -u)" = 0
base=/data/wazuh-storage
test "$(findmnt -n -o UUID --target "$base")" = 1c166263-3587-48e4-8098-9f9b9456003b
mkdir -p "$base/containerd" "$base/migration-backups/docker.bak-20260907-080607"
ionice -c 2 -n 7 nice -n 10 rsync -aHAXx --numeric-ids --info=stats2 /var/lib/containerd/ "$base/containerd/"
ionice -c 2 -n 7 nice -n 10 rsync -aHAXx --numeric-ids --info=stats2 /var/lib/docker.bak-20260907-080607/ "$base/migration-backups/docker.bak-20260907-080607/"
