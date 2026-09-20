# Wazuh storage migration (host __WAZUH_HOST__)

This is a host-specific runbook, not a generic installation script. Scripts
require root and verify the filesystem UUID before copying or changing services.
Do not run cutover a second time without inspecting its saved state.

## Audit before migration, 2026-09-11

- `/`: `/dev/sda3`, 484 GiB capacity, 382 GiB used (84%).
- `/data/wazuh-storage`: `/dev/sdb1`, 4.9 TiB capacity, 87 GiB used.
- Docker named volumes already live under `/data/wazuh-storage/docker`.
- `syslog-ingest`: approximately 303 GiB on root, including 267 GiB per-device
  JSONL and 36 GiB manager archives. Daily per-device files are already separated.
- `/var/lib/docker.bak-20260907-080607`: 56 GiB inactive migration backup.
- `/var/lib/containerd`: 12 GiB active image/snapshot data, separate from Docker's
  data-root. Runtime directories add approximately 1 GiB.

`df /data` measures the parent root filesystem, NOT the mounted storage below it.
Always check `df /data/wazuh-storage` or `findmnt --target <actual-data-path>`.

## Layout

| Data | Physical location |
| --- | --- |
| Wazuh indexer, manager logs/queue, SOC SQLite history | `/data/wazuh-storage/docker/volumes/` |
| Container images and writable snapshots | `/data/wazuh-storage/containerd/` |
| Syslog archives, per-device logs, splitter cursor | `/data/wazuh-storage/app-data/syslog-ingest/` |
| INFOKOM stores/cache/reports | `/data/wazuh-storage/app-data/infokom-analysis/runtime/` |
| HLD worker database, audit events | `/data/wazuh-storage/app-data/hld-platform/` |
| Previous Docker migration backup | `/data/wazuh-storage/migration-backups/docker.bak-20260907-080607/` |

Bind mounts keep the original `/opt/wazuh-mcp-unified/...` application paths.
Seeing those paths in Compose does not mean bytes still occupy the root disk.
Source code and small configuration files remain on root intentionally.

## Procedure

1. Run `bash integration/storage-precopy.sh`. Services remain online. Exit must
   be zero; live databases in this preliminary copy are NOT yet a valid backup.
   If all five application copies completed but the engine copy was interrupted,
   resume that stage with `bash integration/storage-copy-engine.sh`. The stopped
   final sync still validates every source before switching any application path.
2. Announce the maintenance window. Run `python3 integration/storage-cutover.py`.
   This stops the manager, drains/stops the splitter, stops other containers and
   Docker/containerd, then completes a final sync. It verifies sizes, timestamps,
   ownership and attributes before changing mounts. Rsync checks transferred file
   data internally; the metadata dry-run is not an independent full disk hash.
3. Original directories remain as `*.pre-sdb-migration` until service verification.
   Old containerd remains at `/var/lib/containerd` until verification. No raw log
   or index retention policy is applied by these scripts.
4. Verify all original containers, indexer search, manager processes, fresh logs,
   dashboard access, splitter cursor, and SOC checkpoint persistence. Check each
   mounted path with `findmnt`; test `systemctl show ... -p RequiresMountsFor`.
5. Only after validation, remove verified old source copies to reclaim root space.
   Preserve the inactive Docker backup on the data disk; do not prune volumes.

Systemd drop-ins require the data and application mounts. The host can still boot
if the data disk is absent (`nofail`), but dependent Wazuh/Docker services must not
fall back to writing into unmounted directories on root.

## Recovery

Before successful startup, originals and `/etc/fstab` backup are available under
the paths above and `migration-backups/cutover-20260911/`. If cutover fails, inspect
the last completed step before proceeding. Do not blindly rerun the script.

To revert after new writes have started, first stop all writers and preserve/sync
the newer data back to the old location (check root capacity). Then unmount the
application bind mounts, restore the original directories and fstab, remove only
the migration's service drop-ins/containerd config, daemon-reload and restart the
saved container list. Reverting to stale originals would lose new events.

Reference: https://docs.docker.com/engine/daemon/#daemon-data-directory

## Completion, 2026-09-13

Cutover and cleanup completed successfully.

- `/` after cleanup: `/dev/sda3`, 484 GiB capacity, 14 GiB used (3%).
- `/data/wazuh-storage` after cleanup: `/dev/sdb1`, 4.9 TiB capacity, 462 GiB used (10%).
- The application paths below are bind mounts backed by UUID
  `1c166263-3587-48e4-8098-9f9b9456003b`:
  - `/opt/wazuh-mcp-unified/syslog-ingest`
  - `/opt/wazuh-mcp-unified/infokom-analysis/runtime`
  - `/opt/wazuh-mcp-unified/hld-platform/runtime`
  - `/opt/wazuh-mcp-unified/hld-platform/soar-audit`
  - `/opt/wazuh-mcp-unified/hld-platform/pam-audit`
- Docker remains rooted at `/data/wazuh-storage/docker`.
- Containerd is configured to use `/data/wazuh-storage/containerd`.
- Verified running containers: dashboard, INFOKOM MCP, HLD alert worker, Wazuh
  manager, GenSecAI MCP, Wazuh dashboard and Wazuh indexer.
- Verified service guards: Docker, containerd and the syslog splitter all require
  `/data/wazuh-storage` before startup, preventing fallback writes to root if the
  data disk is missing.
- Verified runtime health: SOC dashboard returned HTTP 200, Wazuh dashboard
  returned HTTPS 302, indexer cluster was green with 103 active shards, and the
  SOC pipeline checkpoint continued after restart.
