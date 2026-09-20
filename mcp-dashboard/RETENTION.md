# Storage and retention deployment notes

The existing Wazuh manager already rotates/compresses daily alert/archive files.
Do not install a second logrotate rule over active alerts.json or archives.json.
Docker stdout logs are a separate layer: the dashboard now uses 20 MB x 5 files.
Other existing containers still require their own compose logging settings and a
planned recreation. Do not restart the Wazuh manager/indexer just for this change.

Storage audit corrected on 2026-09-11: `/` is a 484 GiB filesystem, while
`/data/wazuh-storage` is a separate 4.9 TiB filesystem. `df /data` alone reports
root, not that submount. Docker named volumes already use the larger filesystem;
syslog bind mounts and containerd require separate migration. See
`../integration/storage/README.md` for the migration procedure and actual paths.
Per-device syslog was approximately 267 GiB, manager archives 36 GiB and manager
alerts approximately 22 GiB at this audit. These are not indexer storage sizes.
Measure daily growth and backup requirements before selecting 90/180-day retention.

Migration completed on 2026-09-13. Large syslog/runtime bind mounts and
containerd now live on `/data/wazuh-storage`; root usage dropped to 14 GiB used
(3%). Keep checking actual data paths with `findmnt --target <path>` because the
stable application paths under `/opt/wazuh-mcp-unified` are bind mounts.

Log deletion is NOT enabled by this deployment. Confirm 90 or 180 days, backups
and legal/incident holds first. Apply an ISM policy only to wazuh-alerts-* daily
indices. Never apply it to vulnerability state, security, or other system indices.
Review existing policies before attaching/replacing any policy. Index age is not
necessarily event age for restored/backfilled indices.

Reference: https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/index-lifecycle-management.html

Recommended sequence:
1. Inventory indices, creation dates, bytes, current policies, snapshots and holds.
2. Verify a restore, outside the production index namespace.
3. Review the exact list of indices and compressed files beyond retention.
4. Attach a reviewed 90/180-day policy to future daily alert indices; explicitly
   approve changes to existing indices after the dry run.
5. Separately expire only closed/compressed manager archive files and associated
   checksums older than the chosen period, excluding holds. Never truncate active
   files or remove volume directories.

Dashboard analysis history uses SOC_REPORT_RETENTION_DAYS (default 180), rather
than 100 snapshots. It does not control Wazuh log retention. Old reports already
removed by the former 100-report cap cannot be recovered without a backup.
Each 15-minute report also has a materialized `report_summaries` row containing
bounded attack categories, top source/destination, users, assets, rules, CVEs,
provider consensus and AI verdict. Date/range selection defaults to these local
rows and does not rerun AI or call an external threat-intelligence provider.
Legacy retained reports are backfilled into this table when their date range is
first opened. Raw event drill-down remains an explicit OpenSearch query because
copying every Wazuh event into SQLite would duplicate the index and increase I/O.

The stream collector reads wazuh-alerts-* only and keeps a persistent checkpoint.
Initial scope is the preceding 24 hours. Each 5-minute window is read completely
using a scroll, with 5-minute overlap and a 2-minute ingest delay. Failed windows
restart without advancing the checkpoint; IOC upserts deduplicate replay. Events
arriving later than the overlap and history older than initialization require
separate backfill. Raw non-alert archives are not automatically indexed or read.
While catching up, a separate recent-window pass runs approximately every minute,
covering the latest ten minutes with a two-minute ingestion delay. Its progress
is shown separately as live_through and does not advance the historical checkpoint.

IOC discovery, enrichment, AI inference and delivery execute independently. The
queue stores indicators, not copies of every log. Provider failures remain visible
and retries are bounded. Enrichment still obeys SOC_IOC_BUDGET; increasing volume
does not increase subscription quotas. History event browsing is bounded to 186
days per query and 10,000 paged hits; narrow the range to inspect a larger result.
This deployment uses a five-minute enrichment interval and two new IOC lookups
per cycle, not unlimited real-time provider queries. CVE cache remains six hours.
