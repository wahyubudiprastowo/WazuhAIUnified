# SOC Analysis and Delivery

The dashboard runs a scheduled, read-only analysis worker. Settings are editable
in **Settings > SOC Automation**, **AI Analyst**, and **Report Delivery**.
**SOC Workbench > SOC Analysis Report** shows the last report, evidence links,
CYFIRMA matches and delivery status. L1 and L2 link to this report.
**Settings > AI & Email Connection** contains connection diagnostics only.

## Coverage

- Queries the last 24 hours of `wazuh-alerts-*`, including decoded syslog alerts.
- Overview aggregates 30 observable values per field. Incremental discovery now
  separately enumerates indexed events and persists deduplicated public source/
  destination IPs, supported hashes, domains and URLs for subsequent enrichment.
- Checks loaded candidates against exact IOC values in CYFIRMA tailored/global
  feeds, paginated up to 1,000 records per scope. Reports loaded/reported counts.
- Enriches public IPs, domains, file hashes and full URLs within the configured
  lookup budget. URL paths alone and URLs containing query credentials are skipped.
- Reuses existing INFOKOM integrations; per-provider failures remain visible.
- Attaches event IDs, rule explanations, reporting devices, source/destination IPs,
  users/actions and L1/L2 recommendations. A reporting collector is not necessarily
  the target. External reputation alone does not confirm infection.
- Relates CVEs to Wazuh package inventory. Reports the first 25 critical inventory
  records sorted by publication date; CVE score, NVD, KEV and PoC checks use a
  separate per-cycle budget.
- Raw archives and unindexed syslog are not covered. On this deployment Filebeat
  archive indexing is disabled. Enabling it requires storage/retention sizing.

Library default: one cycle/hour; this deployment uses five minutes, two new
multi-provider IOC lookups and two CVE refreshes per cycle. Adjust budgets to
actual API entitlements. Cached enrichment lasts six
hours; failed IOC lookups are retried after one hour. IOC candidates rotate so
recently checked indicators do not consume every cycle.

CYFIRMA upstream cache remains controlled by `CYFIRMA_CACHE_TTL` in INFOKOM.
Wazuh manager currently has vulnerability detection enabled with a `60m` feed
update interval. Endpoint Syscollector inventory must also stay current. A
scheduled poll does not guarantee the upstream publisher has published a new CVE.

## AI

Set the reachable model API base URL (including `/v1` where required), model and
API key. Enable AI Analyst, save, and use **Test AI Analyst** against the latest
report. Enable **Auto Analyze** to include model analysis in scheduled reports.
For containers, `localhost` is the dashboard container, not the Docker host.
Set `AI_PROVIDER_BASE_URL` in `dashboard.env` to your reachable
OpenAI-compatible endpoint (keep any secret in `AI_API_KEY`, never inside the
URL). Model routing is gateway-specific: some gateways (for example OmniRoute)
only route to a real upstream model on `stream: true` + `text/event-stream`
requests and return an empty stub otherwise, so verify with **Test AI Analyst**
before enabling automation. Model discovery alone does not prove inference
works. The response timeout and token budget are configurable (defaults 180
seconds and 4,096 tokens; set `AI_MAX_TOKENS` accordingly). **Only
`stream: true` + `text/event-stream` requests route to a real upstream model**;
non-streaming requests may return an empty `copilot-m365-*` stub. Tests persist
their result in the latest report, including timeouts and invalid output. The AI
receives bounded structured context (~6,200 chars), never raw logs.

The model receives bounded structured evidence using `/chat/completions`. The
system prompt requests a senior SOC investigation brief with evidence references,
uncertainties and prioritized recommendations. Output is validated JSON and shown
as advisory. An incomplete JSON object (no `summary`) now degrades gracefully
to a narrative instead of crashing the job. No model-directed tool execution or
containment is implemented.
The separate existing HLD alert worker is unchanged.

### Per-finding concurrency

Per-finding analyses run on a pool of `AI_FINDING_WORKERS` threads (default `2`,
1..16), independent of the single report-analysis worker guarded by `ai_lock`.
`Automation.start()` spawns one `finding_ai_loop` per configured worker, each
claiming a queue row with an atomic conditional update so concurrent workers
never double-run a job while backpressure is preserved. `FINDING_SYSTEM_PROMPT` is
strict JSON-only ("OUTPUT RULES": exactly one JSON object, no fences/markdown,
no prose, omit fabricated empty placeholders) to minimize the narrative fallback
in `_extract_ai_json_object`. `/api/findings/ai-jobs` reports `workers` and
`active`. Bump `AI_FINDING_WORKERS` only if the upstream model pool tolerates
parallel copies; the report assessment path remains single-threaded and bounded.

## Reports

Recipients are configured in **Report Delivery > Email recipients**. Delivery
remains disabled until a transport is enabled and credentials are set.

- Email: SMTP host, STARTTLS port (default 587), sender, and credentials when the
  relay requires authentication. The SMTP server must permit the sender address.
- Microsoft 365: select `oauth2`, host `smtp.office365.com`, port `587`, and the
  sending mailbox as username/from. Configure Entra application credentials or
  select reuse of the existing M365 application. A mailbox password is not an
  OAuth2 token or application secret. IMAP settings are not used for delivery.
  The application needs Exchange SMTP application authorization (SMTP.SendAsApp
  with consent or supported Exchange application RBAC), service-principal
  registration and permission for the sender mailbox. SMTP AUTH must be allowed
  by tenant/mailbox policy. Do not weaken tenant security policies globally.
  **Test SMTP OAuth2 / TLS** reports TCP, TLS and authentication separately and
  does not send a message. The existing audit-feed grant does not grant mail send.
  See [Microsoft SMTP OAuth documentation](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth).
- Teams: HTTPS webhook from a Teams Workflow configured for the intended channel
  or chat. Email recipients do not automatically determine a Teams destination.
  This implementation supports webhooks that authenticate using the secret URL.
- Enable the selected channel and save settings. Send the current report using
  the corresponding button. Scheduled delivery uses a minimum interval, default
  one day, and serializes sends to prevent concurrent duplicates.
- `accepted` means SMTP/webhook accepted the request; it does not prove the user
  read the message or that a downstream Teams Workflow completed successfully.

Reports, the IOC queue and checkpoints persist in the `soc-automation` Docker
volume. History retention defaults to 180 days and is independent of Wazuh log
retention. Provider and AI credentials are not part of report payloads.
Use Event History for absolute start/end times (UTC or WIB), events and archived
analysis reports. See RETENTION.md for coverage and storage boundaries.

## Verification

```sh
python3 -m unittest test_provider_status.py test_findings.py test_soc_analysis.py test_soc_automation.py
```

The dashboard exposes POST endpoints under `/api/automation/`: `status`, `run`,
`ai-test`, `smtp-test`, and `send` (`channel: email|teams`). A run returns immediately while
analysis continues in the worker. Status preserves partial provider results.
