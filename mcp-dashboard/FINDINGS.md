# SOC Findings Workspace

Open the dashboard at `http://<dashboard-host>:8088` (default port 8088). Findings is the default view; Command, the SOC lanes, Tool Console and Settings remain available.

## Analyst workflow

1. Filter by category, evidence type and severity, or search an IP, CVE, user, rule or hash.
2. Select a record. Overview shows the reason, context, classification and suggested analyst actions.
3. Local evidence searches the selected time window and shows up to 25 latest Wazuh records with an exact total for the checked fields.
4. Threat intelligence automatically queries applicable providers for the selected indicator. Individual failures are shown, and results are cached for ten minutes.
5. CVE context shows the risk score, CVSS, EPSS, CISA KEV, NVD description and references, and public PoC metadata. Clicking a referenced CVE opens its context.

## Data meaning

- Command threat ranking uses the overview's returned alert sample. Findings and L1 use the index aggregation once loaded, ordered by Wazuh rule level then event count. Source IP rule associations are not event counts; missing risk scores are shown as unavailable, not zero.
- M365 evidence is filtered by operation. Users, client IPs and objects are available in individual event records.
- Asset inventory indicates a reported vulnerable package, not proof of exploitation.
- CrowdSec watchlists and CYFIRMA feed records are external intelligence. Local evidence must be checked separately. IP geolocation describes the address/network, not the attacker's identity.
- CYFIRMA starts with 20 tailored and 20 global records. Load more retrieves subsequent pages. Totals can change as the provider refreshes its feed.
- Automatic local matching supports source IPs, listed hash fields and `data.dns.question.name` for domain pivots from indexed logs. No match in checked fields is not an environment-wide clearance.
- Provider connection tests are displayed as integration health, not local security findings. Unconfigured, unavailable and unsupported results are not safe verdicts.
- Recommendations are guidance. The Findings view executes no blocking, account changes or response actions.

## Implementation and checks

## Command And Vulnerabilities (2026-09-10)

- Command now uses index-wide severity and timestamp aggregations, not the 1,000-event overview sample, for its primary charts and priority queue. Downloaded Chart.js 4.4.8 is served locally; its license is in `static/vendor/CHARTJS-LICENSE.md`. Raw bucket values remain available below the charts. First and last time buckets can be partial.
- Vulnerabilities queries `wazuh-states-vulnerabilities-*` directly through a fixed index allowlist. It shows CVE, package/version, host, detection time and source evidence. This is current inventory, independent of the alert time selector. One CVE can affect multiple packages/assets; inventory record totals are not unique CVE totals.
- Severity and CVE/host/package search use structured queries, with 25 results per page and a 10,000-record browsing cap. Narrow the search for larger inventories. Unique CVE and asset counts use index cardinality aggregations.
- NVD/EPSS/KEV/PoC enrichment is read-only and cached. Tool priority scores are distinct from CVSS severity; a LOW priority score must not be interpreted as remediation or absence of risk.
- The language selector persists in this browser. Navigation, common interface labels, and the new Command/Vulnerabilities views support Indonesian and English. Original vendor descriptions, logs, field identifiers and tool output are retained as source evidence. Some older analytical prose is not yet fully localized.
- `check_enterprise_ui.py` validates CVE-to-host navigation, language switching, nonblank chart pixels, and responsive layouts using live data. This is functional verification, not an enterprise load or security certification.

Workbench, L1 and L2 share an indicator analysis panel. `/api/analysis/coverage` aggregates the selected window in `wazuh-alerts-*`, including exact total hits, up to 200 rules and 30 most frequent values per supported indicator field. It does not read raw archives or every arbitrary log field. Field occurrence counts can overlap; the union event count is displayed separately. Rule count error bounds and omitted rule event counts are returned by the API. Partial index results are not presented as complete coverage.

The first eligible indicator is enriched automatically; additional requests are bounded to batches of three to respect provider quotas. The four-provider comparison distinguishes unavailable, unsupported, no data, no matches and malicious context. The selected indicator and results are shared across views; they are not an assertion that all logs have been enriched. IPs that are private/reserved are not sent to external intelligence providers. GreyNoise Community supports IPv4; OTX/VirusTotal also accept supported IPv6 observables.

`soc_analysis.py` interprets known rule descriptions/groups in Indonesian, retains the original rule, and provides L1/L2 verification steps. Unknown rules use an explicit fallback rather than an invented explanation. CVE relationships are only asserted as rule references when the rule explicitly names the CVE. Neither provider associations nor a signature prove local exploitation. Findings, local evidence and supported Tool Console results reuse this context. `static/analysis.css` aligns Findings with the dark SOC shell.

`server.py` provides `/api/findings/intel` (read-only tool allowlist, request cache) and `/api/findings/evidence` (structured index queries). `static/findings.js` and `static/findings.css` implement the workspace.

Backend checks: `python3 -m unittest test_findings.py test_soc_analysis.py` from this directory. Browser checks: run `check_analysis_ui.py` and `check_findings_ui.py` with a Python environment containing Playwright and Chromium; screenshots are written to `artifacts/`.

The INFOKOM adapter now supports VirusTotal IP reports, richer detection metadata, exact CYFIRMA IOC matching and paginated feeds. VirusTotal schema: https://docs.virustotal.com/reference/ip-info and https://docs.virustotal.com/reference/ip-object.
