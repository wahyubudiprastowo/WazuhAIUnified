# MCP Dashboard Change Log

Chronological record of optimizations, audits and fixes to the Wazuh MCP SOC
dashboard. Concise; each entry states what changed, why, and the measured result.
See AUTOMATION.md, FINDINGS.md and RETENTION.md for coverage and boundaries.

## 2026-09-16 — Multi-worker finding AI queue + stricter JSON prompt

Addresses the single-worker AI bottleneck flagged in the previous audit and
tightens the finding prompt to reduce narrative-fallback JSON failures.

- **Parallel per-finding analysis.** The finding AI path no longer serializes
  behind the single report `ai_lock`. Added a dynamic `_ConcurrencyGate` whose
  limit is re-read from `AI_FINDING_WORKERS` on every acquire, so the admin can
  change concurrency at runtime in Settings without a restart.
  `Automation.start()` now spawns `AI_FINDING_WORKERS` (default 2, clamp 1..16)
  `finding_ai_loop` threads; each claims a queue row via an atomic conditional
  `UPDATE ... WHERE status='queued'`, so concurrent workers never double-run a
  job and backpressure is preserved.
- Report analysis (`ai_loop`/`test_ai`) still guards with `ai_lock`; finding
  analyses run independently, so a long report assessment no longer blocks queued
  findings (and vice versa).
- **New setting** `AI_FINDING_WORKERS` ("Per-finding AI concurrency", integer,
  default 2, limits 1..16) added to `FIELDS`/`SCHEMA`/`LIMITS` and set to `2` in
  `dashboard.env`. `/api/findings/ai-jobs` now reports `workers` and `active`.
- **Stricter finding prompt.** `FINDING_SYSTEM_PROMPT` now enforces "OUTPUT
  RULES": exactly one valid JSON object, no code fences, no markdown, no prose
  before/after, omit fabricated empty placeholders. Optional keys are dropped when
  there is no evidence instead of emitting empty arrays/objects. This reduces the
  `_extract_ai_json_object` narrative fallback path for `auto/pro-coding`.
- Tests: `test_soc_automation.py` grew 3 cases covering the runtime-respected
  gate limit, exposed worker metrics, and finding-AI independence from the report
  `ai_lock`. Dashboard suite 64 → 67 tests OK.

## 2026-09-16 — AI Analyst completion, cross-platform status, audit

### Fixes / optimizations (AI Analyst)

- Raised the AI response token cap from 1,200 to 4,096 in
  `_request_ai_assessment()` and `analyze_finding_with_model()` in
  `soc_automation.py` (lines ~1137, ~1314). The reasoning model consumes preamble
  tokens before producing JSON; at 4,096 tokens a full valid analysis object
  (~4,400 chars) is now produced consistently instead of a truncated fragment.
- Set `AI_MAX_TOKENS=4096` in `dashboard.env`.
- Added a crash-resilient fallback in `analyze_finding_with_model()`: when
  `_extract_ai_json_object` returns an incomplete object (no `summary`), the
  pipeline now degrades gracefully to a narrative instead of raising
  `ValueError` and burning a job.
- Required `--build` on `docker compose -f docker-compose.dashboard.yml up -d`
  because the Dockerfile copies `soc_automation.py` at build time; the volume
  only mounts `dashboard.env` and `runtime/`.

### Verified live

- `/api/automation/ai-ping` returns real model `big-pickle` via OmniRoute.
- `/api/findings/ai-jobs` showed several completed analyses (avg ~69.2s) plus a
  queue backlog cleared after the token-cap fix.
- New test finding completed in ~90.2s with `fallback_used: false` — full valid
  JSON without narrative fallback.
- All platforms connected: GenSecAI (58 tools), INFOKOM (136 tools), AI Analyst,
  Wazuh Indexer (81M records served via `size:0` + aggregations).

### Note on OmniRoute

Only `stream: true` + `text/event-stream` requests route to the real upstream
models behind the configured `AI_PROVIDER_BASE_URL`. Non-streaming requests fall
back to empty `copilot-m365-*` stubs. This is why streaming mode is mandatory
for all analyst calls.

### New: Cross-platform status widget

- Added POST `/api/platform/status` in `server.py` (`_platform_overview_status`)
  returning a live, aggregated snapshot: `gensecai`, `infokom`, and `ai_analyst`
  (model, job counts, average duration, recent jobs) plus the total tool count.
  Tool discovery is cached (30s) via `_tool_catalog`.
- Added a **Connected Platforms** panel in the Command view
  (`static/index.html`): `#platformStatusGrid` + `#platformStatusMeta`, with one
  card per platform, operational dot, tool/model counts and up to three recent AI
  jobs.
- Added `static/styles.css` rules (`.platformCard`, `.platformDot.ok/.err`,
  `.platformStat`, `.platformJob`, responsive auto-fit grid).
- `static/app.js`: `loadPlatformStatus()` (20s timeout) + `renderPlatformStatus()`,
  invoked non-blocking inside `loadDashboard()` after `renderOverview`. It never
  blocks the primary overview.
- Verified live: `curl -X POST /api/platform/status` → `total_tools=194`
  (58 + 136), all three platforms `ok: true`. HTML/JS/CSS all served correctly.

### Audit result

The architecture already handles the 81M-record index without a full fetch:
`size:0` + `aggs` queries, `INDEXER_SLOTS=10`, overview/comparison caching, and
async materialization. The AI receives bounded structured context (~6,200
chars), never raw logs. No full-index scan occurs in the request path.

### Known limitation / next step

- `/api/automation/ai-test` returns `busy` while the single worker is processing.
  The single-worker AI queue is the current bottleneck at 3M events/day scale;
  a multi-worker queue is the recommended next optimization.
- `RAPIDAPI_KEY` is still empty in `gensecai-core/.env`; RapidAPI-backed tools
  are not fully live until it is populated.

## 2026-09-16 — Periodic platform-status auto-refresh (audit follow-up)

The **Connected Platforms** widget previously loaded once on dashboard load and
stalled until a manual refresh / view switch. It now stays live.

- Added `platformRefreshLoop()` (60s chained timer, `PLATFORM_REFRESH_MS`) and
  `ensurePlatformRefresh()` in `static/app.js`. The loop only fires
  `loadPlatformStatus()` while `state.view === "command"`; otherwise it silently
  reschedules, avoiding background calls on other views.
- The loop uses a chained `setTimeout` (not `setInterval`), so a slow/20s-timeout
  request can never overlap the next tick.
- `loadPlatformStatus()` now guards a `state.platformLoading` flag: it only
  overwrites the "Loading…" placeholder on the first load, so periodic refreshes
  do not flicker the widget.
- `ensurePlatformRefresh()` is invoked at startup and on every `setView`
  transition into `command`.
- Verified live: `platformRefreshLoop`, `ensurePlatformRefresh`,
  `PLATFORM_REFRESH_MS` all present in the served `static/app.js`; the platform
  endpoint still returns all three platforms `ok` (`total_tools=194`).

### Test alignment (audit) — `test_soc_automation.py`

`test_ai_disabled_never_contacts_model_and_validates_output` patched the old
module-level `post` (`patch.object(soc, 'post')`), but after the OmniRoute
streaming refactor `analyze_with_model()` routes through `post_chat`, so the mock
never intercepted the call and the test attempted a real network request. Updated
the patch target to `soc.post_chat`. Full dashboard suite now green:
`python3 -m unittest test_provider_status.py test_findings.py test_soc_analysis.py
test_soc_automation.py` → 64 tests OK.