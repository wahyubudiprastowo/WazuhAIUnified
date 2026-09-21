(() => {
  "use strict";
  const ledger = document.querySelector("#cyfirmaLedger");
  const status = document.querySelector("#cyfirmaLedgerStatus");
  if (!ledger || !status) return;
  let request = 0;

  const stamp = value => {
    if (!value) return "-";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
  };
  const badge = (value, tone = "neutral") => `<span class="intelBadge ${tone}">${esc(value)}</span>`;
  const metric = (label, value, note) => `<div class="intelMetric"><span>${esc(label)}</span><strong>${esc(value)}</strong><small>${esc(note)}</small></div>`;

  function render(data) {
    const summary = data.summary || {};
    const items = data.items || [];
    const linked = data.cve_items || [];
    const feeds = data.feed_status || [];
    status.textContent = `${data.storage || "stored ledger"} · 0 provider calls`;
    const feedRows = feeds.map(feed => `<tr><td>${esc(feed.scope)}</td><td>${badge(feed.status, feed.status === "loaded" ? "good" : feed.status === "error" ? "bad" : "warn")}</td><td>${fmt.format(Number(feed.loaded || 0))} / ${fmt.format(Number(feed.reported || 0))}</td><td>${esc(stamp(feed.collected_at))}</td></tr>`).join("");
    const cveRows = linked.slice(0, 10).map(item => `<article class="intelCveItem"><strong>${esc(item.name || "CYFIRMA indicator")}</strong><div class="intelBadges">${(item.cves || []).map(value => badge(value, "cve")).join("")}</div><small>${esc(stamp(item.observed_at))}</small></article>`).join("");
    const updates = items.slice(0, 12).map(item => {
      const cves = (item.cves || []).map(value => badge(value, "cve")).join("");
      const labels = (item.labels || []).slice(0, 5).map(value => badge(value)).join("");
      const phases = (item.kill_chain_phases || []).slice(0, 4).map(value => badge(value)).join("");
      const types = (item.ioc_types || []).slice(0, 4).map(value => badge(value, "neutral")).join("");
      return `<article class="intelUpdate">
        <header><div><span class="intelSource">CYFIRMA ${esc(item.scope || "feed")}</span><h3>${esc(item.name || "STIX indicator")}</h3></div><strong>${fmt.format(Number(item.confidence || 0))}<small>confidence</small></strong></header>
        <p>${esc(item.description || "No provider description supplied.")}</p>
        <div class="intelBadges">${cves}${labels}${phases}${types}</div>
        <footer><span>Type ${esc(item.indicator_type || "indicator")}</span><span>Captured ${esc(stamp(item.observed_at))}</span><span>Modified ${esc(stamp(item.modified || item.created))}</span><span>Valid until ${esc(stamp(item.valid_until))}</span><span>${fmt.format(Number(item.ioc_count || 0))} IOC values</span><span>${fmt.format(Number(item.reference_count || (item.references || []).length || 0))} references</span></footer>
      </article>`;
    }).join("");
    const cveNotice = linked.length
      ? `${linked.length} captured CYFIRMA record(s) explicitly reference CVEs. Exposure still requires matching local asset/version evidence.`
      : "No explicit CVE references are present in the captured CYFIRMA STIX indicators for this window. This is not a clean bill of health; local CVE exposure remains sourced from Wazuh inventory and cached NVD, EPSS, KEV and PoC evidence.";
    ledger.innerHTML = `<div class="intelMetrics">
        ${metric("Unique indicators", fmt.format(Number(summary.indicators || 0)), "deduplicated in selected window")}
        ${metric("Tailored", fmt.format(Number(summary.tailored || 0)), "organization-specific feed")}
        ${metric("Global", fmt.format(Number(summary.global || 0)), "global feed records")}
        ${metric("CVE linked", fmt.format(Number(summary.cve_linked || 0)), "explicit provider references")}
      </div>
      <div class="intelProvenance"><strong>Collection model</strong><span>Fetch once, daily deduplication, historical SQLite reads.</span><span>${esc(data.scope_note || "")}</span></div>
      <div class="intelLayout">
        <section><div class="intelSectionHead"><h3>Latest captured intelligence</h3><span>${esc(stamp(summary.last_observed_at))}</span></div>
          <div class="intelUpdates">${updates || `<div class="intelEmpty">No CYFIRMA feed records were captured in this selected window.</div>`}</div></section>
        <aside><div class="intelSectionHead"><h3>Feed freshness</h3><span>Stored status</span></div>
          <div class="intelTableWrap"><table><thead><tr><th>Scope</th><th>Status</th><th>Loaded</th><th>Collected</th></tr></thead><tbody>${feedRows || `<tr><td colspan="4">No feed run stored in this window.</td></tr>`}</tbody></table></div>
          <div class="intelCveNotice"><strong>CVE provenance</strong><p>${esc(cveNotice)}</p></div>
          ${cveRows ? `<div class="intelCveList"><h3>Explicit provider references</h3>${cveRows}</div>` : ""}</aside>
      </div>`;
  }

  async function load() {
    const token = ++request;
    status.textContent = "Reading stored CYFIRMA ledger...";
    ledger.setAttribute("aria-busy", "true");
    try {
      const data = await postJson("/api/intelligence/cyfirma", { ...currentWindowPayload(), limit: 30 });
      if (token !== request) return;
      render(data);
    } catch (error) {
      if (token !== request) return;
      status.textContent = "Stored intelligence unavailable";
      ledger.innerHTML = `<div class="errorPanel"><strong>CYFIRMA ledger could not be loaded</strong><p>${esc(error.message)}</p></div>`;
    } finally {
      if (token === request) ledger.removeAttribute("aria-busy");
    }
  }

  document.addEventListener("soc:view", event => { if (event.detail.view === "vuln") load(); });
  document.querySelector("#rangeSelect")?.addEventListener("change", () => { if (state.view === "vuln") load(); });
  document.querySelector("#globalStart")?.addEventListener("change", () => { if (state.view === "vuln") load(); });
  document.querySelector("#globalEnd")?.addEventListener("change", () => { if (state.view === "vuln") load(); });
  document.querySelector("#refreshBtn")?.addEventListener("click", () => { if (state.view === "vuln") load(); });
})();
