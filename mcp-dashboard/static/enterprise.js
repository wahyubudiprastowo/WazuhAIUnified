(() => {
  // The established dashboard remains the default until the optional overlay is explicitly requested.
  if (new URLSearchParams(window.location.search).get("enterprise") !== "1") return;

  const t = (id, en) => SocLocale.t(id, en);
  const n = value => new Intl.NumberFormat(SocLocale.language === "id" ? "id-ID" : "en-US").format(value ?? 0);
  const e = esc;
  const s = {coverage: null, inventory: null, selected: null, severity: "Critical", search: "", offset: 0, seq: 0, charts: [], vulnChart: null, overview: null, intel: null};
  const colors = ["#ef778b", "#efba5a", "#64b5e3", "#50c8a0"];
  const command = document.createElement("div"); command.id = "enterpriseCommand"; q("#commandView").prepend(command);
  const inventory = document.createElement("div"); inventory.id = "enterpriseInventory"; q("#vulnView").prepend(inventory);
  const oldVuln = q("#vulnView > .gridTwo"); oldVuln.hidden = true;
  for (const selector of [".heroGrid", ".insightStrip", ".kpiGrid", ".gridThree", ".timelinePanel", ".dataQualityPanel", ".aiDeckPanel"]) {
    q(`#commandView > ${selector}`)?.classList.add("legacyCommandHidden");
  }
  const metric = (label, value, hint) => `<div class="entMetric"><span>${label}</span><strong>${value}</strong><small>${hint}</small></div>`;
  const panel = (title, content, note = "") => `<section class="entPanel"><header><h2>${title}</h2><small>${note}</small></header>${content}</section>`;
  function chart(id, type, labels, datasets, options = {}) {
    const canvas = q(`#${id}`); if (!canvas || !window.Chart) return;
    const instance = new Chart(canvas, {type, data: {labels, datasets}, options: {
      responsive: true, maintainAspectRatio: false, animation: false, color: "#c2d0d5",
      plugins: {legend: {display: type === "doughnut", position: "bottom", labels: {color: "#d8e5e9", boxWidth: 12}}, tooltip: {enabled: true}},
      scales: type === "doughnut" ? {} : {x: {grid: {display: false}, ticks: {color: "#a6bcc7", maxTicksLimit: 7}}, y: {beginAtZero: true, grid: {color: "#344047"}, ticks: {color: "#a6bcc7", precision: 0}}}, ...options}});
    s.charts.push(instance);
  }
  function renderCommand() {
    s.charts.forEach(c => c.destroy()); s.charts = [];
    const c = s.coverage, o = s.overview;
    if (!c || !o) { command.innerHTML = `<p class="entNotice">${t("Memuat agregasi indeks...", "Loading index aggregates...")}</p>`; return; }
    const severity = [0, 0, 0, 0];
    for (const b of c.severity || []) severity[b.key >= 15 ? 0 : b.key >= 12 ? 1 : b.key >= 7 ? 2 : 3] += b.doc_count;
    const sources = (c.sources || []).slice(0, 6), timeline = c.timeline || [];
    const urgent = (c.rules || []).filter(r => r.level >= 7).slice(0, 6);
    const analysisText = (analysis, field) => SocLocale.analysis ? SocLocale.analysis(analysis, field) : (analysis?.[field] || "");
    command.innerHTML = `<div class="entHeading"><div><span class="entEyebrow">${t("SITUASI OPERASIONAL", "OPERATIONAL SITUATION")}</span><h2>${t("Prioritas, bukti, dan cakupan", "Priorities, evidence and coverage")}</h2><p>${t("Keparahan rule bukan konfirmasi serangan berhasil.", "Rule severity does not confirm a successful attack.")}</p></div><span class="entTimestamp">${e(c.range)} · ${e(c.generated_at.slice(0,19))} UTC</span></div>
      <div class="entMetrics">${metric(t("Alert terindeks", "Indexed alerts"), n(c.total_events), "wazuh-alerts-*")}${metric(t("Keparahan tinggi / kritis", "High / critical events"), n(severity[0] + severity[1]), t("Seluruh rentang, bukan sampel", "Full window, not a sample"))}${metric(t("Aset aktif", "Active agents"), `${n(o.agents?.counts?.active)} / ${n(o.agents?.total)}`, t("Cakupan agent Wazuh", "Wazuh agent coverage"))}${metric(t("Temuan paket kritis", "Critical package findings"), n(o.vulnerabilities?.critical), t("Inventaris saat ini, bukan alert", "Current inventory, not alerts"))}</div>
      <div class="entCharts">${panel(t("Tren alert", "Alert trend"), '<div class="entChart"><canvas id="entTrend" role="img" aria-label="Indexed alert trend"></canvas></div>', t("Jumlah event per interval", "Events per interval"))}${panel(t("Distribusi keparahan", "Severity distribution"), '<div class="entChart"><canvas id="entSeverity" role="img" aria-label="Severity distribution"></canvas></div>')}${panel(t("Sumber telemetri", "Telemetry sources"), '<div class="entChart"><canvas id="entSources" role="img" aria-label="Top decoder sources"></canvas></div>', t("Top decoder", "Top decoders"))}</div>
      <div class="entSplit">${panel(t("Prioritas investigasi", "Investigation priorities"), `<div class="entPriority">${urgent.map(r => `<button data-analysis-rule="${e(r.rule_id)}"><span class="entSeverity">L${r.level}</span><div><strong>${e(analysisText(r.analysis, "title") || r.description)}</strong><small>Rule ${e(r.rule_id)} · ${t("Buka bukti dan saran tindakan", "Open evidence and recommended actions")}</small></div><b>${n(r.count)}</b></button>`).join("") || t("Tidak ada rule tinggi pada data dimuat", "No high severity rules in loaded data")}</div>`, t("Diurutkan level, lalu volume", "Ordered by level, then volume"))}${panel(t("Konteks intelijen", "Intelligence context"), `<div class="entIntel"><h3>${t("Bukti lokal → indikator → intelijen", "Local evidence → indicator → intelligence")}</h3><p>${n(c.events_with_observable)} ${t("event memiliki field indikator yang diperiksa. Ini bukan jumlah IOC berbahaya.", "events contain checked indicator fields. This is not a malicious IOC count.")}</p><div class="entProviderNames">${["CrowdSec", "OTX", "GreyNoise", "VirusTotal", "CYFIRMA"].map(p=>`<span>${p}</span>`).join("")}</div><button data-view-link="workbench">${t("Bandingkan hasil penyedia", "Compare provider results")}</button><h3>MITRE ATT&CK</h3><div class="entMitre">${(c.mitre || []).slice(0,6).map(b=>`<span>${e(b.key)} <b>${n(b.doc_count)}</b></span>`).join("") || t("Tidak ada mapping dikembalikan", "No mappings returned")}</div><p class="entMuted">${t("Mapping berasal dari rule. Atribusi pelaku dan eksploitasi belum terkonfirmasi.", "Mappings come from rules. Actor attribution and exploitation are not confirmed.")}</p></div>`)}</div>
      <details class="entData"><summary>${t("Data grafik & batas cakupan", "Chart data & coverage limits")}</summary><p>${t("Agregasi indeks alert pada rentang terpilih. Field indikator dibatasi; arsip mentah tidak dibaca. Rule di luar daftar:", "Alert index aggregation for the selected window. Indicator fields are bounded; raw archives are not read. Events outside loaded rules:")} ${n(c.other_rule_events)}.</p><table><thead><tr><th>UTC</th><th>${t("Jumlah event", "Event count")}</th></tr></thead><tbody>${timeline.map(b=>`<tr><td>${e(b.key_as_string)}</td><td>${n(b.doc_count)}</td></tr>`).join("")}</tbody></table></details>`;
    chart("entTrend", "line", timeline.map(b => b.key_as_string?.slice(5,16).replace("T"," ")), [{label: t("Alert", "Alerts"), data: timeline.map(b=>b.doc_count), borderColor: "#53ccb2", backgroundColor: "#53ccb21a", fill: true, tension: .2, pointRadius: 2}]);
    chart("entSeverity", "doughnut", [t("Kritis", "Critical"), t("Tinggi", "High"), t("Sedang", "Medium"), t("Rendah", "Low")], [{data: severity, backgroundColor: colors, borderWidth: 0}], {cutout: "70%"});
    chart("entSources", "bar", sources.map(b=>b.key.length > 18 ? b.key.slice(0,15)+"..." : b.key), [{label: t("Event", "Events"), data: sources.map(b=>b.doc_count), backgroundColor: "#70b9e3", borderRadius: 3}], {indexAxis: "y", plugins: {legend: {display:false}, tooltip: {callbacks: {title: items=>sources[items[0].dataIndex].key}}}, scales: {x: {beginAtZero: true, grid: {color: "#344047"}, ticks: {color: "#a6bcc7", maxTicksLimit: 3, callback: value=>new Intl.NumberFormat(SocLocale.language,{notation:"compact"}).format(value)}}, y: {grid: {display:false}, ticks: {color:"#a6bcc7", font:{size:11}}}}});
    renderIntel();
  }
  function renderIntel() {
    const host = command.querySelector(".entIntel"); if (!host || !s.intel) return;
    host.querySelector(".entLiveIntel")?.remove();
    const block = document.createElement("div"); block.className="entLiveIntel";
    const rows = s.intel.result?.data?.results || [];
    block.innerHTML=`<h3>${t("Indikator lokal terakhir dianalisis", "Last analyzed local indicator")}</h3><button data-analysis-open="${e(s.intel.indicator)}">${e(s.intel.indicator)}</button><ul>${rows.filter(r=>["otx","greynoise","virustotal","cyfirma"].includes(r.provider)).map(r=>{
      const d=r.detail || {};
      const status=r.error ? (/429/.test(r.error) ? t("Batas API", "API rate limit") : t("Tidak tersedia", "Unavailable")) : d.skipped ? t("Tipe tidak didukung", "Unsupported type") : r.is_malicious ? t("Indikasi berbahaya", "Adverse intelligence") : d.analysis_stats?.suspicious > 0 ? t("Deteksi suspicious", "Suspicious detections") : d.classification === "unknown" ? t("Tidak ada data", "No data") : t("Tidak ada indikasi yang dilaporkan", "No adverse indication reported");
      return `<li><strong>${e(r.provider)}</strong><span>${e(status)}</span></li>`;
    }).join("")}</ul><small>${t("Kecocokan intelijen bukan bukti host telah disusupi.", "Intelligence matches do not prove host compromise.")}</small>`;
    host.append(block);
  }
  function renderInventory() {
    const d = s.inventory;
    if (s.vulnChart) { s.vulnChart.destroy(); s.vulnChart = null; }
    const trend = d?.published_timeline || [];
    inventory.innerHTML = `<div class="entHeading"><div><span class="entEyebrow">${t("PAPARAN ASET", "ASSET EXPOSURE")}</span><h2>${t("CVE terkait paket dan host", "CVEs linked to packages and hosts")}</h2><p>${t("Inventaris Wazuh saat ini, tidak dibatasi pemilih 24h/7d/30d. Temuan tidak membuktikan eksploitasi.", "Current Wazuh inventory, independent of the 24h/7d/30d selector. A finding does not prove exploitation.")}</p></div></div>
      <div class="entProvenance"><span>Wazuh agent</span><b>→</b><span>Package / version</span><b>→</b><span>wazuh-states-vulnerabilities-*</span><b>→</b><span>CVE · NVD · EPSS · KEV · PoC</span></div>
      ${d ? `<div class="entMetrics">${metric(t("Temuan paket-aset", "Package-asset findings"),n(d.inventory_total),t("Bukan jumlah CVE unik", "Not a unique CVE count"))}${metric(t("CVE unik (perkiraan)", "Unique CVEs (approx.)"),n(d.unique_cves),t("Kardinalitas indeks", "Index cardinality"))}${metric(t("Aset terdampak", "Affected assets"),n(d.assets),t("Inventaris saat ini", "Current inventory"))}${metric(t("Terakhir diperiksa", "Last checked"), e(d.generated_at.slice(11,19)),"UTC")}</div>` : ""}
      ${d ? panel(t("Tren CVE inventaris · 90 hari", "Inventory CVE trend · 90 days"), `<div class="entChart entCveChart"><canvas id="entCveTrend" role="img" aria-label="${t("Tren CVE berdasarkan tanggal publikasi", "CVE trend by publication date")}"></canvas></div><details class="entData"><summary>${t("Tabel data tren", "Trend data table")}</summary><table><thead><tr><th>${t("Tanggal", "Date")}</th><th>CVE</th><th>Critical / High</th></tr></thead><tbody>${trend.filter(row=>row.doc_count).map(row=>`<tr><td>${e(row.key_as_string?.slice(0,10))}</td><td>${n(row.cves?.value)}</td><td>${n((row.severity?.buckets || []).filter(x=>["Critical","High"].includes(x.key)).reduce((sum,x)=>sum+x.doc_count,0))}</td></tr>`).join("") || `<tr><td colspan="3">${t("Belum ada tanggal publikasi pada inventaris", "No publication dates in inventory")}</td></tr>`}</tbody></table></details>`, t("Tanggal publikasi sumber; bukan tanggal eksploitasi lokal", "Source publication date; not local exploitation date")) : ""}
      <form id="entVulnFilters" class="entFilters"><label>${t("Cari CVE, host, atau paket", "Search CVE, host or package")}<input id="entVulnSearch" value="${e(s.search)}" maxlength="150"></label><label>${t("Keparahan", "Severity")}<select id="entVulnSeverity">${["all","Critical","High","Medium","Low"].map(v=>`<option value="${v}" ${v === s.severity ? "selected" : ""}>${v === "all" ? t("Semua", "All") : v}</option>`).join("")}</select></label><button>${t("Terapkan", "Apply")}</button></form>
      <div class="entInventorySplit"><section class="entPanel"><header><h2>${t("Daftar paparan", "Exposure inventory")}</h2><small>${d ? `${n(d.total)} ${t("hasil", "results")}` : t("Memuat...", "Loading...")}</small></header><div class="entTableWrap"><table class="entVulnTable"><thead><tr><th>CVE</th><th>${t("Host / paket", "Host / package")}</th><th>${t("Versi", "Version")}</th><th>${t("Keparahan", "Severity")}</th></tr></thead><tbody>${(d?.items || []).map((r,i)=>`<tr class="${r.record_id === s.selected?.record_id ? "selected" : ""}"><td><button data-vuln-record="${i}">${e(r.vulnerability?.id)}</button></td><td><strong>${e(r.agent?.name || r.agent?.id)}</strong><small>${e(r.package?.name)}</small></td><td>${e(r.package?.version || "-")}</td><td><span class="entSeverity">${e(r.vulnerability?.severity)}</span></td></tr>`).join("") || `<tr><td colspan="4">${t("Tidak ada hasil dimuat", "No records loaded")}</td></tr>`}</tbody></table></div><footer><button data-vuln-page="-1" ${s.offset === 0 ? "disabled" : ""}>${t("Sebelumnya", "Previous")}</button><span>${s.offset + 1}–${Math.min(s.offset+25,d?.total || 0)}</span><button data-vuln-page="1" ${!d || s.offset+25>=d.total || s.offset >= 9900 ? "disabled" : ""}>${t("Berikutnya", "Next")}</button></footer></section><section class="entPanel" id="entVulnDetail"></section></div>`;
    renderVulnDetail();
    if (d && trend.length && window.Chart) {
      const elevated = trend.map(row => (row.severity?.buckets || []).filter(x => ["Critical", "High"].includes(x.key)).reduce((sum,x) => sum + x.doc_count, 0));
      s.vulnChart = new Chart(q("#entCveTrend"), {type:"line", data:{labels:trend.map(row=>row.key_as_string?.slice(5,10)),datasets:[
        {label:t("CVE unik dipublikasi", "Unique CVEs published"),data:trend.map(row=>row.cves?.value || 0),borderColor:"#4da3ef",backgroundColor:"#4da3ef1f",fill:true,tension:.2,pointRadius:1},
        {label:t("Paparan paket Critical / High", "Critical / High package exposures"),data:elevated,borderColor:"#ef6678",borderDash:[6,4],backgroundColor:"transparent",tension:.2,pointRadius:1}
      ]},options:{responsive:true,maintainAspectRatio:false,animation:false,color:"#c2d0d5",plugins:{legend:{display:true,position:"bottom",labels:{color:"#d8e5e9",boxWidth:14}},tooltip:{enabled:true}},scales:{x:{grid:{display:false},ticks:{color:"#a6bcc7",maxTicksLimit:8}},y:{beginAtZero:true,grid:{color:"#344047"},ticks:{color:"#a6bcc7",precision:0}}}}});
    }
  }
  function renderVulnDetail() {
    const r = s.selected, target = q("#entVulnDetail"); if (!target) return;
    if (!r) { target.innerHTML = `<p class="entNotice">${t("Pilih temuan untuk melihat bukti aset", "Select a finding for asset evidence")}</p>`; return; }
    const v = r.vulnerability || {}, p = r.package || {};
    target.innerHTML = `<header><h2>${e(v.id)}</h2><span class="entSeverity">${e(v.severity)}</span></header><div class="entDetail"><dl>${[[t("Aset", "Asset"),`${r.agent?.name || "-"} (${r.agent?.id || "-"})`],[t("Paket", "Package"),p.name],[t("Versi terpasang", "Installed version"),p.version],[t("Terdeteksi", "Detected"),v.detected_at],[t("Status sumber", "Source status"),v.status]].map(([k,val])=>`<dt>${k}</dt><dd>${e(val || t("Tidak dikembalikan", "Not returned"))}</dd>`).join("")}</dl><h3>${t("Deskripsi sumber (asli)", "Source description (original)")}</h3><p>${e(v.description || "-")}</p><h3>${t("Prioritas dan tindakan", "Priority and action")}</h3><ol><li>${t("Validasi versi paket dan komponen yang benar-benar terpasang pada host.", "Validate the installed package version and affected component on the host.")}</li><li>${t("Bandingkan advisory vendor, KEV dan EPSS; keberadaan PoC tidak membuktikan host dieksploitasi.", "Compare vendor advisories, KEV and EPSS; a public PoC does not prove host exploitation.")}</li><li>${t("Uji patch atau mitigasi dengan pemilik aset, lalu lakukan pemindaian ulang.", "Test patches or mitigations with the asset owner, then rescan.")}</li></ol><div class="entDetailActions"><button id="entFindingAi">${t("Run AI Analysis", "Run AI Analysis")}</button><button id="entCveEnrich">${t("Muat NVD / EPSS / KEV / PoC", "Load NVD / EPSS / KEV / PoC")}</button></div><div id="entCveIntel"></div><details><summary>${t("Bukti inventaris asli", "Original inventory evidence")}</summary><pre>${e(JSON.stringify(r,null,2))}</pre></details></div>`;
  }
  async function loadInventory() {
    const seq = ++s.seq;
    try {
      inventory.setAttribute("aria-busy", "true");
      const d = await postJson("/api/vulnerabilities/inventory", {severity:s.severity, search:s.search, offset:s.offset});
      if (seq !== s.seq) return;
      if (!d.ok) throw new Error(t("Hasil indeks parsial", "Partial index result"));
      s.inventory=d; s.selected=d.items[0] || null; renderInventory();
    } catch (error) { if (seq === s.seq) inventory.innerHTML = `<p class="entNotice">${e(error.message)}</p><button id="entInventoryRetry">${t("Coba lagi", "Retry")}</button>`; }
    finally { if (seq === s.seq) inventory.removeAttribute("aria-busy"); }
  }
  document.addEventListener("submit", ev => {
    if (ev.target.id !== "entVulnFilters") return; ev.preventDefault();
    s.search=q("#entVulnSearch").value; s.severity=q("#entVulnSeverity").value; s.offset=0; loadInventory();
  });
  document.addEventListener("click", async ev => {
    const row=ev.target.closest("[data-vuln-record]"), page=ev.target.closest("[data-vuln-page]");
    if (row) { s.selected=s.inventory.items[Number(row.dataset.vulnRecord)]; renderInventory(); }
    if (page) { s.offset+=Number(page.dataset.vulnPage)*25; loadInventory(); }
    if (ev.target.closest("#entInventoryRetry")) loadInventory();
    if (ev.target.closest("#entFindingAi") && s.selected) {
      const cve=s.selected.vulnerability?.id;
      if (cve && SocFindings.open("cve",cve,s.selected)) setTimeout(()=>q(`[data-finding-ai="inventory:${CSS.escape(cve)}:${CSS.escape(String(s.selected.agent?.id || ""))}"]`)?.click(),0);
      return;
    }
    if (!ev.target.closest("#entCveEnrich")) return;
    const selected=s.selected, output=q("#entCveIntel"), button=q("#entCveEnrich"); button.disabled=true;
    output.innerHTML=`<p>${t("Memuat bukti penyedia...", "Loading provider evidence...")}</p>`;
    const results=[];
    for (const [kind,name] of [["nvd","NVD"],["cve","CVSS / EPSS"],["kev","CISA KEV"],["poc","Public PoC"]]) {
      try { const result=await postJson("/api/findings/intel",{kind,indicator:selected.vulnerability.id}); results.push(SocFindings.renderProvider(name,result.data,result.ok ? "" : result.error || result.text)); }
      catch(error) { results.push(`<p>${e(name)}: ${e(error.message)}</p>`); }
      if (s.selected !== selected || !output.isConnected) return;
      output.innerHTML=`<p class="entNotice">${t("Skor prioritas tool tidak menggantikan keparahan CVSS, paparan layanan dan konteks aset. Hasil LOW bukan berarti CVE kritis sudah aman.", "Tool priority scores do not replace CVSS severity, service exposure and asset context. A LOW score does not make a critical CVE safe.")}</p>`+results.join("");
    }
    button.disabled=false;
  });
  document.addEventListener("soc:coverage", ev => {s.coverage=ev.detail; renderCommand();});
  document.addEventListener("soc:overview", ev => {s.overview=ev.detail; s.coverage=null; s.intel=null; renderCommand(); loadInventory();});
  document.addEventListener("soc:indicator", ev => {s.intel=ev.detail; renderIntel();});
  document.addEventListener("soc:language", () => {renderCommand(); renderInventory();});
  renderCommand(); renderInventory();
})();
