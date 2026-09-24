(() => {
  const panel = document.querySelector('#automationReport');
  const status = document.querySelector('#automationStatus');
  const connectionStatus = document.querySelector('#automationConnectionStatus');
  const diagnostics = document.querySelector('#automationDiagnostics');
  function showStatus(message) { status.textContent = message; connectionStatus.textContent = message; }
  const tr = (id, en) => window.SocLocale?.t(id, en) || en;
  const listLabels = value => {
    const rows = Array.isArray(value) ? value : value == null ? [] : [value];
    return [...new Set(rows.flatMap(item => {
      if (Array.isArray(item)) return listLabels(item);
      if (item && typeof item === 'object') {
        const direct = item.label || item.name || item.id || item.value;
        return direct ? [String(direct)] : Object.values(item).flatMap(listLabels);
      }
      return item == null || item === '' ? [] : [String(item)];
    }))];
  };
  let latest;
  let actionBusy = false;
  let signature = '';
  let reportTab = 'summary';
  for (const view of ['l1']) {
    const host = document.querySelector(`#${view}View`);
    if (!host || host.querySelector(`[data-automation-digest="${view}"]`)) continue;
    const section = document.createElement('section');
    section.className = 'automationDigest glassPanel';
    section.dataset.automationDigest = view;
    host.prepend(section);
  }
  const label = value => ({suspected: tr('Indikasi perlu diselidiki', 'Suspected; investigate'),
    needs_review: tr('Perlu ditinjau', 'Needs review'), completed: tr('Selesai', 'Completed'),
    queued:tr('Menunggu AI','Waiting for AI'), processing:tr('AI sedang memproses','AI processing'),
    disabled: tr('Nonaktif', 'Disabled'), error: tr('Gagal', 'Error'), context: tr('Konteks tersedia', 'Context available'),
    matched: tr('Indikator cocok', 'Indicator matched'), accepted: tr('Diterima layanan pengiriman', 'Accepted by delivery service'),
    not_configured: tr('Belum dikonfigurasi', 'Not configured'), cooldown: tr('Menunggu jadwal pengiriman', 'Delivery cooldown')})[value] || value;
  function detail(item) {
    const events = item.evidence || [];
    return `<details class="automationFinding"><summary><strong>${esc(item.indicator)}</strong> <span>${esc(label(item.status))}</span> <small>${fmt.format(item.event_total || 0)} ${tr('event terkait', 'related events')}</small></summary>
      ${events.map(event => {
        const analysis = event.analysis || {};
        const localized = key => window.SocLocale?.analysis(analysis, key) || analysis[key] || '';
        return `<article><h3>${esc(localized('title') || event.rule?.description)}</h3>
          <p>${esc(localized('meaning'))}</p>
          <dl><dt>${tr('IP sumber / tujuan', 'Source / destination IP')}</dt><dd>${esc(event.source_ip || '-')} / ${esc(event.destination_ip || '-')}</dd>
          <dt>${tr('Perangkat pelapor', 'Reporting device')}</dt><dd>${esc(event.device || '-')}</dd>
          <dt>${tr('Pengguna / tindakan', 'User / action')}</dt><dd>${esc(event.user || '-')} / ${esc(event.action || '-')}</dd>
          <dt>${tr('Bukti', 'Evidence')}</dt><dd>${esc(event.event_id)} | Rule ${esc(event.rule?.id)} | ${esc(event.timestamp)}</dd></dl>
          <p><b>L1:</b> ${esc(localized('l1'))}</p><p><b>L2:</b> ${esc(localized('l2'))}</p>
          <button type="button" data-automation-rule="${esc(event.rule?.id)}">${tr('Buka bukti Wazuh', 'Open Wazuh evidence')}</button></article>`;
      }).join('')}
      <table><thead><tr><th>Provider</th><th>Status</th><th>${tr('Konteks', 'Context')}</th></tr></thead><tbody>
      ${(item.providers || []).map(p => `<tr><td>${esc(p.provider)}</td><td>${esc(label(p.status))}</td><td>${esc(p.error || listLabels(p.tags).join(', ') || tr('Tidak ada bukti tambahan', 'No additional evidence'))}</td></tr>`).join('')}</tbody></table>
      <details><summary>${tr('Rincian intelijen tiap provider', 'Provider intelligence details')}</summary>${(item.providers || []).map(p => window.SocFindings?.renderProvider(p.provider, p, p.error) || '').join('')}</details>
      <p>CYFIRMA: ${(item.cyfirma_matches || []).length} ${tr('kecocokan persis', 'exact matches')}</p>
      ${(item.cyfirma_matches || []).map(m => `<p><b>${esc(m.name)}</b> ${esc(m.description)} | ${esc(listLabels(m.labels).join(', '))}</p>`).join('')}
      ${item.error ? `<p role="alert">${esc(item.error)}</p>` : ''}
    </details>`;
  }
  function cveScore(v) {
    const score = v.intelligence?.cve?.data;
    const c = score?.components;
    if (!c) return tr('Skor belum tersedia', 'Score not available');
    return `CVSS ${esc(c.cvss_score ?? '-')} · EPSS ${c.epss_probability == null ? '-' : (Number(c.epss_probability)*100).toFixed(2)+'%'} · KEV ${c.in_kev == null ? '-' : c.in_kev ? tr('terdaftar','listed') : tr('tidak terdaftar','not listed')} · PoC ${esc(c.poc_confidence || '-')} · ${esc(score.urgency || '')}`;
  }
  function deck(report) {
    const d = report?.intelligence_deck;
    if (d) return d;
    const c = report?.coverage || {};
    return {
      generated_at: report?.generated_at,
      coverage_cards: [
        {label:'Eligible IOCs', value:c.eligible_candidates, detail:'Public observables available for enrichment'},
        {label:'Enriched IOCs', value:c.analyzed_candidates, detail:'Indicators with evidence or provider context'},
        {label:'Deferred IOCs', value:c.deferred_candidates, detail:'Queued indicators intentionally delayed by API budget/backoff'},
        {label:'Critical CVEs', value:c.critical_inventory_records, detail:'Wazuh vulnerability inventory records'},
      ],
      provider_coverage: Object.entries(c.cyfirma_feeds || {}).map(([scope, feed]) => ({provider:`CYFIRMA ${scope}`, status:feed.status, matched:feed.loaded, context:feed.reported, errors:feed.error ? 1 : 0, tags:[]})),
      top_findings: (report?.findings || []).slice(0, 6).map(item => ({
        indicator:item.indicator, kind:item.kind, status:item.status, risk_score:item.status === 'suspected' ? 70 : 35,
        confidence:item.cyfirma_matches?.length ? 'high' : 'medium', event_total:item.event_total,
        source_ips:[...new Set((item.evidence || []).map(e => e.source_ip).filter(Boolean))],
        devices:[...new Set((item.evidence || []).map(e => e.device).filter(Boolean))],
        related_cves:[...new Set((item.providers || []).flatMap(p => p.cves || []))],
        cyfirma_labels:listLabels((item.cyfirma_matches || []).flatMap(m => listLabels(m.labels))),
        providers:item.providers || [], evidence:item.evidence || [],
        recommended_action:{l1:'Validate Wazuh evidence and event direction.', l2:'Correlate with endpoint, auth, cloud, firewall and vulnerability context.', l3:'Hunt historical spread before containment.'}
      })),
      vulnerability_focus: (report?.vulnerabilities || []).slice(0, 8).map(v => ({cve:v.cve, asset:v.agent, package:v.package, version:v.version, severity:v.severity, score:(v.intelligence?.cve?.data?.components || {}), priority:v.severity === 'Critical' ? 70 : 40, recommendation:v.recommendation_en || v.recommendation})),
      next_actions: [
        {lane:'L1', title:'Validate evidence first', detail:'Confirm source, destination, reporting device and action result.'},
        {lane:'L2', title:'Correlate before containment', detail:'Join provider reputation with local Wazuh evidence.'},
        {lane:'L3', title:'Hunt historical spread', detail:'Search older windows for the same IOC/CVE/user/host.'},
      ],
    };
  }
  function scoreTone(score) {
    const value = Number(score || 0);
    if (value >= 75) return 'critical';
    if (value >= 50) return 'high';
    if (value >= 25) return 'medium';
    return 'low';
  }
  function severityTone(value) {
    const text = String(value || '').toLowerCase();
    if (text.includes('critical') || text.includes('malicious')) return 'critical';
    if (text.includes('high') || text.includes('suspicious')) return 'high';
    if (text.includes('medium') || text.includes('review')) return 'medium';
    return 'low';
  }
  function aiList(rows, empty) {
    return Array.isArray(rows) && rows.length
      ? `<ul>${rows.map(row => `<li>${esc(String(row))}</li>`).join('')}</ul>`
      : `<p>${esc(empty)}</p>`;
  }
  function renderCommandDeck(report) {
    const target = document.querySelector('#commandAiDeck');
    const statusEl = document.querySelector('#aiDeckStatus');
    if (!target) return;
    if (!report) {
      target.innerHTML = `<div class="emptyState">${tr('Jalankan analisis untuk membuat AI Intelligence Deck.', 'Run analysis to build the AI Intelligence Deck.')}</div>`;
      return;
    }
    const d = deck(report);
    const coverageCards = (d.coverage_cards || []).filter(card => !/^(indexed alerts?|indexed events?|queue depth)$/i.test(String(card.label || '').trim()));
    if (statusEl) statusEl.textContent = `${tr('Last run', 'Last run')}: ${report.generated_at || '-'}`;
    const ai = report.ai || {};
    const top = d.top_findings?.[0];
    target.innerHTML = `
      <article class="aiDeckHero ${scoreTone(top?.risk_score)}">
        <span>AI Analyst</span>
        <strong>${esc(ai.result?.verdict?.severity || label(ai.status || 'not_configured'))}</strong>
        <p>${esc(ai.result?.summary || tr('Evidence-based synthesis is available after AI completes.', 'Evidence-based synthesis is available after AI completes.'))}</p>
        ${ai.result?.verdict ? `<small>${esc(ai.result.verdict.status || 'needs_review')} · ${esc(ai.result.verdict.confidence || 'low')} confidence</small>` : ''}
        <button type="button" data-open-automation>${tr('Buka laporan lengkap', 'Open full report')}</button>
      </article>
      ${coverageCards.map(card => `
        <article class="aiMetricCard">
          <span>${esc(card.label)}</span>
          <strong>${fmt.format(Number(card.value || 0))}</strong>
          <small>${esc(card.detail)}</small>
        </article>
      `).join('')}
      ${(d.top_findings || []).slice(0, 2).map(item => `
        <button class="aiFindingCard ${scoreTone(item.risk_score)}" type="button" data-automation-ioc="${esc(item.indicator)}">
          <span>${esc(item.kind || 'IOC')} · ${esc(item.confidence || 'unknown')}</span>
          <strong>${esc(item.indicator)}</strong>
          <small>${fmt.format(Number(item.event_total || 0))} ${tr('event terkait', 'related events')} · ${(item.providers || []).filter(p => p.status === 'matched').length} provider matches</small>
        </button>
      `).join('')}
    `;
  }
  function renderVulnBrief(report) {
    const target = document.querySelector('#vulnAiBrief');
    if (!target) return;
    const rows = deck(report).vulnerability_focus || [];
    target.innerHTML = rows.length ? rows.slice(0, 6).map(row => `
      <button class="vulnBriefCard ${scoreTone(row.priority)}" type="button" data-automation-cve="${esc(row.cve)}">
        <span>${esc(row.severity || 'unknown')} · priority ${fmt.format(Number(row.priority || 0))}</span>
        <strong>${esc(row.cve || '-')}</strong>
        <small>${esc(row.asset || '-')} · ${esc(row.package || '-')} ${esc(row.version || '')}</small>
        <p>CVSS ${esc(row.score?.cvss || row.score?.cvss_score || '-')} · EPSS ${row.score?.epss_probability == null ? '-' : (Number(row.score.epss_probability) * 100).toFixed(2) + '%'} · KEV ${row.score?.kev == null ? '-' : row.score.kev ? 'listed' : 'not listed'}</p>
      </button>
    `).join('') : `<div class="emptyState">${tr('No CVE priority rows yet.', 'No CVE priority rows yet.')}</div>`;
  }
  function renderLaneDigests(report) {
    const d = deck(report);
    for (const digest of document.querySelectorAll('[data-automation-digest]')) {
      const lane = digest.dataset.automationDigest === 'l1' ? 'L1' : 'L2';
      const actions = (d.next_actions || []).filter(action => action.lane === lane || (lane === 'L2' && action.lane === 'Response')).slice(0, 3);
      const findings = (d.top_findings || []).slice(0, 3);
      digest.innerHTML = `<div class="panelHead"><h2>${lane} ${tr('AI action brief', 'AI action brief')}</h2><span>${esc(report?.generated_at || '-')}</span></div>
        <div class="automationReport laneBrief">
          <div class="laneBriefGrid">
            ${actions.map(action => `<article><span>${esc(action.lane)}</span><strong>${esc(action.title)}</strong><small>${esc(action.detail)}</small></article>`).join('')}
          </div>
          <div class="laneFindingStrip">${findings.map(f => `<button type="button" data-automation-ioc="${esc(f.indicator)}">${esc(f.indicator)} · ${esc(f.confidence)} · ${fmt.format(Number(f.event_total || 0))} events</button>`).join('')}</div>
          <button type="button" data-open-automation>${tr('Buka laporan dan rekomendasi', 'Open report and recommendations')}</button>
        </div>`;
    }
  }
  function renderDeckSurfaces(report) {
    window.SocAutomation = { latest, report, deck: report ? deck(report) : null };
    renderCommandDeck(report);
    renderVulnBrief(report);
    if (report) renderLaneDigests(report);
    document.dispatchEvent(new CustomEvent('soc:automation', {detail: window.SocAutomation}));
  }
  function reportTabs() {
    return [
      ['summary', tr('Ringkasan', 'Executive')],
      ['findings', tr('Temuan', 'Findings')],
      ['rules', tr('Rule', 'Rules')],
      ['cves', 'CVE'],
      ['ai', 'AI'],
      ['delivery', tr('Pengiriman', 'Delivery')],
    ];
  }
  function tabButton([id, name]) {
    return `<button type="button" class="${reportTab === id ? 'active' : ''}" data-report-tab="${id}" aria-pressed="${reportTab === id ? 'true' : 'false'}">${esc(name)}</button>`;
  }
  function renderReportSummary(report, c, d) {
    const ai = report.ai || {};
    return `<section class="reportSummaryGrid">
      <article class="reportBriefCard primary">
        <span>AI Analyst</span>
        <strong>${esc(label(ai.status || 'not_configured'))}</strong>
        <p>${esc(ai.result?.summary || tr('AI will summarize attack meaning, confidence, affected evidence, and action priority after analysis completes.', 'AI will summarize attack meaning, confidence, affected evidence, and action priority after analysis completes.'))}</p>
      </article>
      ${(d.top_findings || []).slice(0, 4).map(item => `<button class="reportBriefCard ${scoreTone(item.risk_score)}" type="button" data-automation-ioc="${esc(item.indicator)}">
        <span>${esc(item.kind || 'IOC')} · ${esc(item.confidence || 'unknown')}</span>
        <strong>${esc(item.indicator)}</strong>
        <small>${fmt.format(Number(item.event_total || 0))} ${tr('event terkait', 'related events')} · ${(item.providers || []).filter(p => p.status === 'matched').length} provider matches</small>
        <p>${esc(item.recommended_action?.l2 || tr('Correlate local evidence with provider reputation before response.', 'Correlate local evidence with provider reputation before response.'))}</p>
      </button>`).join('') || `<article class="reportBriefCard"><strong>${tr('Tidak ada IOC prioritas', 'No priority IOC')}</strong><p>${tr('Belum ada indikator eksternal yang cocok di siklus ini.', 'No external indicator matched in this cycle.')}</p></article>`}
      <article class="reportBriefCard">
        <span>CYFIRMA</span>
        <strong>${fmt.format(Number(c.cyfirma_candidates_checked || 0))} ${tr('kandidat', 'candidates')}</strong>
        <p>${Object.entries(c.cyfirma_feeds || {}).map(([scope, feed]) => `${esc(scope)} ${esc(feed.status)} ${fmt.format(Number(feed.loaded || 0))}/${fmt.format(Number(feed.reported || 0))}`).join(' | ') || '-'}</p>
      </article>
    </section>
    <section class="reportActionGrid">
      ${(d.next_actions || []).slice(0, 6).map(action => `<article><span>${esc(action.lane || 'SOC')}</span><strong>${esc(action.title)}</strong><p>${esc(action.detail)}</p></article>`).join('')}
    </section>
    <p class="reportHint">${tr('IP bereputasi buruk belum membuktikan perangkat terinfeksi. Perangkat pelapor dapat berupa pengumpul syslog.', 'A malicious source IP does not prove device infection. The reporting device may be a syslog collector.')}</p>`;
  }
  function renderReportFindings(report) {
    return `<div class="reportSectionHead"><div><strong>${tr('Temuan dan tindakan analis', 'Findings and analyst actions')}</strong><small>${fmt.format(report.findings?.length || 0)} ${tr('indikator', 'indicators')}</small></div></div>
      <div class="reportFindingList">${(report.findings || []).map(detail).join('') || `<p>${tr('Belum ada IOC yang diperkaya.', 'No enriched IOCs yet.')}</p>`}</div>`;
  }
  function renderReportRules(report) {
    return `<div class="reportSectionHead"><div><strong>${tr('Penjelasan rule prioritas', 'Priority rule explanations')}</strong><small>${fmt.format(report.rules?.length || 0)} rules</small></div></div>
      <div class="reportRuleGrid">${(report.rules || []).map(rule => `<article>
        <span>Rule ${esc(rule.rule_id)} · ${fmt.format(rule.count || 0)} ${tr('event', 'events')}</span>
        <strong>${esc(window.SocLocale?.analysis(rule.analysis, 'title') || rule.description)}</strong>
        <p>${esc(window.SocLocale?.analysis(rule.analysis, 'meaning'))}</p>
        <small>L1: ${esc(window.SocLocale?.analysis(rule.analysis, 'l1'))}</small>
        <small>L2: ${esc(window.SocLocale?.analysis(rule.analysis, 'l2'))}</small>
        <button type="button" data-automation-rule="${esc(rule.rule_id)}">${tr('Buka bukti Wazuh', 'Open Wazuh evidence')}</button>
      </article>`).join('') || `<p>${tr('Belum ada rule prioritas.', 'No priority rules yet.')}</p>`}</div>`;
  }
  function renderReportCves(report) {
    return `<div class="reportSectionHead"><div><strong>${tr('CVE pada inventaris perangkat', 'CVEs in device inventory')}</strong><small>${fmt.format(report.vulnerabilities?.length || 0)} records</small></div></div>
      <div class="automationTable"><table><thead><tr><th>CVE</th><th>${tr('Aset', 'Asset')}</th><th>${tr('Paket / versi', 'Package / version')}</th><th>${tr('Prioritas dan tindakan', 'Priority and action')}</th></tr></thead><tbody>
      ${(report.vulnerabilities || []).map(v => `<tr><td><button type="button" data-automation-cve="${esc(v.cve)}">${esc(v.cve)}</button><br>${esc(v.severity)}</td><td>${esc(v.agent)}</td><td>${esc(v.package)}<br>${esc(v.version)}</td><td><b>${cveScore(v)}</b><br>${esc(window.SocLocale?.language === 'en' ? v.recommendation_en : v.recommendation)}<br>${v.intelligence ? Object.entries(v.intelligence).map(([provider, result]) => `${esc(provider)}: ${result.ok ? 'OK' : esc(result.error || 'error')}`).join(' | ') : tr('Enrichment menunggu anggaran siklus', 'Enrichment pending cycle budget')}</td></tr>`).join('') || `<tr><td colspan="4">${tr('Tidak ada CVE inventaris pada laporan ini.', 'No inventory CVEs in this report.')}</td></tr>`}</tbody></table></div>`;
  }
  function renderReportAi(report) {
    const ai = report.ai || {};
    const result = ai.result || {};
    const verdict = result.verdict || {};
    const recommendations = Array.isArray(result.recommendations) ? result.recommendations : [];
    const actionPlan = result.action_plan || {};
    const lanes = ['l1', 'l2', 'l3', 'response'];
    const citationGroups = ['attack_narrative', 'attack_categories', 'network_paths', 'identities', 'data_impact', 'cve_priorities'];
    const claimRows = citationGroups.flatMap(key => result[key] || []);
    const verifiedClaims = claimRows.filter(row => row.citation_status === 'verified_reference').length;
    const unverifiedClaims = claimRows.length - verifiedClaims;
    return `<section class="reportAiPanel analystV2">
      <article class="aiVerdictCard ${severityTone(verdict.severity || verdict.status)}">
        <span>Verdict</span>
        <strong>${esc(verdict.severity || label(ai.status || 'not_configured'))}</strong>
        <p>${esc(ai.error || verdict.reason || result.summary || tr('No AI assessment yet.', 'No AI assessment yet.'))}</p>
        <small>${esc(verdict.status || 'needs_review')} · ${esc(verdict.confidence || 'low')} confidence · ${esc(ai.schema || 'legacy')}</small>
      </article>
      <article>
        <span>${tr('Penilaian', 'Assessment')}</span>
        ${result.daily_brief ? `<p><b>${tr('Daily brief', 'Daily brief')}:</b> ${esc(result.daily_brief)}</p>` : ''}
        <p>${esc(result.assessment || tr('Run analysis after AI settings are saved and reachable.', 'Run analysis after AI settings are saved and reachable.'))}</p>
      </article>
      <article>
        <span>${tr('Validasi evidence AI', 'AI evidence validation')}</span>
        <p>${verifiedClaims} ${tr('klaim dengan ID event/rule yang tervalidasi', 'claims with validated event/rule IDs')}</p>
        <small>${unverifiedClaims} ${tr('klaim belum terverifikasi; jangan perlakukan sebagai observasi', 'claims unverified; do not treat as observations')}</small>
      </article>
      <article>
        <span>${tr('Eskalasi', 'Escalation')}</span>
        <p><b>${esc(result.escalation?.level || 'l1')}</b> · ${esc(result.escalation?.sla || 'same shift')}</p>
        <small>${esc(result.escalation?.reason || tr('Analyst validation required.', 'Analyst validation required.'))}</small>
      </article>
      <article>
        <span>${tr('Rekomendasi', 'Recommendations')}</span>
        ${aiList(recommendations, tr('No AI recommendations returned yet.', 'No AI recommendations returned yet.'))}
      </article>
      <article>
        <span>${tr('Baseline anomali', 'Anomaly baseline')}</span>
        ${(result.anomaly_baseline || []).map(row => `<p><b>${esc(row.signal || '-')}</b><br><small>${esc(row.current || '-')} vs ${esc(row.baseline || '-')} · ${esc(row.interpretation || '-')}</small></p>`).join('') || `<p>${tr('No anomaly baseline returned yet.', 'No anomaly baseline returned yet.')}</p>`}
      </article>
      <article>
        <span>${tr('Alur serangan', 'Attack narrative')}</span>
        ${(result.attack_narrative || []).map(row => `<p><b>${esc(row.stage || 'Stage')}</b>: ${esc(row.detail || '-')}<br><small>${esc(row.citation_status === 'verified_reference' ? (row.evidence || []).join(', ') : tr('Unverified: no matching event/rule citation', 'Unverified: no matching event/rule citation'))}</small></p>`).join('') || `<p>${tr('No attack narrative returned yet.', 'No attack narrative returned yet.')}</p>`}
      </article>
      <article>
        <span>${tr('Aset terdampak', 'Affected assets')}</span>
        ${(result.affected_assets || []).map(row => `<p><b>${esc(row.asset || '-')}</b> · ${esc(row.role || 'unknown')}<br><small>${esc(row.evidence || '-')}</small></p>`).join('') || `<p>${tr('No affected asset assertion returned.', 'No affected asset assertion returned.')}</p>`}
      </article>
      <article>
        <span>${tr('Provider intelligence', 'Provider intelligence')}</span>
        ${(result.provider_findings || []).map(row => `<p><b>${esc(row.provider || '-')}</b> · ${esc(row.verdict || 'unknown')}<br><small>${esc(row.signal || '-')}</small></p>`).join('') || `<p>${tr('No provider synthesis returned.', 'No provider synthesis returned.')}</p>`}
      </article>
      <article>
        <span>CVE</span>
        ${(result.cve_priorities || []).map(row => `<p><b>${esc(row.cve || '-')}</b> · ${esc(row.priority || 'verify_only')}<br><small>${esc(row.asset || '-')} · ${esc(row.reason || '-')}</small></p>`).join('') || `<p>${tr('No CVE priority returned.', 'No CVE priority returned.')}</p>`}
      </article>
      <article class="aiActionPlan">
        <span>${tr('Rencana tindakan', 'Action plan')}</span>
        <div class="aiActionGrid">${lanes.map(lane => `<div><strong>${esc(lane.toUpperCase())}</strong>${aiList(actionPlan[lane], tr('No steps returned.', 'No steps returned.'))}</div>`).join('')}</div>
      </article>
      <article>
        <span>${tr('Gap bukti', 'Evidence gaps')}</span>
        ${aiList(result.gaps, tr('No gaps returned.', 'No gaps returned.'))}
      </article>
      <article>
        <span>${tr('Faktor confidence', 'Confidence drivers')}</span>
        ${aiList(result.confidence_drivers, tr('No confidence drivers returned.', 'No confidence drivers returned.'))}
      </article>
    </section>`;
  }
  function renderReportDelivery(data) {
    const deliveries = data.deliveries || [];
    return `<div class="reportDeliveryGrid">${deliveries.map(d => `<article>
      <span>${esc(d.channel)}</span>
      <strong>${esc(label(d.result?.status))}</strong>
      <p>${esc(d.result?.error || d.result?.detail || '-')}</p>
    </article>`).join('') || `<article><strong>${tr('Belum ada pengiriman', 'No deliveries yet')}</strong><p>${tr('Konfigurasi SMTP atau Teams diperlukan.', 'SMTP or Teams configuration is required.')}</p></article>`}</div>
    <details class="reportLimitations"><summary>${tr('Cakupan dan keterbatasan', 'Coverage and limitations')}</summary><ul>${(latest?.latest?.limitations || []).map(value => `<li>${esc(value)}</li>`).join('')}</ul></details>`;
  }
  function renderReportTab(data, report, c, d) {
    if (reportTab === 'findings') return renderReportFindings(report);
    if (reportTab === 'rules') return renderReportRules(report);
    if (reportTab === 'cves') return renderReportCves(report);
    if (reportTab === 'ai') return renderReportAi(report);
    if (reportTab === 'delivery') return renderReportDelivery(data);
    return renderReportSummary(report, c, d);
  }
  function render(data) {
    latest = data;
    const report = data.latest;
    const labels = {'runAutomation':['Jalankan analisis','Run analysis'], 'testAnalyst':['Tes AI Analyst','Test AI Analyst'],
      'sendReportEmail':['Kirim laporan email','Send email report'], 'sendReportTeams':['Kirim laporan Teams','Send Teams report'],
      'testSmtp':['Tes SMTP / TLS','Test SMTP / TLS']};
    for (const [id, pair] of Object.entries(labels)) document.getElementById(id).textContent = tr(...pair);
    const phases = {coverage:tr('Menghitung cakupan Wazuh', 'Querying Wazuh coverage'), cyfirma:tr('Membaca feed CYFIRMA', 'Loading CYFIRMA feeds'), indicators:tr('Memperkaya indikator', 'Enriching indicators'), vulnerabilities:tr('Memeriksa konteks CVE', 'Checking CVE context'), ai:tr('Menunggu jawaban model AI', 'Waiting for AI model response')};
    status.textContent = data.running ? phases[data.phase] || tr('Analisis berjalan...', 'Analysis running...') : data.error || (report ? tr('Terakhir: ', 'Last run: ') + report.generated_at : tr('Belum ada laporan', 'No report yet'));
    if (!actionBusy) connectionStatus.textContent = `AI: ${label(report?.ai?.status || 'not_configured')}`;
    document.querySelector('#runAutomation').disabled = data.running || actionBusy;
    if (!report) {
      panel.textContent = tr('Laporan akan tersedia setelah analisis pertama selesai.', 'The report will appear after the first analysis completes.');
      renderDeckSurfaces(null);
      return;
    }
    const c = report.coverage;
    renderDeckSurfaces(report);
    const d = deck(report);
    panel.innerHTML = `<div class="automationMetrics">
      <div><span>${tr('Temuan di laporan', 'Findings in report')}</span><strong>${fmt.format((report.findings || []).length)}</strong></div>
      <div><span>${tr('Kandidat IOC dimuat', 'IOC candidates loaded')}</span><strong>${fmt.format(c.loaded_candidates)}</strong></div>
      <div><span>${tr('IOC diperkaya / layak', 'Enriched / eligible IOCs')}</span><strong>${c.analyzed_candidates} / ${c.eligible_candidates}</strong></div>
      <div><span>AI Analyst</span><strong>${esc(label(report.ai?.status))}</strong></div></div>
      ${report.ai?.error ? `<p role="alert" class="reportHint"><strong>AI Analyst:</strong> ${esc(report.ai.error)}</p>` : ''}
      <div class="reportTabs" role="tablist">${reportTabs().map(tabButton).join('')}</div>
      <div class="reportTabBody">${renderReportTab(data, report, c, d)}</div>`;
  }
  async function refresh() {
    try {
      const data = await postJson('/api/automation/status', {known_revision:latest?.revision});
      if(data.unchanged) data.latest=latest?.latest;
      const next = JSON.stringify([data.running, data.phase, data.error, data.latest?.id, data.latest?.ai, data.deliveries]);
      latest = data;
      if (next !== signature) { signature = next; render(data); }
    }
    catch (error) { showStatus(error.message); }
  }
  async function action(button, endpoint, payload = {}) {
    actionBusy = true; button.disabled = true;
    showStatus(tr('Memproses...', 'Processing...'));
    try {
      const result = await postJson(endpoint, payload);
      if (result.started) await refresh();
      else showStatus(result.reason || result.error || label(result.status));
      if (endpoint.endsWith('smtp-test')) {
        diagnostics.innerHTML = `<dl class="settingsList">${[['SMTP',`${result.host || '-'}:${result.port || '-'}`], ['Email enabled',result.email_enabled],['Recipients',result.recipient_count],['Sender configured',result.sender_configured],['TCP',result.tcp],['TLS',result.tls],['Auth method',result.auth_method],['Authenticated',result.authenticated],['SMTP.SendAsApp',result.smtp_send_as_app],['Token roles',(result.token_roles || []).join(', ')],['Error',result.error],['Next step',result.next_step]].filter(([_,v]) => v != null).map(([k,v]) => `<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`).join('')}</dl>`;
      } else if (endpoint.endsWith('ai-ping')) {
        diagnostics.innerHTML = `<dl class="settingsList"><dt>AI</dt><dd>${esc(label(result.status))}</dd><dt>Model</dt><dd>${esc(result.model || '-')}</dd><dt>Finish</dt><dd>${esc(result.finish_reason || '-')}</dd><dt>Answer</dt><dd>${esc(result.answer || result.error || '-')}</dd></dl>`;
      } else if (endpoint.endsWith('ai-test')) {
        diagnostics.innerHTML = `<p>${esc(result.error || label(result.status))}</p>${result.result ? `<p>${esc(result.result.summary)}</p><button type="button" data-open-automation>${tr('Buka analisis lengkap', 'Open full analysis')}</button>` : ''}`;
        await refresh();
      } else if (endpoint.endsWith('/send')) {
        await refresh();
      }
    } catch (error) { showStatus(error.message); }
    finally { actionBusy = false; button.disabled = false; }
  }
  document.querySelector('#runAutomation').onclick = e => action(e.currentTarget, '/api/automation/run', window.SocWindow?.payload?.() || {range: '24h'});
  document.querySelector('#testAnalyst').onclick = e => action(e.currentTarget, '/api/automation/ai-ping');
  document.querySelector('#testSmtp').onclick = e => action(e.currentTarget, '/api/automation/smtp-test');
  document.querySelector('#sendReportEmail').onclick = e => action(e.currentTarget, '/api/automation/send', {channel:'email'});
  document.querySelector('#sendReportTeams').onclick = e => action(e.currentTarget, '/api/automation/send', {channel:'teams'});
  panel.addEventListener('click', async e => {
    const tab = e.target.closest('[data-report-tab]');
    if (tab) {
      reportTab = tab.dataset.reportTab || 'summary';
      render(latest);
      return;
    }
    const rule = e.target.closest('[data-automation-rule]');
    const cve = e.target.closest('[data-automation-cve]');
    if (rule) window.SocFindings?.open('rule', rule.dataset.automationRule);
    if (cve) {
      cve.disabled = true;
      try {
        const result = await postJson('/api/vulnerabilities/inventory', {search: cve.dataset.automationCve});
        if (!result.items?.length) status.textContent = tr('CVE sudah tidak ditemukan di inventaris terbaru.', 'CVE is no longer in the current inventory.');
        else window.SocFindings?.open('cve', cve.dataset.automationCve, result.items[0]);
      } catch (error) { status.textContent = error.message; }
      finally { cve.disabled = false; }
    }
  });
  document.addEventListener('soc:language', () => { if (latest) render(latest); });
  document.addEventListener('click', event => {
    if (event.target.closest('[data-open-automation]')) { setView('workbench'); document.querySelector('#automationPanel').scrollIntoView(); }
    const ioc = event.target.closest('[data-automation-ioc]');
    if (ioc) {
      const item = latest?.latest?.findings.find(f => f.indicator === ioc.dataset.automationIoc);
      window.SocFindings?.open(item?.kind === 'ip' ? 'ip' : 'indicator', ioc.dataset.automationIoc);
    }
    const cvePivot = event.target.closest('[data-automation-cve]');
    if (cvePivot && !event.target.closest('#automationReport')) {
      window.SocFindings?.open('cve', cvePivot.dataset.automationCve);
    }
  });
  setInterval(() => { if (!actionBusy && (latest?.running || ['settings','workbench'].includes(state.view))) refresh(); }, 10000);
  refresh();
})();
