(() => {
  const $ = id => document.getElementById(id);
  const words = {Start:'Mulai',End:'Selesai',Timezone:'Zona waktu',Records:'Rekaman',Events:'Event',
    'Analysis reports':'Laporan analisis','Provider intelligence':'Intelijen provider',Search:'Cari','Minimum level':'Level minimum',Previous:'Sebelumnya',Next:'Berikutnya'};
  const t = (en,id) => window.SocLocale?.language === 'id' ? id || words[en] || en : en;
  let offset=0, items=[], timeline=[], selection=0, generation=0, busy=false;
  const local = ms => new Date(ms+Number($('historyZone').value)*3600000).toISOString().slice(0,16);
  const instant = value => { const ms=Date.parse(value+'Z')-Number($('historyZone').value)*3600000; if(!Number.isFinite(ms)) throw new Error(t('Select valid dates','Pilih tanggal yang valid')); return new Date(ms).toISOString(); };
  const display = value => new Intl.DateTimeFormat(window.SocLocale?.language==='id'?'id-ID':'en-GB',{dateStyle:'medium',timeStyle:'short',timeZone:$('historyZone').value==='7'?'Asia/Jakarta':'UTC'}).format(new Date(value));
  const chip = (value, cls='') => `<span class="historyChip ${esc(cls)}">${esc(value ?? '-')}</span>`;
  const metric = (label, value, detail='') => `<article><span>${esc(label)}</span><strong>${esc(value ?? '-')}</strong>${detail ? `<small>${esc(detail)}</small>` : ''}</article>`;
  const list = value => Array.isArray(value) ? value : value == null ? [] : [value];
  const providerStatus = p => p?.error ? 'error' : p?.status || (p?.is_malicious ? 'matched' : 'context');
  const providerLine = p => {
    const cves = list(p.cves || p.detail?.cves).slice(0,5).map(value=>typeof value==='object'?(value.cve||value.id||value.name||''):value).filter(Boolean).join(', ');
    return `<li><b>${esc(p.provider || 'provider')}</b><span>${esc(providerStatus(p))}</span>${cves ? `<small>CVE: ${esc(cves)}</small>` : ''}${p.error ? `<small>${esc(p.error)}</small>` : ''}</li>`;
  };
  const reportCard = r => {
    const v = r.verdict || {};
    const top = (r.top_indicators || []).slice(0,3).map(x => `${x.indicator} (${fmt.format(x.event_total || 0)})`).join(', ');
    return `${esc(v.severity || r.ai || '-')}${top ? ` · ${esc(top)}` : ''}`;
  };
  const compactList = (rows, empty='-') => (rows || []).slice(0,5).map(r=>`<li><b>${esc(r.value || r.provider || '-')}</b><span>${fmt.format(r.count ?? r.match ?? 0)}</span></li>`).join('') || `<li>${esc(empty)}</li>`;
  function renderSummary(summary, mode) {
    const target = $('historySummary');
    if (!target) return;
    if (!summary || !['reports','intelligence'].includes(mode)) {
      target.innerHTML = '';
      return;
    }
    if (mode === 'intelligence') {
      target.innerHTML = `<div class="historySummaryHero">
        <div><span>${t('Provider intelligence memory','Memori intelijen provider')}</span><strong>${t('Stored IOC snapshots','Snapshot IOC tersimpan')}</strong><p>${t('Historical results are read locally and do not consume provider API quota.','Hasil historis dibaca secara lokal dan tidak memakai kuota API provider.')}</p></div>
        <b>${fmt.format(summary.unique_indicators || 0)}</b>
      </div>
      <div class="historyMetrics historySummaryMetrics">
        ${metric(t('Snapshots','Snapshot'),fmt.format(summary.snapshots || 0),summary.materialization?.complete
          ? `${t('SQL summary ready','Ringkasan SQL siap')} · ${summary.retention_days || 180}d`
          : `${fmt.format(summary.materialization?.pending_legacy_snapshots || 0)} ${t('legacy snapshots pending','snapshot lama menunggu materialisasi')}`)}
        ${metric(t('Provider results','Hasil provider'),fmt.format(summary.provider_results || 0),t('stored locally','tersimpan lokal'))}
        ${metric(t('Provider matches','Provider match'),fmt.format(summary.provider_matches || 0),`${fmt.format(summary.provider_errors || 0)} ${t('errors','error')}`)}
        ${metric('CYFIRMA',fmt.format(summary.cyfirma_matches || 0),t('exact IOC matches','IOC match persis'))}
      </div>
      <div class="historySummaryGrid">
        <article><h3>${t('Provider coverage','Cakupan provider')}</h3><ul>${compactList(summary.providers,t('No stored provider result','Belum ada hasil provider tersimpan'))}</ul></article>
        <article><h3>${t('Stored CVE references','Referensi CVE tersimpan')}</h3><div class="historyChipRow">${(summary.cve_refs||[]).slice(0,12).map(v=>chip(v,'cve')).join('') || chip(t('No CVE references in this window','Tidak ada referensi CVE pada window ini'),'cve')}</div></article>
      </div>`;
      return;
    }
    const totals = summary.totals || {};
    const baseline = summary.baseline || {};
    const change = baseline.change_vs_previous || {};
    const providers = (summary.provider_consensus || []).slice(0,6);
    const cveHistory = summary.cve_history || {};
    target.innerHTML = `<div class="historySummaryHero">
      <div><span>${t('AI daily brief memory','Memori AI daily brief')}</span><strong>${t('Selected historical window','Window historis terpilih')}</strong><p>${t('Read from stored reports, not raw log replay or live provider calls.','Dibaca dari report tersimpan, bukan replay raw log atau panggilan provider live.')}</p></div>
      <b>${fmt.format(totals.case_score || 0)}</b>
    </div>
    <div class="historyMetrics historySummaryMetrics">
      ${metric(t('Reports','Report'), fmt.format(totals.reports || 0), t('stored analyst cycles','cycle analyst tersimpan'))}
      ${metric(t('Indexed events','Event terindeks'), fmt.format(totals.indexed_events || 0), t('largest report window','window report terbesar'))}
      ${metric(t('Findings','Temuan'), fmt.format(totals.findings || 0), `${t('change','perubahan')}: ${change.findings ?? '-' }%`)}
      ${metric(t('Provider matches','Provider match'), fmt.format(totals.provider_matches || 0), `${t('errors','error')}: ${fmt.format(totals.provider_errors || 0)}`)}
      ${metric(t('Deferred IOCs','IOC ditunda'), fmt.format(totals.deferred_candidates || 0), t('protected by quota/backoff','dilindungi quota/backoff'))}
      ${metric(t('New API lookups','Lookup API baru'), fmt.format(totals.new_external_lookups || 0), t('live provider calls in reports','call provider live di report'))}
      ${metric('CYFIRMA', fmt.format(totals.cyfirma_matches || 0), t('exact historical matches','match historis persis'))}
      ${metric('CVE', fmt.format(cveHistory.unique_cves || totals.critical_cves || 0), `${fmt.format(cveHistory.affected_assets || 0)} ${t('assets · stored locally','aset · tersimpan lokal')}`)}
    </div>
    <div class="historySummaryGrid">
      <article><h3>${t('Top source IP / IOC','Top source IP / IOC')}</h3><ul>${compactList(summary.top_source_ips, t('No IOC in stored reports','Tidak ada IOC di report tersimpan'))}</ul></article>
      <article><h3>${t('Top Wazuh rules','Top rule Wazuh')}</h3><ul>${compactList(summary.top_rules, t('No rule summary stored','Tidak ada ringkasan rule'))}</ul></article>
      <article><h3>${t('Attack categories','Kategori serangan')}</h3><ul>${compactList(summary.attack_categories, t('No classified attack category','Belum ada kategori serangan terklasifikasi'))}</ul></article>
      <article><h3>${t('Top destinations','Tujuan teratas')}</h3><ul>${compactList(summary.top_destinations, t('No destination captured','Belum ada tujuan yang tertangkap'))}</ul></article>
      <article><h3>${t('Observed identities','Identitas teramati')}</h3><ul>${compactList(summary.top_identities, t('No user identity captured','Belum ada identitas user yang tertangkap'))}</ul></article>
      <article><h3>${t('Affected assets','Aset terdampak')}</h3><ul>${compactList(summary.affected_assets, t('No affected asset assertion','Tidak ada aset terdampak'))}</ul></article>
      <article><h3>${t('Provider consensus','Konsensus provider')}</h3><ul>${providers.map(p=>`<li><b>${esc(p.provider)}</b><span>${fmt.format(p.match || 0)} match · ${fmt.format(p.error || 0)} error</span></li>`).join('') || `<li>${t('No provider memory','Tidak ada memori provider')}</li>`}</ul></article>
      <article><h3>${t('Anomaly baseline','Baseline anomali')}</h3><p>${t('Previous window','Window sebelumnya')}: ${fmt.format(baseline.previous_window?.findings || 0)} ${t('findings','temuan')} · ${t('7 days','7 hari')}: ${fmt.format(baseline.last_7_days?.findings || 0)} · ${t('30 days','30 hari')}: ${fmt.format(baseline.last_30_days?.findings || 0)}</p></article>
      <article><h3>${t('CVE history','Histori CVE')}</h3><p>${fmt.format(cveHistory.observations || 0)} ${t('daily asset/package observations','observasi harian aset/paket')} · ${fmt.format(cveHistory.critical || 0)} critical · ${fmt.format(cveHistory.high || 0)} high</p><div class="historyChipRow">${(summary.cve_refs || []).slice(0,8).map(v=>chip(v,'cve')).join('') || chip(t('No stored CVE in this window','Tidak ada CVE tersimpan pada window ini'),'cve')}</div><small>${esc(cveHistory.materialization?.complete ? t('Local ledger complete; zero provider calls','Ledger lokal lengkap; tanpa call provider') : `${fmt.format(cveHistory.materialization?.pending || 0)} ${t('legacy reports pending migration','report lama menunggu migrasi')}`)}</small></article>
    </div>`;
  }
  $('historyStart').value=local(Date.now()-86400000); $('historyEnd').value=local(Date.now());
  let oldZone=Number($('historyZone').value);
  $('historyZone').onchange=()=>{ for(const id of ['historyStart','historyEnd']) $(id).value=local(Date.parse($(id).value+'Z')-oldZone*3600000); oldZone=Number($('historyZone').value); };
  function labels(){document.querySelectorAll('[data-htext]').forEach(el=>el.textContent=t(el.dataset.htext));}
  async function pipeline(){
    try {const p=await postJson('/api/pipeline/status',{});
      $('pipelineStatus').innerHTML=[ [t('Discovery','Pembacaan log'),p.enabled?t('Enabled','Aktif'):t('Disabled','Nonaktif')], [t('Stream status','Status stream'),p.scan_status||'-'], [t('Checkpoint','Checkpoint'),p.checkpoint?display(p.checkpoint):'-'],[t('Lag','Keterlambatan'),p.lag_seconds==null?'-':Math.round(p.lag_seconds/60)+' min'],[t('Checkpoint events','Event checkpoint'),fmt.format(p.checkpoint_events_scanned)], [t('Rollup gaps','Gap rollup'),fmt.format(p.rollup?.gaps?.missing||0)], [t('Unique indicators','Indikator unik'),fmt.format(p.queued_indicators)], [t('Due for enrichment','Menunggu pengayaan'),fmt.format(p.due_indicators)] ].map(([k,v])=>`<div>${esc(k)}<strong>${esc(v)}</strong></div>`).join('')+`<p>${esc(p.error || p.historical_scope_note || t('Indexed alerts only; discovery starts with 24h and replays 5 minutes. Queue depth is not a count of confirmed threats.','Hanya alert terindeks; pembacaan dimulai dari 24 jam dan mengulang 5 menit. Jumlah antrean bukan jumlah ancaman terkonfirmasi.'))}</p>`;
      $('pipelineCommand').innerHTML=$('pipelineStatus').innerHTML;
      if(p.live_through){const line=document.createElement('p');line.textContent=`${t('Recent logs read through','Log terbaru dibaca sampai')}: ${display(p.live_through)}`;$('pipelineStatus').append(line);$('pipelineCommand').append(line.cloneNode(true));}
    }catch(e){$('pipelineStatus').textContent=e.message;}
  }
  function eventDetail(e){
    const a=e.analysis||{}, ax=k=>window.SocLocale?.analysis(a,k)||'', d=e.data||{};
    $('historyDetail').innerHTML=`<h2>${esc(ax('title')||e.rule?.description)}</h2><p>${esc(ax('meaning'))}</p><dl>${[
      [t('Time','Waktu'),display(e['@timestamp'])],[t('Evidence','Bukti'),e.id],[t('Index','Indeks'),e.index],['Rule',e.rule?.id],
      [t('Reporting device','Perangkat pelapor'),e.agent?.name],[t('Source IP','IP sumber'),d.srcip||d.src_ip||d.office365?.ClientIP||d.win?.eventdata?.ipAddress],
      [t('Destination IP','IP tujuan'),d.dstip||d.dst_ip],[t('Operation','Operasi'),d.office365?.Operation],[t('Source','Sumber'),e.decoder?.name]
    ].map(([k,v])=>`<dt>${esc(k)}</dt><dd>${esc(v??'-')}</dd>`).join('')}</dl><h3>L1</h3><p>${esc(ax('l1'))}</p><h3>L2</h3><p>${esc(ax('l2'))}</p><h3>CVE</h3><p>${esc(ax('cve_context'))}</p><details><summary>${t('Original evidence','Bukti asli')}</summary><pre>${esc(JSON.stringify(e,null,2))}</pre></details>`;
  }
  async function choose(i){
    const token=++selection, row=items[i]; if(!row)return;
    if($('historyMode').value==='events') {eventDetail(row);return;}
    if($('historyMode').value==='intelligence') {
      const stored = row.result || {}, data = stored.data || {};
      const providers = Array.isArray(data.results) ? data.results : [];
      const cves = row.cve_refs || [];
      $('historyDetail').innerHTML=`<div class="historyReportHero ${esc(row.malicious?'high':'medium')}">
        <div><span>${t('Stored provider snapshot','Snapshot provider tersimpan')}</span><h2>${esc(row.indicator)}</h2><p>${esc(display(row.observed_at))}</p></div>
        <strong>${esc(row.risk || 'unknown')}</strong>
      </div>
      <div class="historyMetrics">
        ${metric(t('Provider results','Hasil provider'),fmt.format(row.provider_results || 0),t('no live API call','tanpa call API live'))}
        ${metric(t('Matches','Match'),fmt.format(row.provider_matches || 0),`${fmt.format(row.provider_errors || 0)} ${t('errors','error')}`)}
        ${metric('CYFIRMA',fmt.format(row.cyfirma_matches || 0),t('exact IOC matches','IOC match persis'))}
        ${metric('CVE',fmt.format(cves.length),t('provider references; exposure must be verified','referensi provider; paparan harus diverifikasi'))}
      </div>
      <section class="historyBriefBlock"><h3>${t('Provider consensus','Konsensus provider')}</h3><ul class="historyProviderList">${providers.map(providerLine).join('') || `<li>${t('No provider detail stored','Tidak ada detail provider tersimpan')}</li>`}</ul></section>
      <section class="historyBriefBlock"><h3>${t('CVE context','Konteks CVE')}</h3><div class="historyChipRow">${cves.map(v=>chip(v,'cve')).join('') || chip(t('No CVE references stored','Tidak ada referensi CVE tersimpan'))}</div><p>${t('A provider CVE reference is attack context, not proof that a local device is vulnerable.','Referensi CVE provider adalah konteks serangan, bukan bukti perangkat lokal rentan.')}</p></section>
      <details><summary>${t('Stored source record','Record sumber tersimpan')}</summary><pre>${esc(JSON.stringify(stored,null,2))}</pre></details>`;
      return;
    }
    $('historyDetail').textContent=t('Loading report...','Memuat laporan...');
    try {const {report:r}=await postJson('/api/history/report',{id:row.id});if(token!==selection)return;
      const ai = r.ai || {}, res = ai.result || {}, verdict = res.verdict || {};
      const coverage = r.coverage || {};
      const findings = r.findings || [];
      const vulns = r.vulnerabilities || [];
      const providerMatches = findings.reduce((sum,f)=>sum+(f.providers||[]).filter(p=>p.status==='matched'||p.is_malicious).length,0);
      const providerErrors = findings.reduce((sum,f)=>sum+(f.providers||[]).filter(p=>p.error).length,0);
      const cyfirmaMatches = findings.reduce((sum,f)=>sum+(f.cyfirma_matches||[]).length,0);
      const cveRefs = [...new Set([
        ...findings.flatMap(f=>[...(f.cves||[]), ...(f.related_cves||[]), ...(f.providers||[]).flatMap(p=>p.cves||[])]),
        ...((r.intelligence_deck?.top_findings || []).flatMap(f=>f.related_cves||[]))
      ])].slice(0,20);
      const attackCategories = (res.attack_categories || []).slice(0,8);
      const networkPaths = (res.network_paths || []).slice(0,10);
      const identities = (res.identities || []).slice(0,10);
      const dataImpact = (res.data_impact || []).slice(0,8);
      const affectedAssets = (res.affected_assets || []).slice(0,10);
      const topSources = (coverage.syslog_sources || []).slice(0,4).map(s=>`${s.key}: ${fmt.format(s.doc_count||0)}`).join(' | ');
      $('historyDetail').innerHTML=`<div class="historyReportHero ${esc(verdict.severity || 'medium')}">
        <div><span>${t('SOC historical brief','Ringkasan historis SOC')}</span><h2>${t('Analysis report','Laporan analisis')} #${esc(r.id)}</h2><p>${esc(display(r.generated_at))}</p></div>
        <strong>${esc(verdict.severity || ai.status || 'not assessed')}</strong>
      </div>
      <div class="historyMetrics">
        ${metric(t('Indexed events','Event terindeks'), fmt.format(coverage.indexed_events || 0), coverage.range || 'window')}
        ${metric(t('Findings','Temuan'), fmt.format(findings.length), t('stored in report','tersimpan di report'))}
        ${metric(t('Provider matches','Provider match'), fmt.format(providerMatches), providerErrors ? `${fmt.format(providerErrors)} provider errors` : '')}
        ${metric('CYFIRMA', fmt.format(cyfirmaMatches), t('exact IOC matches','IOC match persis'))}
        ${metric('CVE', fmt.format(vulns.length), `${fmt.format(vulns.filter(v=>v.severity==='Critical').length)} critical`)}
      </div>
      <section class="historyBriefBlock"><h3>AI Analyst</h3><p><b>${esc(verdict.status || ai.status || '-')}</b> · ${esc(verdict.confidence || 'low')} confidence</p><p>${esc(verdict.reason || res.summary || ai.error || '-')}</p><p>${esc(res.assessment || '')}</p></section>
      <section class="historyBriefBlock"><h3>${t('Attack classification','Klasifikasi serangan')}</h3><ul>${attackCategories.map(v=>`<li><b>${esc(v.category||'other')}</b> · ${fmt.format(v.count||0)} · ${esc(v.severity||'-')}<br><small>${esc((v.evidence||[]).join(', '))}</small></li>`).join('') || `<li>${t('No AI attack classification stored','Belum ada klasifikasi serangan AI tersimpan')}</li>`}</ul></section>
      <section class="historyBriefBlock"><h3>${t('Source to destination paths','Jalur sumber ke tujuan')}</h3><ul>${networkPaths.map(v=>`<li><b>${esc(v.source||'unknown')} → ${esc(v.destination||'unknown')}</b> · ${esc(v.action||'unknown')} · ${fmt.format(v.events||0)} ${t('events','event')}<br><small>${esc((v.evidence||[]).join(', '))}</small></li>`).join('') || `<li>${t('No verified network path stored','Belum ada jalur jaringan terverifikasi')}</li>`}</ul></section>
      <section class="historyBriefBlock"><h3>${t('Identity and data activity','Aktivitas identitas dan data')}</h3><ul>${identities.map(v=>`<li><b>${esc(v.user||'unknown')}</b> · ${esc(v.activity||'observed')} · ${esc(v.asset||'unknown')}</li>`).join('')}${dataImpact.map(v=>`<li><b>${esc(v.data||'unknown data')}</b> · ${esc(v.operation||'unknown')} · ${esc(v.status||'not_established')}</li>`).join('') || (!identities.length ? `<li>${t('No identity or data impact established','Belum ada dampak identitas atau data yang terbukti')}</li>` : '')}</ul></section>
      <section class="historyBriefBlock"><h3>${t('Affected assets','Aset terdampak')}</h3><ul>${affectedAssets.map(v=>`<li><b>${esc(v.asset||'unknown')}</b> · ${esc(v.role||'unknown')}<br><small>${esc(v.evidence||'')}</small></li>`).join('') || `<li>${t('No affected asset assertion','Tidak ada aset terdampak yang dapat dipastikan')}</li>`}</ul></section>
      <section class="historyBriefBlock"><h3>${t('Recommended action','Rekomendasi tindakan')}</h3><ul>${(res.recommendations||[]).slice(0,6).map(v=>`<li>${esc(v)}</li>`).join('') || `<li>${t('Validate findings against original evidence before response.','Validasi temuan ke bukti asli sebelum respons.')}</li>`}</ul></section>
      <section class="historyBriefBlock"><h3>${t('Telemetry source mix','Komposisi sumber telemetri')}</h3><p>${esc(topSources || '-')}</p></section>
      <section class="historyBriefBlock"><h3>${t('Provider and CVE memory','Memori provider dan CVE')}</h3><div class="historyChipRow">${cveRefs.map(v=>chip(v,'cve')).join('') || chip(t('No provider CVE refs stored','Tidak ada CVE provider tersimpan'))}</div></section>
      <h3>${t('Recorded findings','Temuan tersimpan')}</h3>
      <div class="historyFindingGrid">${findings.slice(0,12).map(f=>`<details class="historyFinding"><summary><b>${esc(f.indicator)}</b><span>${esc(f.status)} · ${fmt.format(f.event_total??f.occurrences??0)} ${t('events','event')}</span></summary>
        <div class="historyChipRow">${(f.cyfirma_matches||[]).slice(0,6).map(m=>chip(`CYFIRMA: ${m.name||m.id||m.pattern||'IOC'}`,'cyfirma')).join('')}${[...new Set((f.providers||[]).flatMap(p=>p.cves||[]))].slice(0,8).map(v=>chip(v,'cve')).join('')}</div>
        <ul class="historyProviderList">${(f.providers||[]).slice(0,8).map(providerLine).join('') || `<li>${t('No provider detail stored','Tidak ada detail provider tersimpan')}</li>`}</ul>
        ${(f.evidence||[]).slice(0,3).map(e=>`<p class="historyEvidence">Rule ${esc(e.rule?.id)} | ${esc(e.device||'-')} | ${esc(e.source_ip||'-')} → ${esc(e.destination_ip||'-')} | ${esc(e.timestamp)}</p>`).join('')}
      </details>`).join('') || `<p>${t('No findings stored in this report.','Tidak ada temuan tersimpan pada report ini.')}</p>`}</div>
      <h3>${t('CVE inventory priorities','Prioritas inventaris CVE')}</h3>
      <div class="historyCveGrid">${vulns.slice(0,16).map(v=>`<article><strong>${esc(v.cve)}</strong><span>${esc(v.severity)} · ${esc(v.agent)}</span><small>${esc(v.package)} ${esc(v.version||'')}</small></article>`).join('') || `<p>${t('No CVE inventory stored.','Tidak ada inventaris CVE tersimpan.')}</p>`}</div>`;
    }catch(e){if(token===selection)$('historyDetail').textContent=e.message;}
  }
  function chart(){
    const max=Math.max(1,...timeline.map(v=>v.doc_count));
    $('historyChartSummary').textContent=timeline.length?`${t('Event volume','Volume event')} · ${t('Peak','Puncak')} ${fmt.format(max)} · ${timeline.length>1&&timeline[1].key-timeline[0].key>=86400000?t('daily','harian'):t('hourly','per jam')}`:'';
    $('historyTimeline').innerHTML=timeline.map((v,i)=>`<button type="button" data-bucket="${i}" style="--bar:${Math.max(2,v.doc_count/max*100)}%" title="${esc(display(v.key))}: ${fmt.format(v.doc_count)}" aria-label="${esc(display(v.key))}: ${fmt.format(v.doc_count)}"></button>`).join('');
  }
  async function load(reset=true){
    if(reset)offset=0; const token=++generation; ++selection; busy=true;
    $('historySearch').disabled=true; $('historyStatus').textContent=t('Searching...','Mencari...'); $('historyDetail').textContent='';
    if ($('historySummary')) $('historySummary').innerHTML = '';
    try {
      const mode=$('historyMode').value;
      const data=await postJson('/api/history/'+mode,{start:instant($('historyStart').value),end:instant($('historyEnd').value),offset,query:$('historyQuery').value,min_level:Number($('historyLevel').value)});
      if(token!==generation)return; if(data.ok===false)throw new Error(t('Partial index response. Narrow the time range and retry.','Respons indeks parsial. Persempit periode lalu coba lagi.'));
      items=data.events||data.reports||data.intelligence||[]; if(reset){timeline=data.timeline||[];chart();renderSummary(data.summary, mode);}
      $('historyStatus').textContent=mode==='events'?`${fmt.format(data.total)} ${t('events in selected interval; not all are attacks','event pada periode terpilih; tidak semuanya serangan')}`:mode==='intelligence'?`${fmt.format(data.total)} ${t('stored provider snapshots in selected interval','snapshot provider tersimpan pada periode terpilih')}`:`${fmt.format(items.length)} ${t('analysis reports in selected interval','laporan analisis pada periode terpilih')}`;
      $('historyHead').innerHTML=`<tr><th>${t('Time','Waktu')}</th><th>${t('Record','Rekaman')}</th><th>${mode==='events'?'Level':mode==='intelligence'?t('Risk','Risiko'):'AI'}</th></tr>`;
      $('historyRows').innerHTML=items.map((r,i)=>{const when=mode==='events'?r['@timestamp']:mode==='intelligence'?r.observed_at:r.generated_at;const record=mode==='events'?r.rule?.description||r.id:mode==='intelligence'?`${r.indicator} · ${r.provider_results} provider result(s)`:'#'+r.id+' · '+r.findings+' '+t('findings','findings');const sub=mode==='events'?r.agent?.name||'':mode==='intelligence'?`${r.provider_matches} match · ${r.cve_refs?.length||0} CVE · ${r.cyfirma_matches||0} CYFIRMA`:reportCard(r);const level=mode==='events'?r.rule?.level:mode==='intelligence'?r.risk:r.verdict?.severity||r.ai;return `<tr><td>${esc(display(when))}</td><td><button type="button" data-history-row="${i}">${esc(record)}</button><br>${esc(sub)}</td><td>${esc(level)}</td></tr>`;}).join('');
      $('historyPage').textContent=`${offset+Number(items.length>0)}–${offset+items.length}`;
      $('historyPrevious').disabled=offset===0; $('historyNext').disabled=mode==='events'?offset+items.length>=data.total||offset>=9950:items.length<20;
      if(items.length)await choose(0);
    }catch(e){if(token===generation){$('historyStatus').textContent=e.message; $('historyRows').innerHTML=''; $('historyNext').disabled=true;}}
    finally{if(token===generation){busy=false;$('historySearch').disabled=false;}}
  }
  $('historyFilters').onsubmit=e=>{e.preventDefault();load();};
  $('historyQuery').disabled=true; $('historyLevel').disabled=true;
  $('historyMode').onchange=()=>{const mode=$('historyMode').value;$('historyQuery').disabled=mode==='reports';$('historyLevel').disabled=mode!=='events';load();};
  $('historyPrevious').onclick=()=>{if(!busy){offset=Math.max(0,offset-($('historyMode').value==='events'?50:20));load(false);}};
  $('historyNext').onclick=()=>{if(!busy){offset+=$('historyMode').value==='events'?50:20;load(false);}};
  $('historyRows').onclick=e=>{const b=e.target.closest('[data-history-row]');if(b)choose(Number(b.dataset.historyRow));};
  $('historyTimeline').onclick=e=>{const b=e.target.closest('[data-bucket]');if(!b)return;const i=Number(b.dataset.bucket),step=timeline.length>1?timeline[1].key-timeline[0].key:3600000; $('historyStart').value=local(timeline[i].key);$('historyEnd').value=local(timeline[i].key+step);load();};
  document.querySelector('[data-view="history"]').addEventListener('click',()=>{pipeline();if(!items.length)load();});
  document.addEventListener('soc:language',()=>{labels();if(state.view==='history'){pipeline();load();}});
  setInterval(()=>{if(['history','command'].includes(state.view))pipeline();},15000);
  labels();pipeline();
})();
