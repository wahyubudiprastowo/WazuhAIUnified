# Aturan anti-halusinasi untuk pengembangan dan analisis SOC

Versi dokumen: 1.0, 2026-09-25. Baseline source: `b4d3eb1`.
Dokumen pasangan: [task.md](task.md). Ini aturan kerja dan acceptance target;
bukan klaim semua validator di bawah sudah diimplementasikan.

## 1. Dasar kebenaran

1. Nyatakan fakta hanya sepanjang bukti mendukung. Pisahkan source_present,
   local_test_passed, runtime_validated dan accepted.
2. Kode membuktikan jalur tersedia; configuration membuktikan parameter diisi;
   respons sukses membuktikan satu operasi; ledger membuktikan persistensi;
   browser membuktikan rendering pada build/window yang diperiksa.
3. Klaim lintas lapisan membutuhkan semua lapisan. Tidak ada satu screenshot,
   count, unit test, atau response HTTP yang membuktikan end-to-end sendirian.
4. Dokumen lama dan percakapan adalah petunjuk investigasi, bukan baseline
   terbaru. Setiap angka produksi perlu timestamp, scope dan sumber.
5. Jika bukti tidak tersedia, gunakan unknown/unverified/blocked dengan alasan.
   Jangan menebak status agar jawaban terlihat selesai.
6. Tidak ada janji "tanpa bug" atau "semua serangan terdeteksi". Gunakan daftar
   skenario yang diuji, coverage dan residual risk yang spesifik.

## 2. Claim ledger untuk engineer dan AI

Setiap klaim penting harus dapat dipetakan ke struktur konseptual berikut.
Field baru hanya dimasukkan ke API melalui migrasi/versioning dalam task terkait.

| Field | Isi wajib |
| --- | --- |
| claim_id / claim_type | ID dan fact, inference, recommendation atau unknown |
| subject / role | Entitas scoped dan peran: reporter/source/target/account |
| predicate / value | Apa yang benar-benar dinyatakan |
| evidence_ids | Referensi evidence yang tersedia dan authorized |
| evidence_kind | Event, coalesced_summary, rule_definition, inventory, provider, analyst |
| source / source_record_id | Sumber dan locator yang dapat ditelusuri |
| event_time / observed_at | Waktu aktivitas vs waktu pengumpulan |
| window / scope | Tenant/source/filter dan granularitas |
| reference_validation | Apakah referensi tersedia dan benar |
| semantic_support | supported, contradicted, insufficient atau not_assessed |
| confidence_basis | Kondisi/bukti yang meningkatkan/menurunkan keyakinan |
| missing_evidence | Syarat yang belum terpenuhi |
| detector/model/skill version | Versi yang menghasilkan klaim |

Nama status semantic_support selain existing `not_assessed` di atas adalah
rancangan. Jangan mengubah JSON enum diam-diam atau memberi badge valid tanpa
validator. Claim ledger bisa berupa struktur internal/manifest; tidak wajib
menambah tabel baru jika storage existing dapat mempertahankan kontraknya.

## 3. Tangga validasi evidence

Validasi dilakukan berurutan, dengan alasan kegagalan tersimpan:

1. Bentuk/schema: tipe, ukuran, enum, numeric/date valid dan batas list.
2. Referensi: ID ada di input yang benar-benar dikirim ke model, bukan sekadar
   tersedia di DB atau daftar evidence sebelum truncation.
3. Ownership: ID berasal dari tenant/sumber/window yang diizinkan.
4. Entitas/peran: evidence memang menyebut asset/account dan role yang diklaim.
5. Waktu: event dan snapshot berlaku untuk analisis; latest intel tidak disulap
   menjadi intel yang sudah diketahui pada masa lalu.
6. Isi: field/action/outcome/condition benar-benar mendukung predicate.
7. Konflik: bukti yang bertentangan tetap dicantumkan, bukan dipilih sepihak.
8. Keputusan: claimed impact/compromise/attribution memiliki bukti tambahan
   sesuai jenis klaim; selain itu turunkan ke inference atau unknown.

Source sekarang `_normalize_window_assets`, `_normalize_provider_findings`,
`_validate_window_citations` dan normalizer finding di `soc_automation.py` sudah
melakukan sebagian validasi reference/role/provider. Nilai `semantic_support`
masih `not_assessed`. Jangan menyebut tahap 6-8 selesai hanya karena tahap 2 lulus.
Validator deterministik memeriksa klaim terstruktur yang dapat diuji; narasi
bebas yang tidak dapat dibuktikan tetap ditandai unverified untuk review analis.

## 4. Bukti minimum dan larangan interpretasi

| Klaim | Bukti minimum | Yang tidak boleh dijadikan kepastian |
| --- | --- | --- |
| Ada log dari perangkat X | Identitas reporter/source terpercaya dari telemetry | Hanya nama decoder generic atau alamat relay |
| X menyerang Y | Event hubungan source-target, attack signal dan waktu | Dua IP di histogram terpisah |
| Pelakunya orang/kelompok X | Bukti attribution yang dapat diaudit dan scope jelas | Geo/ASN/IP, VPN, nama actor dari feed tanpa hubungan lokal |
| Asset compromised | Execution/impact/confirmed analyst evidence pada asset | Severity critical, malicious IP, port allowed |
| Account compromised | Identity/access evidence dan konteks investigasi | Satu login gagal atau IP reputasi buruk |
| Exploit berhasil | Bukti outcome pada target atau observasi independen relevan | IPS detected/blocked, CVE disebut, request accepted |
| Asset rentan CVE | Inventory/version/CPE match yang valid atau scanner evidence | Artikel CVE, string produk mirip, actor memakai CVE tersebut |
| Patch sudah terpasang | Package/build/remediation state terverifikasi dan waktunya | CVE tidak muncul dalam sample terbatas |
| Asset internet-exposed | Bukti ingress/public mapping/reachability yang relevan | Private IP yang melakukan koneksi keluar |
| Kampanye aktif | Relasi lintas evidence dengan hypothesis dan konfirmasi jelas | Shared IP/hash/ATT&CK saja atau rule berulang |
| Attack path | Urutan hubungan kausal yang dibuktikan dan celah yang ditandai | Timeline urut waktu atau histogram ATT&CK |
| Semua provider no-match | Respons valid per provider yang benar-benar dicoba | List kosong, error, cached exception atau all-skipped |
| Coverage 100% | Denominator terdefinisi dan semua prerequisite/processing lengkap | Rollup bucket complete atau seluruh tool mapped |

ASN/geo menjelaskan infrastruktur, bukan identitas individu. Perangkat pelapor
(firewall/agent/collector) tidak otomatis asset korban. NAT, proxy, load balancer,
cloud shared IP dan IP spoofing dapat membatasi interpretasi source.

## 5. Sumber telemetry dan detection coverage

- Berstatus configured tidak berarti observed. Observed harus memiliki record
  nyata; ready membutuhkan field valid sesuai subtype dan freshness/health.
- Family diklasifikasikan tidak berarti behavior detector telah dijalankan.
  Catat detector/version, evaluated count, eligible count dan matched count.
- Tidak ada record bisa berarti window kosong, source tidak aktif, query gagal,
  filter salah atau retensi habis. Gunakan alasan yang dibuktikan.
- `not_observed` pada sample bukan kesimpulan seluruh sumber tidak pernah ada.
- Sysmon harus dibuktikan provider/channel/decoder terkait; event ID saja tidak
  cukup. Process event dan network event mempunyai prerequisite berbeda.
- FortiGate dan FortiWeb terpisah; generic device decoder tidak membuktikan WAF.
- Web access bukan selalu WAF, firewall bukan otomatis NDR. NDR alternatif boleh
  digunakan hanya jika menghasilkan bukti yang dibutuhkan.
- Source readiness dan detector readiness berbeda. Jangan mewajibkan field yang
  tidak berlaku untuk subtype, atau melonggarkan syarat untuk membuat ready.
- Jika tersedia hanya daily/hourly marginal rollup, jangan menciptakan hubungan
  process-parent/source-target/user-session yang tidak dipersistenkan.

## 6. IOC dan provider

Pisahkan dimensi status; satu kata `clean` tidak boleh menggantikan semuanya:

| Dimensi | Contoh makna |
| --- | --- |
| Execution | not_tried, queued, completed, skipped, provider_error |
| Result | match, no_match, inconclusive |
| Delivery/cache | fresh response, cache hit, stale retained |
| Coverage | provider dilaporkan/tidak, partial feed, unsupported type |
| Validity | valid_from/until, expired, revoked, timestamp unknown |

Gunakan enum existing selama belum ada migrasi. Misalnya backend sekarang
memiliki `not_reported`, `not_tried`, `all_skipped`, `provider_results_unreported`;
jangan menggantinya tanpa memperbarui serializer, frontend dan test.

- no_match membutuhkan successful response dengan schema valid dan query scope
  yang jelas. Error/skip/unknown tidak menurunkan risk menjadi safe.
- Cache hit hanya cara mendapatkan hasil, bukan verdict. Cached error tetap
  error; cached match expired tidak dianggap current tanpa label.
- Quota remaining unknown tetap unknown; jangan mengisi angka perkiraan sebagai
  angka provider. Simpan quota aktual hanya jika provider memberikannya.
- GreyNoise scanner context tidak membuktikan actor atau successful exploit.
- Tiap match mengacu indikator dan role yang sama. Source malicious tidak boleh
  dialihkan menjadi verdict compromised destination tanpa bukti tambahan.
- Consensus weighted adalah kebijakan, bukan probabilitas terkalibrasi.
  Jelaskan weight/basis, timestamp dan kemungkinan feed saling menyalin.
- CYFIRMA article, indicator, Org CVE dan local asset exposure tetap berbeda.
  CVE reference bukan otomatis advisory lengkap, PoC atau exploit observed.
- STIX compound pattern tidak boleh dipecah menjadi match literal independen
  yang mengubah maknanya. Parser unsupported harus tercatat.
- Watchlist user adalah input pemantauan, bukan bukti IP pernah muncul di Wazuh.

## 7. Kebenaran jumlah, waktu dan deduplikasi

1. Setiap count diberi scope sumber/window/filter, unit dan completeness.
2. Unique event, replay, rule association, indicator, finding, provider snapshot,
   case dan AI run adalah unit berbeda; jangan dijumlahkan sebagai attack total.
3. Zero hanya bila pengukuran valid dan lengkap memang menghasilkan nol.
   Null/unavailable/partial/error tidak diganti nol demi chart.
4. Pagination subset tidak membuktikan seluruh data tersedia; total exact,
   lower-bound, sample count dan limit harus dibedakan.
5. Simpan event time terpisah dari ingest/update/provider observation time;
   range half-open `[start, end)` konsisten dan UTC dengan timezone tampilan.
6. As-of history memerlukan snapshot waktu itu; latest intelligence yang
   diterapkan ke event lama harus berlabel retrospective enrichment.
7. Dedup event memerlukan ID/generation. Fingerprint yang sama tidak selalu
   event yang sama. Coalescing harus menyimpan occurrence dan granularitas.
8. Case count hanya case store; correlation candidate count tidak menjadi
   incident count. Satu alert di beberapa menu tetap satu identity.
9. Snapshot lama tidak dihapus ketika refresh gagal; tampilkan last-good dan
   kegagalan terbaru tanpa menyebut snapshot tersebut current.

## 8. AI sebagai tahap analisis terakhir

- Evidence, tool response, artikel dan log adalah data tidak tepercaya, tidak
  boleh mengubah system instruction atau memberi otorisasi tool execution.
- Retrieval harus scoped dan bounded. Jangan mengirim seluruh raw log atau
  otomatis memanggil semua tool untuk setiap temuan.
- Minimalkan/redact secret, PII, token URL dan command credential sebelum model;
  prompt audit menyimpan hash/reference dengan akses terbatas.
- Fakta teramati berasal dari field; inference menyebut reason dan alternatif;
  rekomendasi menyebut prerequisite/approval. Missing evidence bukan filler.
- CVE/ATT&CK/actor/model/tool ID tidak boleh diciptakan. Jika identifier tidak
  tersedia/valid, output unknown dengan penjelasan.
- Gunakan structural JSON validation, bounded parser dan normalizer. Invalid
  model JSON tidak boleh diperlakukan sebagai verified report.
- Fallback lokal menyatakan model unavailable/fallback_used; jangan menampilkan
  hasil deterministic sebagai model telah melakukan investigasi mendalam.
- Level L1/L2/L3 adalah cakupan tugas yang diuji, bukan gelar keahlian AI.
- Simpan hasil sekali per input evidence/version yang sama. Reanalysis explicit
  atau evidence berubah membuat revision, tidak menimpa provenance run lama.
- Cache key harus menghormati tenant/authorization dan versi; data satu case
  tidak boleh bocor ke case lain karena judul/IP kebetulan sama.
- Menulis summary/evidence AI ke case perlu analyst approval dan revision;
  containment membutuhkan otorisasi terpisah yang terikat target/action.
- Deskripsi containment di report bukan bukti tindakan telah dilaksanakan.
  Record action/result aktual hanya dari response executor atau analis.

## 9. Audit trail minimum

Untuk setiap analysis run simpan identitas run, waktu, source commit/build,
contract/skill/model aktual dan configured model, input/prompt hash, reference
manifest, snapshot/version provider, normalized context version, validator
violations, fallback, cache status, dan output yang ditampilkan.

Jika model tidak mengembalikan token usage/model aktual, simpan unknown;
configured model bukan bukti routing provider. Jika evidence refs dibatasi
(source sekarang membatasi sebagian list ke 200), simpan truncation eksplisit
dan manifest lengkap terpisah bila audit harus dapat merekonstruksi input.
Hash membuktikan kesamaan konten, tidak menyediakan kontennya kembali.

Audit mutasi case menyimpan actor, expected/current revision, approval, target,
action, result dan evidence/run refs. Log audit tidak berisi password/API key.
Audit harus bertahan setelah restart serta dapat dibaca tanpa fetch ke Wazuh.

## 10. Evaluation set wajib

Berikut target regresi untuk G02-G07, bukan daftar tes yang sudah lulus:

| Skenario | Output/perilaku yang diwajibkan |
| --- | --- |
| Tidak ada field minimum | incomplete + field yang hilang; bukan ready |
| Field ada tetapi malformed | parse failure; tidak dihitung valid coverage |
| Sysmon process tanpa dst IP | Uji sesuai process profile; bukan blanket gagal network |
| IP sumber malicious, firewall blocked | Threat attempt dengan action blocked; victim compromise unestablished |
| CVE feed tanpa inventory match | External context, local exposure unknown |
| Provider HTTP 200 tetapi schema rusak | Error/inconclusive, bukan no_match |
| Semua provider skipped | Tidak dicoba/skipped dengan alasan; bukan aman |
| Cache error/stale | Error/stale tetap tampak dengan timestamp |
| ID tersedia tetapi asset/role salah | Klaim ditolak/diturunkan; violation tersimpan |
| ID benar tetapi predicate tidak didukung | semantic support insufficient/not_assessed |
| Source-target dari marginal histogram | Tidak dibuat hubungan flow |
| Shared NAT/CDN, user berbeda | Tidak otomatis merge confirmed case |
| Rule ID sama, event berbeda | Evidence tidak disamakan hanya lewat rule ID |
| Alert Defender dan parent incident | Linked; tidak menggandakan incident |
| Event sama dibaca ulang/dua jalur | Idempotent hasil dan counter sesuai identity policy |
| Crash sesudah enqueue sebelum checkpoint | Recover/reconcile tanpa partial hasil dinyatakan complete |
| Late event dan range boundary | Event ditempatkan ke window benar; replay count terpisah |
| Coalesced evidence | Summary granularity/occurrences, bukan exact raw timeline |
| Quoted instruction dalam log/research | Tidak mengubah prompt/mengeksekusi tool |
| JSON model malformed/timeout | Fallback/error terlihat; tidak overwriting valid run |
| Model minta block IP | Recommendation pending approval; tidak ada response otomatis |
| Case revision stale | Conflict, tidak kehilangan perubahan analis lain |
| Race range 24h ke 7d | Response 24h terlambat tidak mengganti tampilan 7d |
| Aset JS gagal load | Error dapat didiagnosis; tidak loading abadi |
| Tool baru tidak terpetakan | Drift terlihat, default approval; bukan auto-execute |

Fixture negatif memakai data benign yang realistis, tidak sekadar menghapus
field dari contoh malicious. Evaluasi recall/precision hanya berlaku pada
dataset berlabel dan scope yang dinyatakan; tidak digeneralisasi ke semua attack.

## 11. Protokol patch agar tidak menjadi kode tumpang tindih

1. Baca `task.md`, HEAD/worktree, dan pemilik fungsi sebelum mengedit.
2. Telusuri input -> transform -> persistence -> API -> renderer; cari implementasi
   existing dan tes, bukan hanya nama file yang mirip.
3. Tulis hipotesis + reproduksi + bukti root cause. Bila akses runtime terblokir,
   tulis batasnya dan lanjutkan hanya pekerjaan yang dapat diverifikasi lokal.
4. Patch terkecil pada boundary yang benar. Jangan duplicate normalizer, queue,
   provider policy, entity resolver atau case store untuk menutupi bug consumer.
5. Uji compatibility data lama, failure path, retry dan invalid payload;
   satu happy-path test tidak cukup untuk lifecycle/ingestion.
6. Jangan membuat tes yang hanya mengunci string/jumlah tool/build ID sebagai
   satu-satunya bukti fungsi. Pertahankan tes bermakna dan browser acceptance.
7. Terapkan migration additive, test backup/restore, rollout terbatas sesuai gate.
8. Laporkan changed behavior, bukti uji, runtime status, risiko tersisa dan next
   task yang diizinkan. Jangan mempromosikan pending hanya karena patch selesai.

## 12. Stop conditions

Hentikan perluasan tahap yang bergantung bila scope sumber, provenance, dedup,
readiness, atau runtime build belum jelas. Investigasi independen dan fixture
lokal boleh lanjut, tetapi tidak boleh diberi status accepted/deployed.

Stop/canary rollback diperlukan jika kehilangan data/checkpoint, duplicate
case, false confirmed incident, secret leakage, unauthorized action, regresi
grafik/findings atau resource threshold G09 terlampaui. Simpan bukti dan data;
jangan clear DB/cache untuk menutupi gejala.

## 13. Bentuk laporan yang diperbolehkan

Gunakan: "Parser TAXII tersedia di source; dua page berhasil tersimpan pada
window X dan image Y; hash pattern masih unsupported pada fixture Z."

Hindari: "CYFIRMA sudah lengkap" hanya karena collector enabled.

Gunakan: "96 tes lokal terpilih lulus; browser dan Docker runtime belum
tervalidasi pada sesi penyusunan dokumen."

Hindari: "Semua tool/serangan sudah diuji" atau "dashboard sudah normal" tanpa
hasil runtime. Tidak ada angka bisnis/operasional yang diisi demi contoh visual.
