# Rencana peningkatan SOC berbasis bukti

Baseline source: `b4d3eb1`, diperiksa 2026-09-25 UTC. Status dokumen: rencana
implementasi dan baseline pemeriksaan lokal, bukan sertifikasi produksi.
Baca bersama [aturan anti-halusinasi](ANTI_HALLUCINATION.md).

## 1. Tujuan dan batas pekerjaan

Alur tujuan: telemetry -> normalisasi -> deteksi deterministik -> finding/evidence
tersimpan -> enrichment IOC/CVE -> korelasi -> analisis AI -> keputusan analis.
Antrean, checkpoint, dan pengayaan berjalan background dengan batas sumber daya.
AI menerima bukti terpilih dan hasil tool tersimpan agar hemat token.

Target yang dapat diuji adalah cakupan sumber, field, dan skenario serangan yang
didefinisikan. Tidak ada acceptance berupa "semua serangan pasti terdeteksi".
Log yang tidak merekam process, payload HTTP, autentikasi, atau traffic tertentu
tidak dapat menjadi bukti lengkap untuk perilaku tersebut. Serangan baru dan
aktivitas yang tidak tercatat tetap merupakan batas deteksi.

Dokumen awal dibuat sebagai rencana tanpa perubahan runtime. Implementasi G00
kemudian diminta dan dijalankan pada 2026-09-25; lihat catatan eksekusi di bawah.
Status baseline historis tidak menggantikan hasil pengamatan terbaru. Tahap
implementasi berikutnya harus dimulai dari gate yang belum lulus.

## 2. Cara membaca status

| Status | Arti | Bukti minimum |
| --- | --- | --- |
| source_present | Implementasi ditemukan di source baseline | File dan simbol |
| local_test_passed | Tes lokal tertentu lulus | Perintah, hasil, tanggal, cakupan |
| runtime_unverified | Image/proses/data yang aktif belum terbukti | Jangan dipromosikan menjadi selesai |
| pending | Pekerjaan belum dilakukan dalam rencana ini | Acceptance dan dependensi |
| blocked | Input/akses yang diperlukan belum tersedia | Blocker spesifik dan bukti |
| runtime_validated | Alur telah ditelusuri pada deployment tertentu | Image, waktu, request, DB, UI |
| accepted | Acceptance fungsional, regresi, beban, dan rollback lulus | Evidence manifest lengkap |

Status source, test, deployment, dan data harus dicatat terpisah. Adanya fungsi
atau tes lulus tidak membuktikan data produksi muncul. Checkbox dicentang hanya
untuk pekerjaan yang benar-benar telah dilakukan, bukan karena pernah diminta.

## 3. Baseline yang diperiksa

- [x] Worktree awal bersih; HEAD `b4d3eb1`.
- [x] Membaca jalur pipeline, taxonomy, telemetry contract, automation,
  provenance AI, entity resolver, case store, exposure, workflow policy,
  collector, entrypoint frontend, Compose, dan pengujian terkait.
- [x] Menjalankan 96 tes lokal yang tercantum di bagian 14; seluruhnya lulus.
- [x] Mencoba `docker compose -f mcp-dashboard/docker-compose.dashboard.yml ps`.
  Hasil: permission denied ke Docker socket.
- [x] Memastikan image/source yang sedang melayani browser sama.
- [x] Mengambil payload runtime terautentikasi, metrik beban, dan hasil DB.
- [x] Membuktikan Security Findings tampil di browser runtime.
- [ ] Memastikan collector dan cursor bergerak pada dua pengamatan runtime.

Audit ini tidak membaca seluruh file repo baris demi baris, tidak menjalankan
seluruh tool, dan tidak membuktikan keamanan/kebenaran semua fitur. Area di atas
adalah jalur yang diperiksa untuk menyusun rencana. Angka lama dari percakapan
(jumlah incident, observation, tool, bucket, atau backlog) bukan baseline live.

## 4. Inventaris implementasi: pakai kembali sebelum menambah

| Komponen | Bukti source | Kondisi yang terbukti dan batasnya |
| --- | --- | --- |
| Pembaca alert | [soc_pipeline.py](mcp-dashboard/soc_pipeline.py), `Pipeline.scan_window` | Membaca `wazuh-alerts-*` lewat scroll; initial 24h, window terbatas, overlap/replay; bukan seluruh arsip syslog |
| Commit window | `Pipeline._commit_scan_window` | IOC, rollup, ledger batch dan checkpoint memiliki jalur transaksi; alur overflow entity perlu audit crash tersendiri |
| Rollup historis | `backfill_once`, `rollup_summary`, `rollup_gaps` | Ada completion ledger; agregasi term dibatasi dan detail tidak sama dengan ringkasan |
| Worker rollup | [materializer.py](mcp-dashboard/materializer.py), [Compose](mcp-dashboard/docker-compose.dashboard.yml) | Service terpisah, satu replica, default 1 CPU/768m; runtime belum diverifikasi |
| Background enrichment/AI | [soc_automation.py](mcp-dashboard/soc_automation.py), `Automation.start`, `loop`, `build` | Berjalan dari proses dashboard; materializer hanya memulai pipeline. External collector, grouping, AI, delivery bukan otomatis pindah ke materializer |
| Arsip syslog | [upgrade-device-splitter.sh](integration/upgrade-device-splitter.sh) | Skrip menghasilkan reader inode/offset dan file per-device; tidak membuktikan instalasi aktif, exactly-once, atau integrasi deteksi |
| Syslog tool | [host_forensics.py](infokom-analysis/mcp_server/tools/host_forensics.py), `blueteam_read_syslog` | Pembacaan tail on-demand; bukan intake semua log |
| Klasifikasi serangan | [detection_taxonomy.py](mcp-dashboard/detection_taxonomy.py), `classify` | 11 family; memilih kecocokan pertama dari label/rule dan sinyal Forti tertentu; bukan engine behavioral lengkap |
| Readiness sumber | [telemetry_contract.py](mcp-dashboard/telemetry_contract.py), `summary` | Lima status sudah ada; threshold field 80%, freshness dan gap; profil masih terlalu umum untuk beberapa subtype |
| Entity graph | [entity_resolver.py](mcp-dashboard/entity_resolver.py) | Canonical nodes, evidence, relations, queue, candidate grouping, timeline sudah ada |
| Granularitas evidence | `prepare_wazuh_evidence` | Evidence Wazuh dipilih dan dikelompokkan berdasarkan bucket 5 menit, rule, signature entitas; bukan satu row untuk setiap raw event |
| Persistent case | [case_store.py](infokom-analysis/mcp_server/core/case_store.py) | SQLite WAL, migration JSONL, revision guard, evidence/notes/assignments/audit dan lifecycle sudah ada; jangan membuat case store kedua |
| Case API/UI | [server.py](mcp-dashboard/server.py), `_incident_mutate`, `_sync_finding_case` | List/create/get/timeline/action serta AI advisory linking ada; validasi end-to-end masih diperlukan |
| CMDB/CVE | [cve_exposure.py](mcp-dashboard/cve_exposure.py), [sync_cmdb_inventory.py](tools/sync_cmdb_inventory.py) | Normalisasi dan inventory sync ada; owner/zone/CPE/patch nyata tidak boleh diisi dengan tebakan |
| CVE summary | `server._materialize_cve_exposure` | Materialisasi sudah ada; audit join dan kelengkapan per field, bukan membuat graph baru |
| Defender | [defender_xdr.py](mcp-dashboard/defender_xdr.py), `collect`, `correlate`, `history` | Jalur incident dan alert, ledger/checkpoint/korelasi ada; permission dan record runtime perlu diuji |
| CYFIRMA | [cyfirma_taxii.py](mcp-dashboard/cyfirma_taxii.py), [Org CVE](mcp-dashboard/cyfirma_org_vulnerability.py), [research](mcp-dashboard/cyfirma_research.py) | Collector TAXII/Org CVE/research sudah ada; entitlement, collection, pagination dan coverage belum tervalidasi sesi ini |
| Status provider | `server._annotate_finding_intel_status`, `_provider_health_record` | Status cache/error/skip dan circuit health ada; audit semantik response dan alias provider |
| AI | [soc_contract.py](mcp-dashboard/soc_contract.py), `normalize_ai_result`, `normalize_finding_ai_result` | Contract `senior-soc-ai/1.0.0`, fallback dan provenance validators ada; semantic support masih `not_assessed` |
| Audit AI | `_window_audit_metadata`, `_finding_audit_metadata` | Model/configured model, skill/contract, prompt/input hash, evidence refs ada; traceability hasil truncation perlu diperiksa |
| Workflow tools | [soc_workflows.py](mcp-dashboard/soc_workflows.py), `policy`, `Workflows` | Klasifikasi automatic/guided/on_demand/approval_required, cache dan antrean ada; klasifikasi bukan bukti eksekusi |
| Security Findings | [findings.js](mcp-dashboard/static/findings.js), [app.js](mcp-dashboard/static/app.js), [index.html](mcp-dashboard/static/index.html) | Initialization guard, fallback dan renderer ada; laporan browser rusak belum ditutup dengan bukti runtime |

Dokumen lama [AUDIT_PRIORITIES.md](mcp-dashboard/AUDIT_PRIORITIES.md) memuat gap
case pagination/concurrency yang sudah memiliki implementasi di baseline ini.
[RETENTION.md](mcp-dashboard/RETENTION.md) memuat deskripsi interval replay yang
harus dibandingkan dengan konfigurasi efektif. Jangan menyalin status lama
sebagai kebenaran runtime. Perbarui dokumen spesifik setelah gate terkait lulus.

## 5. Prinsip arsitektur dan kepemilikan data

1. Pertahankan Wazuh sebagai pemilik alert/index existing. Jangan menyalin seluruh
   raw index ke SQLite dashboard atau mengubah collector lama tanpa baseline.
2. Sumber non-alert memerlukan satu intake yang terukur; identifikasi dahulu
   apakah sudah tersedia lewat index, arsip JSON, forwarder, atau splitter.
3. Gunakan normalisasi/provenance bersama. Tool atau parser baru tidak boleh
   membuat identitas IP/user/asset dan case store yang bersaing.
4. Jalankan detection pack terhadap stream yang dibaca sekali dan state lokal.
   Hindari satu full scan Indexer per family per interval.
5. SQLite existing menyimpan metadata, state, temuan, evidence terpilih dan hasil.
   Kebutuhan event store tambahan harus melalui keputusan retensi/kapasitas G03.
6. Tidak ada transaksi lintas DB yang diasumsikan atomic. Gunakan outbox/retry
   idempotent untuk handoff ke case store jika dibutuhkan.
7. Pencocokan feed lokal boleh menjangkau observables yang tersimpan secara
   bertahap. External provider dibatasi quota; ketertundaan tetap terlihat.
8. AI memakai finding/case terpilih. Perubahan bukti signifikan membuat versi
   analisis baru; refresh menu tidak memulai analisis ulang.
9. Gunakan modul existing sebagai pemilik fungsi. Modul baru diperbolehkan untuk
   batas baru seperti intake/detector, dengan API kecil dan dependency eksplisit.
10. "Automatic" pada katalog saat ini dapat berarti `overview_refresh`, bukan
    scheduled background. Audit trigger nyata sebelum mengubah orkestrasi.

## 6. Peta gap yang perlu diprioritaskan

| ID | Prioritas | Temuan/batas | Dampak dan gate |
| --- | --- | --- | --- |
| R01 | P0 | User melaporkan Findings gagal init; source mempunyai error guard, belum ada validasi browser sesi ini | Pulihkan visibilitas dulu, G00 |
| R02 | P0 | Image/worker/API/DB runtime belum dapat diperiksa | Klaim deploy dan coverage tidak dapat dibuat, G00-G01 |
| R03 | P0 | Scope scan saat ini hanya alert index | Non-alert syslog belum otomatis dianalisis, G01-G03 |
| R04 | P1 | Source readiness memakai daftar field universal; Sysmon process dan network event tidak selalu memiliki field sama | Readiness per event subtype/detection prerequisite, G02 |
| R05 | P1 | `classify` first-match; malware selalu menambahkan `hash_or_process_evidence` | Uji classification dan field checks; jangan menyebut taxonomy detector penuh, G04 |
| R06 | P1 | Historical top terms dan evidence coalescing bersifat terbatas | Tidak boleh merekonstruksi relasi src/dst/user dari histogram terpisah, G02/G06/G08 |
| R07 | P1 | `_ioc_values` TAXII menggunakan pola sederhana `object:value = '...'` | Hash seperti `file:hashes.'SHA-256'` dan pattern kompleks perlu parser/test; G05 |
| R08 | P1 | Semantic support AI belum dinilai | ID valid tidak menjamin narasi benar; G07 |
| R09 | P1 | Entity overflow dapat enqueue sebelum commit scan utama | Uji crash/replay/visibility untuk mencegah evidence partial dan count ganda; G02/G06 |
| R10 | P1 | Tool UI smoke test lama mencari kategori `cyfirma`; categories Findings sekarang tidak memuatnya | Perbaiki test sesuai menu pemilik data, jangan memulihkan panel salah hanya demi test; G00/G08 |

R04-R09 adalah risiko/batas yang terlihat dari source, bukan klaim insiden produksi.
P0 mendahului perluasan deteksi. Setiap gate berikut memiliki satu hasil yang
dapat direview, batas perubahan, tes gagal/lulus, dan jalan rollback.

## 7. Urutan task dan gate

G00 memiliki subtask frontend **runtime_validated**, tetapi belum **accepted**
secara penuh karena blocker runtime yang ditemukan pada audit penutup. G01-G09
masih **pending**. Pemeriksaan lokal bagian 3 tidak menyelesaikan acceptance
runtime. Dependency utama:
`G00 -> G01 -> G02 -> G03 -> G04 -> G05 -> G06 -> G07 -> G08 -> G09`.
G05/G06 boleh diaudit lebih awal; jangan menyatakan alur keseluruhan diterima
sebelum bukti input, deteksi, dan hubungan datanya stabil. Masalah display yang
memblokir tahap mana pun dikembalikan ke G00, bukan ditunda sampai G08.

### G00 / P0: Baseline deployment dan pulihkan pembacaan Findings

Pemilik: `server.py`, `static/app.js`, `static/findings.js`, `static/index.html`,
Dockerfile/Compose; gunakan `tools/check_dashboard_deploy.sh` sebagai awal.

- [x] Rekam source commit, image ID/digest, build ID, container start, worker,
  volume DB, konfigurasi non-secret dan waktu pengamatan.
- [x] Bandingkan hash aset host/image/HTTP yang benar-benar dimuat browser.
  Periksa status HTTP, MIME, auth, cache, script order, first JS exception,
  global helper, DOM target dan event `soc:overview`/`soc:view`.
- [x] Telusuri satu window: request -> API payload -> data shape -> buildRows ->
  DOM. Simpan payload tersanitasi; bedakan exception dari query lambat.
- [x] Reproduksi satu bug sebelum patch. Tambah tes browser yang gagal pada
  baseline bug dan lulus setelah patch. Tes string source tidak mencukupi.
- [x] Pulihkan data existing dan grafik tanpa redesign/menu baru. Range berubah
  harus menolak response lama yang datang terlambat.
- [x] Uji cold/warm cache, auth gagal, API gagal, payload null/partial, direct
  URL, refresh, back/forward, 24h/7d/30d/custom, desktop/mobile.

Acceptance: tidak ada exception tak tertangani; response berisi temuan benar-benar
tampil; loading berakhir pada data/empty/error dengan alasan; data stale berlabel;
grafik existing tetap render. Gagal endpoint tidak menyapu seluruh menu menjadi
nol. Screenshot + network trace tersanitasi + build identity wajib tersedia.

Rollback: simpan image/aset baseline yang teridentifikasi; kembalikan patch UI/API
secara terarah jika regresi. Jangan reset repo atau menghapus DB. Jangan
menyatakan rollback image sebagai rollback schema.

#### Eksekusi G00: 2026-09-25 UTC

Scope: pemuatan Security Findings, isolasi response per rentang, error/retry,
preservasi last-good snapshot, dan verifikasi grafik existing. Tidak menambah
detector, mengubah decoder, schema, credential, case store, atau quota provider.

**Bukti sebelum patch**

- Source baseline `b4d3eb1` + working-tree patch; belum dibuat commit baru.
- Pada runtime patch10, `SocFindings.ready` sudah true dan 188 record agregat
  ditampilkan. Error inisialisasi pada screenshot patch9 lama tidak tereproduksi;
  tidak diklaim bahwa penyebab screenshot lama sudah ditemukan.
- Lima tes browser awal: satu lulus, empat gagal. Kegagalan terbukti: response
  24h terlambat menimpa 7d; overview 503 meninggalkan loading; refresh gagal
  tanpa peringatan di Findings; dependency 401 menimbulkan unhandled rejection.
- Pengujian diperluas menjadi 10 skenario. Kasus tambahan mencakup null/partial,
  timeout/retry, coverage lama, route/reload/back-forward dan mobile. Ditemukan
  pula overflow teks scope pada lebar 390px; aturan flex diperbaiki terbatas.

**Perubahan dan pengujian**

- `app.js`: request generation/window guard, timeout terbatas untuk pembacaan
  overview/settings/tools, response decoder yang menangani non-JSON error,
  serta status pemuatan eksplisit. Semua dependency rejection ditangani segera.
- `findings.js`: loading/error berakhir jelas; snapshot terakhir pada rentang
  sama dipertahankan saat refresh gagal. `analysis-workspace.js` menolak coverage
  dari rentang lama. Tidak mengganti grafik atau kategori temuan.
- `check_findings_ui.py`: autentikasi dari env, endpoint allowlist pembacaan,
  hash/MIME, rentang, viewport, grafik dan artefak private. Tab CYFIRMA usang
  tidak lagi dijadikan syarat; smoke test tidak menekan AI atau lookup provider.
- **153 tes lokal lulus**: `python3 -m unittest test_frontend_lifecycle
  test_style_isolation test_findings test_detection_improvements
  test_entity_resolver test_soc_pipeline test_cve_exposure` dari `mcp-dashboard`.
- **10 tes browser lulus** menggunakan aset nyata dan API fixture terisolasi:
  `../.ui-check/bin/python -m unittest test_browser_findings`.
- Cold/warm browser state dan failure injection diuji dalam fixture. Cache DB
  produksi tidak dikosongkan untuk memaksakan kondisi cold.

**Deployment dan bukti runtime**

- Dashboard saja dibangun/recreate, start `2026-09-25T22:07:08.112799379Z`,
  build `2026-09-25-patch11`, image
  `sha256:e3fca3a797d1f309dbff9aed300ac9aecb79c9e03eab634a998b1309d5fa53e2`.
- Rollback tag `wazuh-mcp-dashboard:g00-before-patch11` menyimpan image sebelumnya
  `sha256:bd4652cf1bdd4b050c83f2657395c7a53ba3dd22f0ee4617522be65b5735dd74`.
- Materializer tidak direstart; image
  `sha256:08310d9b9197162140e568337f997b53dca00b99aa30364686ded4a47023c1d6`,
  start tetap `2026-09-25T12:26:53.372682423Z`. Pipeline/automation/entity source
  cocok; `server.py` hanya berbeda build constant. Aset UI lama di worker tidak
  melayani HTTP. Tidak ada perubahan Wazuh Manager/Indexer/INFOKOM.
- Volume tetap `wazuh-mcp-dashboard_soc-automation` di `/app/runtime`.
  Dashboard worker flag false, materializer true; limit worker 1 CPU/768 MiB.
  Tidak ada migrasi schema atau reset checkpoint/DB/cache.
- Server/aset di image cocok dengan source. Lima aset HTTP cocok byte-for-byte
  dengan source dan MIME tepat; tanpa autentikasi HTTP 401, dengan autentikasi
  HTTP 200. Bukti source-image dan source-HTTP diperiksa terpisah.
- Dua smoke run berhasil, terakhir mulai `2026-09-25T22:09:31Z`. 24h/7d/30d/custom
  masing-masing menampilkan 189/229/270/128 record agregat saat diperiksa;
  masing-masing 12 row pada halaman pertama dan 12 tombol AI. Custom memakai
  2026-09-23 00:00 sampai 2026-09-24 00:00 UTC. Ini bukan total semua raw alert.
- Tidak ada exception browser atau percobaan endpoint di luar allowlist.
  Trend SVG dan empat severity bar tetap ada, screenshot diperiksa; viewport
  1440/1024/768/390 tidak memiliki horizontal overflow.
- Bukti private ignored: `mcp-dashboard/artifacts/g00-20260925T220931Z/` berisi
  `summary.json` (status/path/hash/count, tanpa payload mentah) dan screenshot.
  Artefak juga dikecualikan dari Docker build context.

**Blocker dan batas yang belum selesai**

1. Lock watchdog yang ditemukan pada patch11 sudah dipatch pada patch12/13.
   Siklus yang gagal sekarang dicatat `degraded`, thread tidak berhenti, dan
   siklus berikutnya dapat kembali `ok`. Writer penyebab contention historis
   belum diisolasi; tidak ada lock baru pada pengamatan runtime patch13.
2. Snapshot 7d/30d masih `stale-refreshing`; custom `building` pada smoke run.
   Temuan tersedia tidak membuktikan materialisasi lengkap. Angka build dalam
   snapshot historis bisa patch9/10 walaupun image/aset aktif patch11. Bedakan
   identitas snapshot dan identitas service pada audit berikutnya.
3. Settings/pipeline status belum selesai pada sebagian capture browser;
   endpoint tersebut belum dinyatakan runtime sehat. Telusuri latency dan
   contention bersama blocker DB sebelum menambah pekerjaan background.
4. Statistik Docker satu pengamatan bukan benchmark: dashboard sekitar 166 MiB
   dan 24.59% CPU; worker 42 MiB dan 1.41% CPU. Baseline latency/beban pembanding
   belum ada, sehingga tidak ada klaim kapasitas atau optimasi performa produksi.
5. Restore image belum diuji dengan rollback produksi; semua menu/tool, isi
   detail historis, collector cursor dan AI semantic support belum diaudit ulang.

#### Follow-up G00: lock recovery dan cache identity, 2026-09-25 UTC

- `soc_automation.py` menambahkan state watchdog (`status`, `last_run`,
  `last_success`, `last_error`, `lock_events`) pada payload `findings/ai-jobs`.
  `sqlite3.OperationalError` bertipe lock tidak lagi mematikan thread; error
  non-lock juga ditandai dan tidak dianggap sukses.
- Tes recovery menggunakan temporary worker dan fault injection lock: status
  `degraded` pada siklus pertama, lalu `ok` pada siklus berikutnya. Suite penuh
  setelah perubahan: **199 tests, OK**.
- Build/deploy dashboard patch13: image
  `sha256:0ebc4a2e71edaa30a99ec1e265a21c8d053494604b8c0018781882db1de7821`,
  container baru dibuat pada `2026-09-25T22:30:18Z`; materializer tetap tidak
  direstart. Backup image `wazuh-mcp-dashboard:g00-before-patch13` dibuat.
- Setelah lebih dari satu interval watchdog: status `ok`, `lock_events=0`,
  queued/processing `0/0`, completed `17`, failed `0`; log tail baru memiliki
  `0` traceback dan `0` pesan `database is locked`.
- Cache overview lama tidak dihapus. `server.py` sekarang menyajikan
  `service_build_id=2026-09-25-patch13` dan mempertahankan `snapshot_build_id`
  bila snapshot lama berasal dari patch sebelumnya. Ini memperbaiki provenance
  identitas tanpa memaksa requery atau mengubah data snapshot.
- Smoke runtime terakhir `check_findings_ui.py --screenshots` lulus untuk
  24h/7d/30d/custom. Semuanya `load_status=ready`, 12 row halaman pertama,
  12 kontrol AI, grafik tren dan 4 severity bar; HTTP API 200, browser error 0,
  blocked action 0, dan overflow desktop/mobile 0.

#### Follow-up G00: startup schema race lintas proses, 2026-09-26 UTC

- [x] Audit ulang setelah runtime patch14 menunjukkan race yang terbukti:
  proses dashboard/probe baru mengimpor `server`, sementara materializer sedang
  menulis migrasi schema; hasilnya `sqlite3.OperationalError: database is locked`
  pada `cyfirma_research.ensure_schema()`. Pada pengamatan itu dashboard sempat
  restart 2 kali. Materializer tidak restart dan data tidak dihapus.
- [x] Patch minimal di `soc_automation.py`: schema yang sudah lengkap diverifikasi
  dengan query read-only; hanya schema/migrasi yang kurang yang dijalankan.
  Jalur migrasi langka diserialisasikan dengan lock file di volume runtime dan
  retry bounded khusus error SQLite lock. Error lain tetap dilempar, sehingga
  tidak ditutupi sebagai readiness palsu.
- [x] Tambah regression test untuk lock transient, recovery collector, dan
  scheduler boundary. Suite terpilih terakhir: **202 tests, OK**; `py_compile`
  dan `git diff --check` juga lulus.
- [x] Deploy terkontrol build `2026-09-26-patch16`, image
  `sha256:152e50c89d8a09542ebfc3a7c30be773b75a30625fcebdcee5fd84e3d3e15126`.
  Backup image sebelum deploy disimpan sebagai
  `wazuh-mcp-dashboard:g01-before-patch16`. Hanya `mcp-dashboard` dan
  `mcp-materializer` direcreate; Wazuh, Indexer, INFOKOM, volume, checkpoint,
  dan database tidak direset.
- [x] Runtime setelah deploy: kedua container `restart=0`, build ID patch16
  cocok pada kedua service, deploy audit lulus, case DB WAL `quick_check=ok`,
  CMDB 14 asset authoritative, pipeline `caught_up`, backfill lengkap tanpa
  failure, dan log baru tidak memiliki traceback/database lock.
- [x] Browser smoke patch16: 24h/7d/30d/custom `load_status=ready`, masing-masing
  12 row + 12 kontrol AI, endpoint yang diuji HTTP 200, browser error 0,
  blocked action 0, trend SVG 1, severity bar 4, dan overflow 0 pada
  1440/1024/768/390. Hasil 24h/7d/30d/custom: 191/228/269/143 record agregat
  pada halaman pertama. Ini bukan jumlah semua raw alert.
- [x] Warning `overview.errors.statistics` ditutup pada patch17: endpoint
  statistik manager yang mengembalikan HTTP 400 tidak lagi dipanggil bila
  agregasi alert lokal untuk window live berhasil. Jalur manager tetap menjadi
  fallback bila agregasi lokal gagal, sehingga kegagalan nyata tetap terlihat.
  Historis tetap memakai rollup tanpa fetch statistik live.

#### Follow-up G00: sumber hourly dan verifikasi range, 2026-09-26 UTC

- [x] Root cause terbukti pada runtime: `_local_alert_window()` berhasil
  menyediakan agregasi dan timeline, tetapi `_overview()` selalu memanggil
  `get_wazuh_statistics`; Wazuh Manager membalas HTTP 400 dan error opsional
  itu masuk ke `overview.errors`, walaupun Findings tetap dapat dirender.
- [x] Patch minimal di `server.py`: `_overview_statistics()` memilih sumber
  `local_alert_timeline` saat agregasi lokal sehat, `historical_rollup` untuk
  rentang historis, dan hanya memanggil manager statistics sebagai fallback
  jika agregasi lokal gagal. Tidak ada query Indexer tambahan atau perubahan
  schema/provider/cache/checkpoint.
- [x] Label UI diubah dari `Manager statistics` menjadi `Hourly activity
  source`, karena chart memang sudah fallback ke timeline lokal.
- [x] Checker browser diperbaiki agar hash navigation menunggu
  `overview.window.range` dan `overviewLoad.windowKey` milik range yang sedang
  diuji; ini menutup false failure dari status `ready` range sebelumnya.
- [x] Suite Findings/lifecycle: **84 tests, OK**. Full discovery:
  **255 tests, OK (10 skipped)**; `py_compile` dan `git diff --check` lulus.
- [x] Deploy terkontrol build `2026-09-26-patch17`. Rollback image
  `wazuh-mcp-dashboard:g00-before-patch17` disimpan sebelum recreate. Hanya
  `mcp-dashboard` dan `mcp-materializer` direcreate; Wazuh, Indexer, INFOKOM,
  volume, database, cache, dan checkpoint tidak direset.
- [x] Runtime API terautentikasi: `build_id/service_build_id=patch17`, 24h
  alert status `available`, total `3,380,550`, dan `errors={}`. Payload tidak
  mengklaim manager statistics tersedia; chart membaca timeline lokal.
- [x] Browser smoke nyata: 24h/7d/30d/custom semuanya `ready`, 12 row + 12
  kontrol AI, HTTP 200, browser error 0, blocked action 0, asset parity cocok,
  trend SVG 1, severity bar 4, dan overflow 0 pada 1440/1024/768/390.
  Satu respons 7d memuat `local_index_aggregation` sebagai error source dan
  tetap menampilkan data dengan status yang terlihat; itu belum dipromosikan
  menjadi data lengkap.

#### Follow-up G00: isolasi seed rollup saat startup, 2026-09-26 UTC

- [x] Reproduksi patch18: import probe dashboard gagal pada seed
  `rollup_windows` dengan `sqlite3.OperationalError: database is locked` saat
  materializer aktif. Ini bukan kehilangan data; kegagalan terjadi pada write
  idempotent saat `Pipeline` diimpor.
- [x] Patch19 di `soc_pipeline.py`: seed dipisahkan dari schema setup, didahului
  pemeriksaan read-only. Jika ledger sudah berisi baris atau tidak ada legacy
  rollup yang perlu dipindahkan, write dilewati. Hanya migrasi yang benar-benar
  perlu yang memakai retry lock terbatas. Test transient-lock ditambahkan.
- [x] Suite jalur pipeline/automation/Findings: **149 tests, OK**; full discovery
  terakhir **257 tests, OK (10 skipped)**; `py_compile` dan `git diff --check`
  lulus setelah patch19.
- [x] Deploy patch19: image aktif
  `sha256:1bd0a2448bdf56b5948179b04bdd2bb56230d9bee1ca381a8d439b3228ef8577`,
  rollback `wazuh-mcp-dashboard:g01-before-patch19`. Hanya dashboard dan
  materializer direcreate; kedua container `restart=0`; import probe mencetak
  `import ok` pada dua percobaan.
- [x] API 24h terautentikasi: `build_id/service_build_id=patch19`, alert
  `available`, total `3,380,550`, `errors={}`. Browser smoke empat rentang
  lulus: 12 row + 12 kontrol AI, HTTP 200 untuk alur utama, browser error 0,
  chart trend/severity ada, asset parity cocok, dan overflow 0 pada semua
  viewport yang diuji.
- [ ] Deploy check penuh belum lulus: probe `pipeline.status()` dan
  `external_intelligence_status()` melewati timeout 20 detik ketika worker
  aktif; probe dihentikan agar tidak menggantung. Ini adalah temuan performa
  status/ledger yang terukur, bukan dipromosikan menjadi health.
- [ ] Smoke juga merekam HTTP 500 berulang pada `/api/intelligence/cyfirma`.
  Findings tetap tampil, tetapi query ledger CYFIRMA perlu bounded read,
  error contract, dan observability terpisah sebelum provider dinyatakan siap.

#### Follow-up G00: bounded runtime status dan ledger error contract, patch20, 2026-09-26 UTC

- [x] Root cause patch20 dibuktikan dari probe runtime: `Pipeline.status()` dan
  `external_intelligence_status()` melakukan pembacaan detail yang dapat
  menunggu transaksi materializer; status probe melewati 20 detik. Ini bukan
  kehilangan rollup atau ledger.
- [x] Patch minimal menambah koneksi SQLite `read_db()` bounded, read-only,
  `query_only`, tanpa schema migration. Mode `lightweight` pada pipeline,
  automation, dan external intelligence hanya dipakai oleh health route/deploy
  check; kontrak detail lama tetap tersedia untuk pembacaan pemilik data.
  Timeout dikembalikan sebagai `degraded/unavailable` dengan `reason`, bukan
  angka nol atau status `ready` palsu.
- [x] Endpoint `/api/pipeline/status` dan `/api/automation/status` sekarang
  memakai snapshot bounded. `/api/intelligence/cyfirma` mempertahankan HTTP
  200 dengan payload `status=unavailable` bila ledger error, sehingga provider
  error tidak disamarkan sebagai `no_match`; data sukses tetap berasal dari
  ledger lokal dan `provider_calls=0`.
- [x] Regression tests ditambahkan untuk bounded status, status scope, detail
  omission, dan fallback; full discovery menghasilkan **259 tests, OK
  (10 skipped)**. `py_compile` dan `git diff --check` lulus.
- [x] Deploy patch20: dashboard dan materializer sama-sama memakai build
  `2026-09-26-patch20`; tidak ada reset volume, SQLite, cache, checkpoint,
  Wazuh, Indexer, atau INFOKOM. Deploy check penuh lulus: shared-code parity,
  runtime build identity, import, CMDB, case DB WAL, dan worker.
- [x] Runtime retained state: CMDB 14 authoritative assets, Defender 92
  durable observations, CYFIRMA organization vulnerability 1.091 observations
  dengan cursor `partial`, research 25 item `stored`, rollup complete,
  pipeline `caught_up`, lag 158 detik pada saat probe.
- [x] Endpoint terautentikasi: pipeline status HTTP 200 dengan
  `status=ok/status_scope=bounded_runtime_snapshot`; CYFIRMA history HTTP 200,
  5 item, `provider_calls=0`; tidak ada 500 pada validasi ulang.
- [x] Browser smoke kedua: 24h/7d/30d/custom `load_status=ready`, masing-masing
  12 row + 12 kontrol AI, endpoint read-only HTTP 200, browser error 0,
  blocked action 0, trend SVG 1, severity bar 4, dan overflow 0 pada
  1440/1024/768/390. Percobaan pertama menangkap race 30d dengan status
  `loading`, tetapi pengulangan lulus; dicatat sebagai residual cache-refresh
  observability, bukan dianggap data hilang.
- [ ] G00 belum dinyatakan accepted untuk semua fitur: TAXII tetap `not_started`
  karena belum ada cursor/observasi runtime, telemetry WAF/Sysmon/auditd/NDR
  tetap harus dibuktikan dari event nyata, dan seluruh tool/provider belum
  terbukti callable/executed/rendered. Ini adalah pending evidence, bukan bug
  yang boleh ditutup dengan label UI.

#### Follow-up G01: measured source/subtype inventory dan cache schema refresh, patch21, 2026-09-26 UTC

- [x] Root cause tambahan dibuktikan setelah deploy: snapshot overview lama masih
  dapat diberi `build_id` service terbaru walaupun belum memiliki field additive
  `telemetry_contract.inventory_evidence`. Ini membuat renderer baru tidak
  memperoleh bukti inventory, walaupun data alert lama tetap ada.
- [x] Patch additive menambahkan `inventory_evidence` dari dimensi rollup yang
  sudah ada. Isinya source matrix, status/field coverage, subtype Forti,
  detection family, ukuran sample bounded, dan batasan timestamp. Tidak ada
  query Indexer tambahan, provider call, schema DB baru, reset cache, atau
  perubahan enum readiness.
- [x] Status yang belum mempunyai kontrak sumber diberi label eksplisit:
  `parser_version=not_observed`, `received_vs_indexed=unavailable`, dan
  `late_events=unavailable`. `unmatched_decoder` hanya memakai arti
  `decoder.name` tidak ada; tidak disebut sebagai kegagalan manager.
- [x] Cache lama tidak dihapus. Pembacaan mendeteksi ketiadaan
  `inventory_evidence`, mempertahankan snapshot last-good, memberi status
  `stale-schema-refreshing`, lalu menjalankan refresh background. Regression
  test mengunci perilaku ini.
- [x] UI Settings > Telemetry Readiness menampilkan detail terlipat untuk
  inventory source/subtype agar tidak menggandakan kartu Command Center atau
  Findings. Grafik dan kontrol yang ada tidak dihapus.
- [x] Full discovery setelah patch: **261 tests, OK (10 skipped)**;
  `py_compile` dan `git diff --check` lulus. Test validasi helper mengunci
  subtype terukur serta metadata yang tetap `unavailable`, bukan zero.
- [x] Deploy terkontrol: dashboard dan materializer sama-sama build
  `2026-09-26-patch21`, image digest
  `sha256:0236ec84e5df52b51017f329c357450f1c3fbd0cd6aabd4fc707c4a924636705`;
  CMDB, case DB WAL, checkpoint, rollup, Wazuh, Indexer, dan INFOKOM tidak
  direset. Backup image sebelum patch tetap diberi tag
  `wazuh-mcp-dashboard:g01-before-patch21`.
- [x] Runtime 24h terautentikasi: HTTP 200, build patch21,
  `inventory_evidence=measured`, indexed events `3,265,847`, subtype rollup
  `forti_type=2`, `forti_subtype=5`, `forti_profile=11`, dan
  `detection_family=4`; parser/ingest/late status tetap jujur unavailable.
  `pipeline= caught_up` dan materializer tetap running pada deploy check.
- [ ] Browser smoke untuk perubahan patch21 belum dijalankan karena host saat
  ini tidak memiliki modul Python Playwright. Static asset parity dan HTTP/API
  runtime sudah dicek; rendering visual patch21 tetap `runtime_unverified`.
- [ ] G01 belum accepted penuh: trace event individual dari ingress sampai UI,
  parser version, received-vs-indexed denominator, late-event counter, dan
  rate/resource/lock baseline masih membutuhkan kontrak telemetry/ingestion
  yang belum ada. Subtype rollup bukan bukti raw-event trace atau keberhasilan
  serangan.

#### Follow-up G01: bounded Indexer-to-UI trace dan schema refresh, patch23, 2026-09-26 UTC

- [x] Patch additive menambahkan trace bounded dari record L1 yang benar-benar
  dikembalikan oleh agregasi Wazuh Indexer ke payload overview. Setiap record
  membawa `event_id`, index, timestamp, rule ID, decoder, agent, dan alamat
  source/destination bila tersedia. Batasnya 20 record dan scope-nya eksplisit;
  ini bukan salinan raw log dan bukan bukti ingress syslog sebelum Indexer.
- [x] Cache schema sekarang menganggap snapshot lama tidak lengkap bila
  `telemetry_contract.inventory_evidence.index_to_ui_trace` belum ada, termasuk
  snapshot yang sudah memiliki `inventory_evidence`. Snapshot last-good tetap
  dikembalikan sambil refresh background berjalan; cache tidak dihapus.
- [x] Regression coverage mencakup legacy snapshot tanpa inventory dan snapshot
  patch21 yang inventory-nya ada tetapi trace-nya belum ada. Kedua kasus wajib
  mempertahankan data alert lama dan memulai refresh.
- [x] Full discovery setelah regresi: **262 tests, OK (10 skipped)**;
  `py_compile` dan `git diff --check` lulus.
- [x] Deploy terkontrol: dashboard dan materializer memakai build
  `2026-09-26-patch23`, image digest
  `sha256:460f75762b4b24b3cc7c51bbed94ecdb2db73ebc21200524d23b3a87da0c4b7f`;
  tidak ada reset volume, cache, checkpoint, SQLite, Wazuh, Indexer, atau
  INFOKOM. Backup image sebelum deploy tetap bertag
  `wazuh-mcp-dashboard:g01-before-patch23`.
- [x] Runtime sesudah deploy terautentikasi: overview 24h HTTP 200, service
  build `2026-09-26-patch23`, cache `hit`, `index_to_ui_trace.status=measured`,
  20 record bounded, dan `l1_queue=20`. Contoh runtime menunjukkan decoder
  `json`, `windows_eventchannel`, dan `fortigate-firewall-v5`; ini hanya bukti
  event tersebut sampai Indexer dan dipetakan ke payload UI.
- [ ] Runtime audit historis setelah deploy belum lulus: pada tiga polling
  berbatas 40 detik, `7d` tetap `stale-schema-refreshing` dengan
  `local_index_aggregation` error, `l1_queue=0`, dan `historical_detail=unavailable`;
  `30d` tetap stale dengan `historical_detail=partial`. Ini berarti refresh
  background belum terbukti selesai, bukan berarti datanya kosong atau lengkap.
  Snapshot last-good tetap dipertahankan; diagnosis berikutnya harus mengukur
  durasi/query contention dan refresh error dari worker, tanpa reset cache.
- [ ] G01 tetap belum accepted penuh. Parser version, received-vs-indexed,
  late-event counter, raw syslog/archive ingress, resource/lock baseline, dan
  bukti telemetry WAF/Sysmon/auditd/NDR yang memenuhi field minimum masih
  pending. Trace terukur tidak boleh dipromosikan menjadi coverage sumber.

#### Follow-up G01: historical refresh bounded to durable rollups, patch24, 2026-09-26 UTC

- [x] Root cause terukur: worker historis memanggil `_overview()`, yang masih
  menjalankan agregasi live Indexer dan enrichment meskipun snapshot cepat sudah
  tersedia dari rollup. Pada runtime, proses dashboard tetap aktif lebih dari
  13 menit dan `7d/30d` tetap `stale-schema-refreshing`; ini tidak membuktikan
  materialisasi selesai dan berisiko menambah beban Indexer.
- [x] Patch minimal mengarahkan worker `7d/30d/custom` ke
  `_materialized_overview()` dari durable local rollup. Worker `24h` tetap
  menggunakan jalur `_overview()` existing. Tidak ada worker/checkpoint/DB
  kedua dan tidak ada perubahan pada schema data atau detector.
- [x] Regression test memastikan refresh historis memanggil rollup dan tidak
  memanggil live overview; seluruh cache last-good tetap dipertahankan.
- [ ] Patch24 belum terdeploy ke container pada sesi ini. Deploy berikutnya
  harus membangun dashboard dan materializer bersama, lalu memverifikasi image
  build, cache 7d/30d menjadi `hit`, `materialization.status=rollup`, dan
  `historical_detail` tetap jujur `partial/unavailable`.
- [ ] Deployment terblokir secara operasional pada sesi ini: Docker socket
  `/var/run/docker.sock` adalah `root:docker` dan akun runtime bukan anggota
  group `docker`; tidak ada perubahan permission atau restart paksa dilakukan.
- [ ] G01 tetap belum accepted sampai deployment patch24 dan dua polling
  runtime membuktikan refresh historis selesai tanpa error, serta gap parser,
  ingress, late-event, resource/lock, dan telemetry sumber tambahan ditutup.

#### Re-audit runtime sebelum patch24 deployment, 2026-09-26 UTC

- [x] Service yang merespons masih `2026-09-26-patch23`; patch24 source belum
  masuk image aktif.
- [x] `7d` pada patch23 terukur `HTTP 200`, `cache=hit`, trace `measured`,
  `l1_queue=20`, tetapi `historical_detail=partial`; ini bukan bukti seluruh
  detail historis tersedia.
- [ ] `30d` masih `stale-schema-refreshing`, trace belum ada, dan belum dapat
  dipakai sebagai bukti snapshot materialized patch24.
- [ ] `24h` saat probe sedang `stale-refreshing`; tidak digunakan sebagai bukti
  refresh selesai. Tidak ada reset cache atau restart paksa untuk memaksa hasil.

#### Follow-up G01: historical refresh starvation, patch25, 2026-09-26 UTC

- [x] Root cause runtime dibuktikan setelah patch24 deploy: guard global
  `_overview_refreshing` membuat refresh `24h` yang lambat menahan refresh
  `30d`, walaupun refresh historis hanya memakai rollup lokal. `30d` tetap
  `stale-schema-refreshing` pada beberapa polling dan tidak memiliki trace.
- [x] Patch minimal memisahkan state refresh historis dari set refresh live.
  Satu refresh historis tetap serialized; refresh historis boleh berjalan saat
  refresh `24h` aktif karena tidak melakukan query live Indexer. Tidak ada worker
  kedua, perubahan schema, reset cache, atau perubahan checkpoint.
- [x] Regression test memastikan refresh historis tidak ditolak hanya karena
  refresh live sedang aktif, dan refresh historis kedua tetap tidak dijalankan
  bersamaan.
- [ ] Patch25 belum terdeploy. Setelah deploy, validasi `30d` harus menjadi
  `cache=hit` dengan `materialization.status=rollup` dan trace historis tetap
  `not_observed`/bounded sesuai kontrak, bukan dipaksa menjadi detail raw.

Status G00 saat ini: **runtime_validated untuk Findings/dashboard, bounded
status, ledger read path, dan worker startup**, belum `accepted` penuh karena
TAXII/telemetry sumber tambahan dan seluruh tool masih memerlukan bukti runtime.
Status `stale-refreshing`/`building` tetap valid bila materializer sedang
menyelesaikan snapshot; angka itu tidak boleh dibaca sebagai seluruh detail
historis sudah tersedia. G01 sekarang memiliki bukti subtype bounded, tetapi
belum accepted karena trace/parser/ingest/resource baseline masih pending.
Next allowed task: selesaikan gap G01 atau siapkan kontrak G02 hanya setelah
gap tersebut memiliki keputusan berbukti, bukan menambah panel atau detector
tanpa source evidence. Runtime ini stabil.

Rollback terarah (hanya bila regresi; belum dieksekusi):

```bash
docker tag wazuh-mcp-dashboard:g00-before-patch17 wazuh-mcp-dashboard:latest
docker compose -f mcp-dashboard/docker-compose.dashboard.yml up -d --no-deps mcp-dashboard
```

Jangan build ulang sebelum menjalankan rollback tersebut, karena akan menimpa
tag latest dengan source patch. Tidak ada rollback schema yang diperlukan oleh
patch ini. Blocker DB/worker G00 sudah ditangani pada follow-up patch13; gate
berikutnya tetap penyelesaian G01 setelah review bukti, tanpa menganggap
seluruh fitur sudah accepted.

### G01 / P0: Inventory sumber dan matriks coverage nyata

Pemilik: `soc_pipeline.py`, `telemetry_contract.py`, `soc_analysis.py`,
`defender_xdr.py`, konfigurasi/syslog splitter existing.

- [x] Inventaris jalur aktual: perangkat -> transport -> collector -> archive/
  index -> worker -> DB -> API -> menu. Audit runtime 2026-09-25 membuktikan
  worker membaca `wazuh-alerts-*` dan menulis rollup/ledger SQLite; raw syslog
  archive bukan input pipeline ini. Jalur non-alert syslog masih terputus dan
  dicatat sebagai blocker G03, bukan dianggap tercakup.
- [ ] Sampling terbatasi per sumber/subtype, bukan hanya top decoder global;
  ukur jumlah, field valid, timestamp, parser version, fresh/late/unmatched.
  Rollup source/field coverage sudah terbaca, tetapi sampling subtype dan
  parser version belum ada; checkbox tetap pending.
- [x] Ukur FortiGate/FortiWeb/Sangfor/WAF, Windows Security/Sysmon, auditd,
  M365/Entra/Defender, IDS/NDR dan container secara terpisah. Snapshot 24h
  menghasilkan 10 baris kontrak: FortiGate `ready` (3,001,299 event),
  container `observed_incomplete` (6,723), M365 `observed_incomplete`
  (279,257), Defender `observed_incomplete` (3), dan Sangfor/FortiWeb/WAF/
  Sysmon/auditd/IDS-NDR `not_observed`. Status ini berbasis rollup window,
  bukan bukti bahwa sumber yang tidak observed tidak pernah mengirim data.
- [x] Audit splitter aktif secara read-only: unit `wazuh-device-splitter`
  `active/running`, enabled, `Restart=always`, `NRestarts=0`, tanpa error atau
  warning journal 24 jam. Script generated mode 755, state offset
  `6348658666` sama dengan ukuran `archives.json`, dan output berisi 42 file
  untuk 2 device. Kode menangani inode/size rotation; exactly-once dan handoff
  ke `soc_pipeline` belum terbukti, sehingga tidak dianggap intake detection.
- [ ] Pilih beberapa record traceable dari ingress sampai UI; bandingkan alert
  dan archive yang berasal dari event sama.
- [x] Rekam ukuran sample dan denominator. Overview runtime membedakan count
  exact window dari detail bounded: network dan identity masing-masing 12
  record, decoder 18 bucket dari batas 20, dan telemetry source memakai
  `observed_events` serta field coverage per sumber. Parser version dan
  received-vs-indexed denominator belum tersedia, sehingga bagian itu masih
  pending.
- [ ] Bekukan baseline rate, lag, disk I/O, RSS, query latency, DB lock time dan
  backlog pada periode representatif sebelum menentukan kenaikan beban.

Acceptance: tiap sumber memiliki bukti jalur atau blocker spesifik; jumlah
received/indexed/scanned/evaluated bukan satu angka. Laporan tidak menyebut
semua syslog terjangkau bila baru alert index yang terbaca.

Rollback: audit read-only dengan query/time budget; hentikan sampling jika
latensi atau beban melewati batas yang disepakati. Jangan menjalankan crawl
arsip historis penuh untuk membuat baseline.

#### G01 execution evidence: 2026-09-25 UTC

- [x] Source/image parity: `mcp-dashboard` dan `mcp-materializer` sama-sama
  menjalankan build `2026-09-26-patch16`; static assets dan shared Python
  modules cocok byte-for-byte. Sebelum sync, materializer masih memakai image
  lama; image backup `wazuh-mcp-dashboard:g01-before-materializer-sync`
  disimpan sebelum recreate.
- [x] Runtime safety: hanya dua service dashboard direcreate; Wazuh Manager,
  Indexer, INFOKOM MCP, volume runtime, checkpoint, dan database tidak direset.
  Deploy check lulus: CMDB 14 asset authoritative, case DB WAL `quick_check`
  OK, persistent case count 0, dan rollup checkpoint tetap tersedia.
- [x] Pipeline health: `scan_status=caught_up`, lag sekitar 221 detik,
  rollup/backfill coverage 100% pada state runtime, tanpa error/failure pada
  backfill.
  Ini adalah health rollup, bukan bukti semua raw syslog atau seluruh detail
  historis tersimpan.
- [x] Collector state: Defender `ok` dengan 92 observation dan research
  CYFIRMA 25 item pada pengamatan pascadeploy; Org Vulnerability masih
  `error` 401 dan TAXII masih `error` karena URL tidak lolos host allowlist.
  Cursor/entitlement tidak diubah.
- [x] UI regression smoke: 24h/7d/30d/custom masing-masing `load_status=ready`,
  12 row + 12 kontrol AI pada halaman pertama, API 200, browser error 0,
  chart trend 1 dan severity bar 4; viewport 1440/1024/768/390 tanpa overflow.
  Window 24h masih memiliki warning source `statistics`; warning tersebut
  dicatat sebagai gap upstream dan tidak mengubah hasil Findings menjadi nol.
- [ ] Trace ingress-to-UI untuk event individual, subtype parser profile, serta
  rate/resource baseline belum lulus. Splitter sudah diaudit, tetapi outputnya
  belum tersambung ke `soc_pipeline`; G01 belum accepted.

**G01 status: `runtime_validated` sebagian, `accepted` belum.** Bukti ini
menutup inventaris rollup dan deployment parity, tetapi tidak mengesahkan
intake raw syslog, decoder FortiWeb/WAF/Sysmon/auditd/NDR, atau klaim seluruh
jenis serangan. Gate berikutnya yang aman adalah menyelesaikan bukti subtype dan
jalur sumber yang sudah ada sebelum membangun intake baru pada G03.

### G02 / P1: Kontrak event, readiness dan idempotensi

Pemilik: normalisasi existing di `detection_taxonomy.py`, `entity_resolver.py`,
`soc_pipeline.py`. Schema berikut adalah rancangan, bukan API yang sudah live.

- [ ] Definisikan envelope versioned: source/tenant/sensor, source_record_id,
  canonical_event_id, event_time, ingested_at, parsed_at, decoder/parser version,
  evidence locator/hash, event_kind, src/dst/port, device reporter, asset target,
  account, action/outcome, protocol/process/hash/CVE bila tersedia.
- [ ] Per field simpan asal dan status observed/inferred/unavailable serta
  parse failure; string kosong atau nilai malformed bukan field valid.
- [ ] Pisahkan ID sumber dari fingerprint konten. Dua aktivitas identik pada
  waktu berbeda tetap dua event; replay event sama tidak menambah hitungan.
- [ ] Tentukan dedup lintas alert/archive dengan ID asal bila tersedia; jika
  hanya fingerprint heuristik, tandai uncertain dan jangan diam-diam membuang.
- [ ] Profilkan readiness per subtype: Sysmon process/network, firewall traffic/
  IPS, auditd syscall/auth, Defender alert/incident. Tidak semua subtype wajib
  memiliki destination IP atau hash.
- [ ] Ukur completeness field bersama pada event yang sama untuk prerequisite
  detector. Persentase field terpisah tidak membuktikan joint completeness.
- [ ] Pisahkan freshness ingestion sekarang dari kelengkapan window historis.
  Record lama yang sesuai window historis tidak otomatis berarti collector mati.
- [ ] Uji commit/gagal/restart termasuk overflow entity yang sempat diantrekan
  sebelum `_commit_scan_window`, partial shard, timeout, late event dan retry.

Acceptance: tidak ada checkpoint melewati data belum durable; replay tidak
menggandakan finding/evidence; incomplete diketahui; mapping existing tetap
kompatibel lewat field additive/version. Coalesced evidence tetap berlabel
summary dan memiliki aturan count yang jelas.

Rollback: migration additive idempotent, fixture DB versi lama + pembacaan oleh
versi lama diuji; bila tidak kompatibel, hentikan rollout sampai rencana restore
dan rekonsiliasi write baru tersedia. Jangan memindah cursor mundur tanpa dedup.

### G03 / P1: Intake background untuk sumber yang belum tercakup

Dependency: G01 membuktikan sumber tersedia, G02 menetapkan kontrak dan dedup.
Pemilik baru hanya jika diperlukan: satu adapter intake, bukan script per attack.

- [ ] Buat keputusan arsitektur dari bukti: konsumsi index existing, forwarder
  durable existing, atau reader arsip lokal. Jangan membangun ketiganya serentak.
- [ ] Jika memakai file: simpan identitas file/generation, offset byte, partial
  line; uji rename rotation, copytruncate, restart, inode reuse, file terlambat,
  format berubah dan arsip compressed. Jangan advance sebelum commit/spool.
- [ ] Jika memakai index: cek versi/dukungan PIT + search_after dan stable sort
  sebelum mengganti scroll. Tangani PIT expiry, late insertion dan cursor invalid.
- [ ] Simpan malformed events ke quarantine terbatasi dengan alasan/retry;
  tidak menghilang sebagai baris yang dilewati diam-diam.
- [ ] Batasi page/bytes/time per cycle, antrean/spool, retention, CPU/RAM/I/O;
  gunakan backpressure dan counters deferred/dropped jika terjadi kehilangan.
- [ ] Catat scheduler ownership/lease. Satu job untuk satu stream aktif;
  catch-up dan live memiliki budget terpisah agar backlog tidak menelan live.
- [ ] Mulai shadow mode pada satu sumber dan window kecil. Tidak menerbitkan
  alert duplikat, memanggil AI/provider, atau mengubah rule Wazuh.
- [ ] Evaluasi apakah metadata/state cukup; event store baru hanya jika query
  deteksi memerlukannya dan retensi/akses/kapasitas/backup telah ditetapkan.

Acceptance: restart/crash/rotasi tidak kehilangan record yang sudah diterima
durably; duplikasi terukur dan ditekan dengan identity; backlog dapat dikejar;
pipeline Wazuh existing tetap sehat. Jaminan delivery hanya untuk batas yang
diuji, bukan untuk packet yang hilang sebelum collector.

Rollback: disable adapter baru, drain/park antreannya, simpan checkpoint; reader
lama tetap berfungsi. Tidak menjalankan dua active consumer untuk stream sama.

### G04 / P1: Detection pack yang dapat diuji

Pemilik: `detection_taxonomy.py` sebagai label compatibility, modul detector
terpisah bila stateful, input dari G02/G03. AI tidak menjadi detector per event.

- [ ] Buat registry pack dengan id/version, sumber/subtype, required fields,
  rule/signature/threshold, time window, state TTL, suppress policy, MITRE source,
  explainable matched conditions, evidence refs dan batas deteksi.
- [ ] Bedakan classification existing dari detector baru; first-match label
  tetap kompatibel, multi-signal baru additive dengan provenance per detector.
- [ ] Tinjau `malware` gap yang selalu muncul dan confidence `other`; jangan
  memperbaikinya hanya dengan menaikkan confidence atau menghapus syarat bukti.
- [ ] Prioritaskan pack dengan telemetry nyata sesuai matriks bagian 8.
  Pack tanpa sumber diparkir sebagai blocked, bukan ditandai aktif.
- [ ] Buat state persist: keyed source/target/account + window, distinct counts,
  late-event policy dan TTL; tidak mengandalkan state in-memory setelah restart.
- [ ] Persist finding beridentitas stabil, detector version, window, condition,
  outcome, count, confidence basis, missing evidence, first/last seen, evidence.
- [ ] Satu finding dapat memiliki beberapa observasi; rule alert + detector
  tambahan tidak menjadi dua confirmed incident otomatis.
- [ ] Forti import: pinned checkout, inventory konflik ID/nama, checksum, sample
  sanitasi dan expected decoded fields/rule. Gunakan preflight existing; exit
  code `wazuh-logtest` saja tidak cukup tanpa memeriksa hasil decode/rule.
- [ ] Bandingkan rule existing dahulu; import hanya delta reviewed. Uji benign
  dan malicious, lalu canary satu sumber sebelum restart manager terkontrol.

Acceptance tiap pack: fixture positif, benign, malformed, missing field, replay,
late/out-of-order, cross-window dan load lulus. Rule/version terlihat di finding;
blocked attempt tidak menjadi successful compromise. Threshold didasarkan pada
baseline atau konfigurasi reviewed, bukan angka universal yang tidak diuji.

Rollback: disable pack/version baru; hasil lama disimpan dengan versi/provenance;
restore hanya file rule/decoder delta jika import gagal. Tidak menghapus finding
atau rewrite sejarah untuk membuat metrik terlihat membaik.

### G05 / P1: IOC/CVE enrichment yang lengkap dalam scope

Pemilik: `soc_automation.py`, `server.py`, provider aggregate INFOKOM,
`cyfirma_*`, `cve_exposure.py`, `tools/sync_cmdb_inventory.py`.

- [ ] Audit extractor terhadap field nyata termasuk IPv6, URL/domain dan hash;
  internal IP tetap entitas lokal, bukan dikirim ke public reputation API.
- [ ] Per indikator pisahkan lookup state, verdict, cache freshness, evidence
  time, provider time, error/backoff/quota dan alasan skip.
- [ ] Enforce response schema: malformed/empty payload tidak dianggap successful
  no-match. Audit alias provider agar tidak menambah row provider yang sama.
- [ ] Deduplikasi `(tenant, kind, canonical_value, provider, policy_version)`
  dengan freshness. Budgets dan fairness mencegah satu watchlist memonopoli queue.
- [ ] Cocokkan dengan feed lokal secara incremental dan rematch ketika feed
  berubah, menggunakan checkpoint sendiri tanpa rescan raw event.
- [ ] Lengkapi test parser STIX untuk IP/domain/URL/file hashes, escape, AND/OR,
  revoked, valid_from/until dan object version. Pattern unsupported disimpan
  dengan alasan; jangan mengekstrak satu literal lalu mengabaikan syarat pattern.
- [ ] TAXII/Org CVE: ukur page/cursor, received/accepted/rejected/dedup/stored,
  restart di tengah halaman, duplicate page, expired token, 401/403/429, empty
  page + more. Pertahankan TLS/host allowlist, jangan menebak endpoint.
- [ ] Pisahkan IOC ledger, Org CVE, research dan local exposure. News CVE tidak
  otomatis menjadi vulnerability asset atau bukti eksploitasi.
- [ ] CMDB: merge inventory tanpa menimpa owner/zone verified; identitas ambigu
  tidak autojoin. Uji kasus hostname sama, NAT/shared IP dan agent ID lintas scope.
- [ ] Materialisasi asset -> package/version/CPE -> CVE -> intelligence -> case
  dengan provenance per field. Patch state dan internet exposure perlu bukti
  tersendiri; unknown tidak menjadi false/zero.

Acceptance: replay enrichment reuse hasil; perubahan range tidak menambah API
provider; expired/error dibedakan; actor/EPSS/KEV/PoC lokal tidak direka. Tepat
satu join terverifikasi atau explicit ambiguity, bukan cross product asset-CVE.

Rollback: disable collector/policy baru per-provider, pertahankan ledger/cursor;
backoff visible, tidak clear cache global atau mereset semua page ke awal.

### G06 / P1: Korelasi dan case yang tidak duplikat

Pemilik: `entity_resolver.py`, `defender_xdr.py`, case store INFOKOM,
`server._sync_finding_case`; tidak membuat incident store paralel.

- [ ] Canonical identity scoped tenant/source: IP/hostname, UPN/mailbox/user,
  agent/device, domain/URL/hash, CVE/CPE/package/cloud resource; alias dan roles
  tidak membuktikan dua identifier pasti milik objek sama.
- [ ] Correlate berdasarkan evidence entitas + bounded time + kondisi relevan;
  shared CDN/NAT IP, CVE sama, atau hostname pendek bukan auto-merge case.
- [ ] Simpan hubungan typed: observed_with, connected_to, matched_indicator,
  inventory_exposure, candidate_member, confirmed_case_member dengan evidence.
  Jangan menyebut observed_with sebagai causal attack step.
- [ ] Periksa coalescing lima menit: jumlah occurrence, first/last seen, locator
  representatif dan loss of detail harus terlihat pada timeline.
- [ ] Alert Defender dan incident induknya linked, tidak dihitung dua incident;
  update revision sumber tidak menjadi alert baru.
- [ ] Candidate tetap candidate sampai keputusan analis atau policy explicit
  evidence-gated yang diuji. Simpan alasan merge/split dan ability undo.
- [ ] Case update memakai expected revision; stale write ditolak. Attachment
  evidence/AI idempotent, duplicate request tidak menggandakan notes/evidence.
- [ ] Uji crash antar DB; outbox/reconciliation bila perlu, bukan klaim atomic
  transaction yang melintasi dua koneksi/store.

Acceptance: trace finding -> evidence -> entity -> candidate -> approved case
dapat dibaca setelah restart; reads case tidak memanggil Wazuh/provider;
timeline mencatat timestamp granularity, sumber, ID, confidence dan ATT&CK asal.

Rollback: disable grouping version baru; restore membership lewat audit trail;
case analis tetap utuh. Jangan mereklasifikasi case confirmed menjadi kandidat
secara massal sebagai efek migrasi.

### G07 / P1: AI menjelaskan bukti dan tindakan

Pemilik: `soc_contract.py`, `soc_automation.py`, existing AI jobs/run store,
case action endpoint. Aturan lengkap: [ANTI_HALLUCINATION.md](ANTI_HALLUCINATION.md).

- [ ] Freeze evaluation set dari fixture tersanitasi: serangan, benign, error
  provider, missing source, contradicting evidence, historical/as-of.
- [ ] Directed retrieval dari entity/case/evidence yang sama dan rentang yang
  benar; cap hops/records/bytes/tokens/time. Budget habis menjadi gap, bukan loop.
- [ ] Evidence bank memiliki IDs unik dan jenis event/summary/inventory/provider.
  Rule ID hanya menunjuk rule, bukan identitas event unik.
- [ ] Tambahkan validasi claim-to-field/time/role/provider/asset, bukan sekadar
  membership ID; claim tanpa dukungan menjadi inference/unverified/gap.
- [ ] Simpan severity/confidence basis, fact/inference, missing evidence,
  observed outcome, source/destination/device/account, CVE relationship serta
  next action dan approval boundary secara terstruktur.
- [ ] Persist run ID, contract/skill/model aktual vs configured, input/prompt
  hash, evidence snapshot references lengkap atau manifest durable, versions,
  truncation, validator violations, token usage jika tersedia dan fallback.
- [ ] Cache berdasarkan scoped evidence/version/policy/skill/model/window,
  bukan sekadar judul alert. Satu bukti berubah menghasilkan run baru terhubung.
- [ ] Lampirkan hasil tersimpan ke case melalui persetujuan analis dan revision
  guard; tidak ada tool containment yang dijalankan dari output model.
- [ ] Tampilkan profile kerja L1/L2/L3 sebagai batas workflow: triage, investigasi
  terkait, hypothesis hunting. Bukan klaim tingkat keahlian manusia/certification.

Acceptance: semua observed claim memiliki dukungan terukur atau diturunkan;
unknown/contradiction tidak disembunyikan; prompt injection tidak memicu aksi;
fallback disebut fallback; repeated read tidak menggunakan token baru; restart
tidak menggandakan analysis attachment ke case.

Rollback: nonaktifkan model/skill baru, baca run lama sesuai versinya; jangan
menimpa run lama, mengganti provenance, atau menjalankan ulang seluruh case.

### G08 / P1: Penyajian sesuai fungsi menu

Pemilik: static per-menu existing dan kontrak API. Gunakan
[MENU_DATA_OWNERSHIP.md](mcp-dashboard/MENU_DATA_OWNERSHIP.md) sebagai dasar.

- [ ] Command Center: posture dan tindakan dari case/CMDB dengan scope jelas;
  unknown bukan nol; grafik existing dipertahankan selama semantik benar.
- [ ] Findings: queue finding dan evidence drilldown; grouping rule, alert
  detail, inventory, provider-only dibedakan; jumlah sample bukan jumlah total.
- [ ] L1: validasi/escalation; L2: entity evidence timeline; Workbench: report
  dan approved recommendations; Incidents: assignment/SLA/lifecycle/evidence.
- [ ] Vulnerabilities: exposure/CVE/research context; Assets: inventory/owner/
  completeness; History: retensi/range; Hunting: hypothesis dan coverage.
- [ ] Tools: katalog, policy, eksekusi, result; Settings: dependency/budget/
  cursor/health. Pindah detail lewat link; jangan ulang full card lintas menu.
- [ ] Pagination Findings server-side adalah task eksplisit jika diperlukan;
  UI page 12 atas subset bukan pagination semua event. Cursor diikat ke filter,
  window dan stable sort, dengan query budget dan expiry yang jelas.
- [ ] Date semantics per panel: event_time, updated_time, inventory as-of atau
  all-time harus tampak. Partial materialization tidak menjadi empty success.
- [ ] Perbaiki browser smoke tests yang sudah tertinggal; uji seluruh 12 route,
  rentang, mobile, overflow, grafik nonblank dan API error state.

Acceptance: satu metric punya satu definisi dan pemilik, drilldown konsisten;
raw detail tetap opsional; analyst bisa menjawab apa/siapa terkena/dampak/tindakan
beserta bukti dan ketidakpastian. Tidak ada data sintetis di panel produksi.

Rollback: patch UI terpisah dari DB/detector; revert hanya modul yang regresi,
tanpa menghilangkan chart existing atau mengubah arti angka demi layout.

### G09 / P1: Beban, deployment bertahap dan operasi

- [ ] Benchmark terisolasi, data tersanitasi/replay: ekuivalen 1M, 3M, 10M
  event/hari, lalu burst dan recovery. 3M/hari ~34,7 event/detik rata-rata,
  bukan bukti kapasitas puncak. Catat event size/cardinality dan variasi sumber.
- [ ] Catat throughput, p95/p99 query/dashboard, CPU/RSS/I/O, WAL growth,
  lock wait, lag, oldest pending, queue depth, rejected/dropped, API dan token.
- [ ] Tetapkan threshold lulus numerik dari baseline G01 sebelum canary:
  resource cap, overhead Indexer, latency, live-lag, waktu recovery dan disk.
  Status threshold saat dokumen dibuat: belum diukur/belum ditetapkan.
- [ ] Budget penuh: service backpressure; tidak menambah worker/rate otomatis
  tanpa audit ownership/SQLite contention/quota.
- [ ] Restore SQLite WAL lewat backup konsisten (SQLite backup API atau writer
  quiesce), test di lokasi terpisah; jangan copy hanya file `.db` saat aktif.
- [ ] Deploy service yang berubah beserta dependencies; simpan previous image
  digest dan compatible schema, smoke test API/UI, amati beberapa cycle.
- [ ] Canary satu sumber/pack -> perluas hanya setelah acceptance; kurangi/
  hentikan jika metrik melewati threshold. Jaga data dan checkpoint saat rollback.
- [ ] Tetapkan retention evidence/summary/AI/provider, legal hold dan redaction.
  Retensi habis harus menghasilkan expired/unavailable yang dapat dijelaskan.

Acceptance: kapasitas hanya dinyatakan untuk profil yang diuji; setelah restart
cursor bergerak, DB result terbaca, UI sehat, token/provider budget terjaga dan
temuan tidak duplikat. Acceptance gagal bila workload baseline tidak tersedia.

## 8. Matriks detection pack: backlog, bukan daftar fitur aktif

Semua baris memerlukan fixture positif dan negatif serta bukti sumber G01.
Teknik ATT&CK harus diverifikasi terhadap mapping resmi saat implementasi;
family tidak otomatis setara satu technique atau satu tahapan attack path.

| Family/skenario | Bukti minimum untuk detector | Yang tidak cukup / kontrol negatif |
| --- | --- | --- |
| Brute force / password spray | Auth result, account/target, waktu, count/window dan source bila tercatat | Satu login gagal; admin retry; user bersama/NAT |
| Scan / reconnaissance | Distinct destination/port/service per actor/window, outcome dan baseline | Health checker, authorized scanner; label Nmap bukan identitas orang |
| SQL injection | HTTP/WAF signature atau request evidence, URL, target dan action | Kata SQL di log umum; escaped contoh kode; success perlu bukti lanjutan |
| XSS | HTTP/WAF evidence dan konteks request/response relevan | String script biasa; WAF blocked tidak membuktikan eksekusi di browser |
| Exploit / RCE attempt | IPS/WAF/process signal, target, action dan signature | Nama CVE saja; allow network bukan code execution |
| DoS / DDoS | Rate/time, protocol, target, fan-in dan kapasitas baseline | Volume harian tinggi atau spike bisnis; distributed source perlu bukti |
| Malware / ransomware | Endpoint alert, process/hash/file evidence dan action | Reputation IP saja; file download bukan eksekusi; noisy backup writes |
| Phishing / mailbox abuse | Email/Defender/auth evidence, recipient/user, verdict/action | Email dikirim bukan credential theft; submission bukan confirmed phishing |
| Beaconing / C2 suspected | Ordered connection timestamps, peer, interval/jitter dan baseline | Rollup total saja; scheduled update atau monitoring |
| MITM suspected | ARP/DHCP/DNS/TLS atau endpoint evidence yang relevan | Generic firewall traffic; certificate rotation sah |
| Sniffing suspected | Capture process/capability/interface atau NDR signal spesifik | Firewall tidak melihat passive capture; diagnostic capture berizin |
| Persistence / privilege escalation | Process/auth/config/registry/service/cron change terkait | Software install admin; process name saja |
| Lateral movement | Source-target auth/service/process dengan identity/time link | Shared IP atau co-observation saja; remote administration sah |
| Exfiltration / data access | Bytes/destination + data/access context, policy dan baseline | Koneksi keluar saja; update/backup/cloud sync sah |
| Defense evasion / log tamper | Audit/service/security policy perubahan + actor/process | Tidak ada log tidak otomatis berarti attacker menghapusnya |
| Cloud/account misuse | Entra/M365/Defender/audit resource/action dan scoped identity | Impossible travel dari VPN tanpa sign-in context |
| Container/cloud workload compromise | Runtime/API/process/image/resource + identity/action | Container restart atau image baru bukan compromise |

11 family pertama memiliki label existing dengan kemampuan terbatas; family
tambahan adalah backlog yang harus dibuktikan kebutuhannya. IDS/NDR tidak wajib
untuk semua pack; telemetry alternatif boleh dipakai jika mencatat bukti setara.
Script background dapat memproses bukti tersedia, tidak menciptakan bukti network
atau endpoint yang tidak pernah direkam.

## 9. Kamus angka dan status: cegah kesimpulan palsu

- `received`: diterima collector dalam boundary yang terdefinisi.
- `parsed`: berhasil dinormalisasi; tampilkan rejected/quarantined terpisah.
- `evaluated`: benar-benar diproses oleh detector/version, bukan hanya scanned.
- `eligible`: prerequisite detector terpenuhi pada record/window tersebut.
- `matched`: detector menghasilkan signal; bukan incident confirmed.
- `enriched`: indikator punya response valid yang tersimpan; pisahkan error.
- `correlated`: relasi candidate tersimpan; bukan causal attack path.
- `ai_analyzed`: hasil run tersimpan; fallback/model dibedakan.
- `rollup_complete`: window ringkasan lengkap menurut ledger, bukan seluruh
  detail raw/evidence/CVE/Defender untuk rentang itu lengkap.

Coverage harus selalu menyebut denominator/window/source/version. Replay count
tidak ditambahkan ke unique event count. Jangan menjumlahkan margin histogram
source/destination/identity menjadi event baru atau merangkainya sebagai flow.

Pertahankan status sumber `not_observed`, `observed_incomplete`, `ready`,
`degraded`, `stale`. Status detection coverage terpisah: prerequisites tersedia,
pack dievaluasi, signal ditemukan, atau evaluation unavailable. `ready` tidak
berarti malicious; `no_signal` tidak berarti semua serangan tidak ada.

## 10. Audit utilisasi tool

- [ ] Discover live catalogs kedua MCP, catat waktu/version dan drift terhadap
  mapping source. Jangan hardcode "194/203 tools semua bekerja".
- [ ] Untuk tiap tool catat name/source/schema, class, trigger, menu pemilik,
  dependency, read/write/external effects, budget, cache, last result/error.
- [ ] Bedakan discovered, mapped, configured, callable, executed, persisted,
  rendered. Katalog bukan hasil dan rendered bukan bukti semua event diperiksa.
- [ ] Uji read-only dengan bounded fixture/staging sesuai dependency; mutating,
  capture, scan aktif dan response tidak dieksekusi massal sebagai health check.
- [ ] Prioritaskan reuse baseline/velocity/beacon/attack-chain/CMDB/CVE/case
  tools setelah kontrak input-output dan cost terbukti; satu owner untuk hasil.
- [ ] Tool baru hanya setelah gap detector/adapter yang spesifik dibuktikan;
  MCP wrapper mengakses fungsi yang sama dengan scheduler, bukan implementasi
  kedua yang menyimpan hasil berbeda.

## 11. Bukti dan deliverable per task

Isi manifest sanitasi berikut untuk setiap gate/subtask. Gunakan lokasi private
ignored untuk payload/DB/screenshot nyata; repo hanya menyimpan fixture aman.

```yaml
task_id: G00
status: pending
source_commit: b4d3eb1
runtime_image_digest: null
environment: unverified
observed_at_utc: null
scope:
  source: null
  window_start: null
  window_end: null
reproduction: null
root_cause_evidence: []
changed_files: []
contract_or_schema_version: null
tests:
  positive: null
  negative: null
  replay_restart: null
  legacy_compatibility: null
  api_ui: null
  resource_budget: null
counts_before_after: null
evidence_artifact_refs: []
remaining_unknowns: []
rollback_procedure: null
rollback_test: null
next_allowed_task: null
```

Satu fix per hipotesis utama. Urutan kerja: baca jalur -> reproduksi -> bukti
root cause -> patch minimal -> test negatif/regresi -> canary runtime -> review
hasil -> catat status. Jangan mengganti angka/dashboard untuk menutupi upstream
yang gagal. Bug yang tidak terbukti dicatat sebagai hipotesis, bukan langsung
diikuti refactor besar.

## 12. Larangan perubahan yang merusak kompatibilitas

- Tidak menjalankan `docker compose down -v`, truncate/delete DB, reset semua
  cursor, clear semua cache, destructive Git reset, atau overwrite `.env`.
- Tidak menambah daemon kedua yang mengerjakan checkpoint yang sama.
- Tidak mengganti schema response/range semantics tanpa consumer/migration test.
- Tidak menghapus grafik/filter/AI button karena data belum tersedia.
- Tidak mengimpor semua Forti rules hanya untuk mengubah label readiness.
- Tidak menyalin credential/raw tenant data ke contoh, fixture, dokumentasi/PR.
- Tidak menaikkan quota/timeouts/concurrency untuk menutupi backlog tanpa ukur.
- Tidak menganggap hash input saja cukup untuk merekonstruksi evidence yang
  telah dihapus. Retensi snapshot/manifest dan hak akses harus jelas.

## 13. Definition of done

Gate selesai jika perilaku yang diminta berfungsi, old data masih terbaca,
error/unknown/partial jujur, duplicate/replay aman, cost terukur, UI/API sesuai,
dan hasil deployment terverifikasi. Tes lokal saja adalah local_test_passed.
Jika runtime tidak dapat diakses, hasil harus tetap runtime_unverified.

Target akhir rencana: analis dapat menjawab serangan/sinyal apa, source-target,
aset/account terdampak, outcome, hubungan CVE, confidence dan next action dengan
ID bukti yang dapat ditelusuri. Identitas pelaku tetap unknown kecuali ada bukti
atribusi memadai; actor context provider tidak menjadi kepastian identitas.

## 14. Pemeriksaan lokal yang sudah dijalankan

Catatan validasi terakhir dari direktori `mcp-dashboard`:

```bash
python3 -m unittest test_detection_improvements test_entity_resolver test_soc_pipeline test_cve_exposure test_frontend_lifecycle
```

Hasil baseline: **96 tests, OK**. Setelah patch25, full discovery menghasilkan
**264 tests, OK (10 skipped)**. Browser smoke runtime patch20 terakhir lulus pada
empat rentang. Tes ini memakai fixture/mock/temp DB dan static checks;
runtime smoke terautentikasi patch23 mencakup API 24h dan deploy check. Semua hasil tersebut
tidak membuktikan API provider live, seluruh tool, load 3M/hari atau seluruh
case lifecycle. Collector/cursor lintas dua pengamatan masih pending.

Pemeriksaan lain pada sesi penyusunan: akses Compose `ps` ditolak Docker socket;
read arsip lewat pencarian file juga mendapat permission denied. Tidak ada
upaya mengubah permission/service pada tahap dokumentasi ini.

Langkah implementasi pertama: **G00**, kemudian **G01**. Jangan mulai dengan
membangun ulang seluruh aplikasi, mengaktifkan semua tool, atau menambah panel.
