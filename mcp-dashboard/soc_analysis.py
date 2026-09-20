"""Evidence-based rule explanations and index-wide coverage summaries."""
import ipaddress
import re
from urllib.parse import urlparse
from datetime import datetime, timezone


EN_CVE_CONTEXT = {
    True: "The rule description explicitly mentions CVE references; validate the affected product and asset version before concluding exposure.",
    False: "The rule does not mention a CVE. Do not link it to a CVE only from IP reputation or a similar attack class.",
}


EN_ANALYSIS_BY_TITLE = {
    "Event terdeteksi oleh rule Wazuh": (
        "Event matched a Wazuh rule",
        "Wazuh matched the event against a rule. The event type and impact must be verified from the original log.",
        "Check the host, user, source, timestamp and rule level; compare them with authorized activity.",
        "Correlate events before and after the activity on the same asset. Escalate if there is evidence of unauthorized access or change.",
        "Needs verification",
    ),
    "Kerentanan dilaporkan pada paket aset": (
        "Vulnerability reported on an asset package",
        "Wazuh linked an installed package or version to a CVE. This is package exposure detection, not proof that exploitation succeeded.",
        "Identify the host, package, version, CVE and scanner state; confirm that inventory is current.",
        "Compare vendor advisory, service reachability, KEV and EPSS. Prioritize patching with the asset owner and validate again after changes.",
        "Vulnerability exposure",
    ),
    "Antrean event agent kembali normal": (
        "Agent event queue recovered",
        "The agent reported that its event queue recovered after delivery pressure.",
        "Confirm the agent is active and recent events are being received.",
        "Review the period before recovery for possible missing events and the reason for the spike.",
        "Telemetry recovery",
    ),
    "Antrean log agent mendekati atau melewati kapasitas": (
        "Agent log queue near or over capacity",
        "The agent event queue is full or spiking. Some events may be delayed or lost; this is monitoring coverage risk, not direct proof of an attack.",
        "Check the affected agent, manager connectivity, event rate and dropped/lost messages.",
        "Trace the source of the log spike; review queue capacity and configuration with the system owner before making changes.",
        "Telemetry loss risk",
    ),
    "Signature serangan jaringan terdeteksi": (
        "Network attack signature detected",
        "A network sensor matched traffic against an attack signature. Read detected or dropped status with the device action; successful exploitation is not confirmed.",
        "Check signature, action, source/destination, port and repeated traffic.",
        "Match the target product and version with explicit signature or CVE evidence; correlate server and endpoint response to assess impact.",
        "Network threat indication",
    ),
    "Pola unduhan cloud mencurigakan": (
        "Suspicious cloud download pattern",
        "The rule flagged an unusual download pattern. Separate legitimate work from possible unauthorized data collection or exfiltration.",
        "Check account, file count and sensitivity, IP address and user permissions.",
        "Correlate sign-ins and sessions, baseline volume and other data access; escalate if it does not match business activity.",
        "Data access anomaly",
    ),
    "Event karantina Microsoft 365": (
        "Microsoft 365 quarantine event",
        "The product logged quarantine-related activity. Check the original operation to distinguish message containment, release or user action.",
        "Review verdict, recipient, sender, operation and latest message status.",
        "Search for similar messages and click/endpoint activity; confirm a malicious message was not released without validation.",
        "Email threat handling",
    ),
    "Hasil pemeriksaan konfigurasi keamanan": (
        "Security configuration assessment result",
        "Asset configuration was compared with a hardening benchmark. A failed control indicates a configuration gap, not automatic exploitation.",
        "Open the failed check, actual evidence and benchmark recommendation; validate approved exceptions.",
        "Prioritize high-impact controls with the asset owner, test the change and run the assessment again.",
        "Hardening gap",
    ),
    "Konfigurasi keamanan berubah": (
        "Security configuration changed",
        "A security device or product logged a configuration change. The change must be matched to authorization and impact.",
        "Check actor, changed object/rule, before/after configuration and change ticket.",
        "Assess whether protection or access restrictions were weakened; correlate account activity and connections before proposing rollback.",
        "Configuration change",
    ),
    "Informasi sistem diakses melalui WMI": (
        "System information accessed through WMI",
        "A WMI query was used to read host information. This may be approved inventory activity or attacker discovery.",
        "Check calling process, account, remote source and query.",
        "Correlate with remote execution, child processes and other hosts; validate administration tooling before escalation.",
        "Discovery needs verification",
    ),
    "Aktivitas hak istimewa": (
        "Privileged activity",
        "Windows logged use or assignment of special privileges. Check whether the operation succeeded, failed, or was only privilege assignment at logon.",
        "Check account, privilege type, Logon ID, process and operation result.",
        "Correlate with admin group changes, remote sessions and process execution to detect unauthorized privilege escalation.",
        "Privilege audit",
    ),
    "Aktivitas tugas terjadwal": (
        "Scheduled task activity",
        "Windows logged Task Scheduler activity. Scheduled tasks can run approved jobs or persistence mechanisms.",
        "Check task name, action/command, account, trigger and creator.",
        "Match it to approved deployment, inspect the executed file and child processes; preserve evidence if the task is unauthorized.",
        "Automation audit",
    ),
    "Proses dijalankan pada host": (
        "Process executed on host",
        "A process start was recorded. The process name alone does not establish malware status.",
        "Check executable path, command line, parent process, hash and user.",
        "Validate signature/hash, correlate network connections and file changes, then compare with the application baseline.",
        "Process audit",
    ),
    "Perangkat eksternal dikenali": (
        "External device detected",
        "The system detected a new external device. Review whether the device is authorized.",
        "Check device type, identity/serial, host and active user.",
        "Correlate file access and removable-media policy; inspect execution from the media without assuming data loss from attachment alone.",
        "Device audit",
    ),
    "Koneksi diizinkan oleh firewall": (
        "Connection allowed by firewall",
        "The firewall allowed a connection according to policy. This log by itself is not proof of attack.",
        "Check source/destination IP, port, application and policy that allowed the connection.",
        "Compare IP reputation with business purpose and endpoint logs. Propose policy change only when unauthorized activity is evidenced.",
        "Network activity",
    ),
    "Koneksi diblokir oleh firewall": (
        "Connection blocked by firewall",
        "The firewall denied a connection. A denial does not prove the attacker gained access.",
        "Check destination, port, block reason and repetition from the same source.",
        "Look for other successful connections from the same source and impact on the destination host before escalation.",
        "Connection denied",
    ),
    "Isi mailbox diakses": (
        "Mailbox contents accessed",
        "An account or application accessed mail items. Normal synchronization can also generate this event.",
        "Match UserId, ClientIP, application and time with the mailbox owner's activity.",
        "Correlate Entra sign-ins, session/token use, inbox-rule changes and bulk access. Revoke sessions through the playbook if account compromise is confirmed.",
        "Email access audit",
    ),
    "Deteksi phishing atau malware Microsoft 365": (
        "Microsoft 365 phishing or malware detection",
        "Microsoft security services reported phishing or malware indications. Read verdict and product action from the original event.",
        "Identify sender, recipient, URL/hash, verdict and whether the message was blocked or delivered.",
        "Check clicks, downloads and recipient endpoints; validate indicators with intelligence and respond according to verified evidence.",
        "Threat indication",
    ),
    "Kebijakan perlindungan data terpicu": (
        "Data protection policy triggered",
        "Activity matched a DLP policy. A policy violation does not automatically mean data was stolen.",
        "Check policy, data type, owner, recipient and recorded action.",
        "Validate whether access or transfer actually occurred and was authorized; involve the data owner for handling.",
        "Policy alert",
    ),
    "File cloud diunduh": (
        "Cloud file downloaded",
        "A file was downloaded from Microsoft 365. Downloads may be legitimate user activity.",
        "Check account, file, client IP, device and download time.",
        "Look for bulk downloads, new accounts or unusual IPs; check file sensitivity before concluding data leakage.",
        "File audit",
    ),
    "Kesalahan sistem berulang": (
        "Repeated system errors",
        "Windows reported multiple system errors. Application or service issues can also trigger this rule.",
        "Check Event ID, provider, affected service and whether there is operational impact.",
        "Correlate crashes with installations, configuration changes and security events; do not treat errors as malware without additional evidence.",
        "System disruption",
    ),
    "Kesalahan sistem Windows": (
        "Windows system error",
        "Windows recorded a service or system error that needs context review.",
        "Read Event ID and error message; check service health and recent changes.",
        "Compare with authentication and process events on the host; escalate to operations or security based on evidence.",
        "System disruption",
    ),
    "Sesi pengguna berakhir": (
        "User session ended",
        "The event records user logout or session closure. This is usually audit evidence.",
        "Match account, host and time with the previous login session.",
        "Review activity during the session only if other suspicious alerts exist.",
        "Session audit",
    ),
    "Login remote memerlukan verifikasi": (
        "Remote login needs verification",
        "The rule flags a remote login pattern that needs investigation. The rule name alone does not prove credential theft or pass-the-hash.",
        "Check account, LogonType, AuthenticationPackageName, source IP and remote access authorization.",
        "Correlate the session with processes, share access and other hosts. Look for lateral movement evidence before declaring compromise.",
        "Access needs verification",
    ),
    "Percobaan autentikasi gagal": (
        "Failed authentication attempts",
        "The system recorded failed logins. Repetition may indicate brute force or credential misconfiguration.",
        "Check attempt count, target account, source IP and whether a successful login followed.",
        "Correlate successful sessions with processes and data access; validate approved automation before restricting an account or source.",
        "Access needs verification",
    ),
    "Aktivitas login atau penerbitan token": (
        "Login or token issuance activity",
        "An authentication or session/token event was recorded. A successful login is not automatically malicious.",
        "Check account, IP, application, authentication result and MFA state when available.",
        "Correlate device, login pattern, permission changes and post-login activity to assess account misuse.",
        "Authentication audit",
    ),
    "Kesalahan layanan atau aplikasi Windows": (
        "Windows service or application error",
        "A service or application reported an operational error. This message does not prove attacker activity by itself.",
        "Check Event ID, provider, full message and affected service.",
        "Correlate with software changes and security events; route to the application owner when it is operational.",
        "Application disruption",
    ),
    "Catatan audit akses Windows": (
        "Windows access audit record",
        "Windows recorded access or failed audited operation. Identify the operation and result in the original event.",
        "Check account, Logon ID, object and access result code.",
        "Correlate session and privileges with host activity before judging unauthorized access.",
        "Access audit",
    ),
    "Status operasional Windows Defender": (
        "Windows Defender operational status",
        "Antimalware logged scan, update or maintenance status. Status records are not malware detections by themselves.",
        "Check Event ID, operation, scan result and whether protection remains enabled.",
        "Search for related detections or protection changes and validate maintenance activity before escalation.",
        "Protection health",
    ),
    "Aktivitas sesi jaringan": (
        "Network session activity",
        "The firewall logged network volume or session changes. High volume or closed sessions do not automatically prove attack.",
        "Check application, endpoints, volume, duration, action and policy.",
        "Compare with baseline and business activity, then look for threat signatures and service impact.",
        "Traffic audit",
    ),
    "Perubahan status layanan": (
        "Service status changed",
        "The system recorded service lifecycle or maintenance activity. Match it to an approved operations window.",
        "Check time, host, operation result and maintenance job.",
        "Investigate if it repeats without plan, affects service, or appears near suspicious account activity.",
        "Operational audit",
    ),
    "File atau registry berubah": (
        "File or registry changed",
        "Wazuh detected a change to a monitored FIM object. The change may be approved deployment or unauthorized activity.",
        "Check path, before/after hash, user and approved change window.",
        "Find the process that wrote the file and related connections; preserve evidence and restore only after unauthorized change is validated.",
        "Integrity change",
    ),
    "Probe atau percobaan serangan aplikasi": (
        "Application probe or attack attempt",
        "The request pattern resembles scanning or a web attack. Probing is not the same as successful exploitation.",
        "Check URL/path, response code, response size and source IP.",
        "Look for sensitive files that were actually exposed, process execution and data access; match CVEs only to identified product/version or signature.",
        "Attack attempt",
    ),
    "Aktivitas container": (
        "Container activity",
        "Runtime or container change event. Determine whether the change matches approved deployment.",
        "Check container/image, command, user and deployment time.",
        "Correlate privileged mode, host mounts, shell execution and network access; contain only according to evidence.",
        "Container audit",
    ),
    "Aktivitas audit Microsoft 365": (
        "Microsoft 365 audit activity",
        "Cloud service logged an operation on an account or object. Operation context determines whether activity is normal or suspicious.",
        "Check operation, user, object, workload and ClientIP in the original log.",
        "Compare with account and object permissions, then correlate DLP/Defender and sign-in events.",
        "Cloud audit",
    ),
}


def explain_rule(rule):
    original = str(rule.get("description") or "Deskripsi rule belum tersedia")
    groups = rule.get("groups") or []
    value = (original + " " + " ".join(groups if isinstance(groups, list) else [str(groups)])).lower()
    title = "Event terdeteksi oleh rule Wazuh"
    meaning = "Wazuh mencocokkan event dengan sebuah rule. Jenis dan dampaknya perlu diverifikasi dari log asli."
    l1 = "Periksa host, pengguna, sumber, waktu dan level rule; cocokkan dengan aktivitas yang diizinkan."
    l2 = "Korelasikan event sebelum dan sesudah kejadian pada aset yang sama. Eskalasi bila ada bukti akses atau perubahan tidak sah."
    status = "Perlu verifikasi"
    basis = "fallback"
    cases = [
        (r"cve-\d{4}-\d+ affects|vulnerability.detector", "Kerentanan dilaporkan pada paket aset", "Wazuh menghubungkan paket atau versi yang terpasang dengan CVE. Ini adalah deteksi paparan paket, bukan bukti bahwa eksploitasi telah berhasil.", "Identifikasi host, paket, versi, CVE dan kondisi scanner; pastikan inventaris terbaru.", "Cocokkan advisory vendor, keterjangkauan layanan, KEV dan EPSS. Prioritaskan patch bersama pemilik aset dan validasi ulang setelah perubahan.", "Paparan kerentanan"),
        (r"agent event queue.*normal", "Antrean event agent kembali normal", "Agent melaporkan pemulihan antrean setelah tekanan pengiriman event.", "Pastikan agent aktif dan event terbaru diterima.", "Periksa periode sebelum pemulihan untuk kemungkinan event yang hilang dan penyebab lonjakan.", "Pemulihan telemetri"),
        (r"agent event queue|agent_flooding", "Antrean log agent mendekati atau melewati kapasitas", "Antrean pengiriman event agent penuh atau mengalami lonjakan. Sebagian event berpotensi terlambat atau hilang; ini masalah cakupan monitoring, bukan bukti serangan langsung.", "Periksa agent terdampak, koneksi ke manager, laju event dan pesan dropped/lost.", "Telusuri sumber log yang melonjak; tinjau kapasitas dan konfigurasi antrean dengan pemilik sistem sebelum perubahan.", "Risiko kehilangan telemetri"),
        (r"attack detected|attack dropped|suricata|snort", "Signature serangan jaringan terdeteksi", "Sensor jaringan mencocokkan trafik dengan signature serangan. Status detected atau dropped perlu dibaca bersama tindakan perangkat; keberhasilan eksploitasi belum terkonfirmasi.", "Periksa signature, action, sumber/tujuan, port dan pengulangan trafik.", "Cocokkan produk dan versi target dengan signature/CVE eksplisit; korelasikan respons server dan endpoint untuk menilai dampak.", "Indikasi ancaman jaringan"),
        (r"suspicious download", "Pola unduhan cloud mencurigakan", "Rule menandai pola unduhan yang tidak biasa. Perlu membedakan pekerjaan resmi dari kemungkinan pengumpulan atau pengambilan data tidak sah.", "Periksa akun, jumlah dan sensitivitas file, IP serta izin pengguna.", "Korelasikan sign-in dan sesi, volume baseline serta akses data lain; eskalasi jika tidak sesuai aktivitas bisnis.", "Anomali akses data"),
        (r"quarantine", "Event karantina Microsoft 365", "Produk mencatat aktivitas terkait karantina. Periksa operasi asli untuk membedakan penahanan pesan, pelepasan atau tindakan pengguna.", "Periksa verdict, penerima, pengirim, operasi dan status pesan terakhir.", "Cari pesan serupa dan aktivitas klik/endpoint; pastikan pesan berbahaya tidak dilepas tanpa validasi.", "Penanganan ancaman email"),
        (r"sca|cis.*benchmark", "Hasil pemeriksaan konfigurasi keamanan", "Konfigurasi aset dibandingkan dengan benchmark hardening. Kegagalan kontrol menandakan gap konfigurasi, bukan otomatis eksploitasi.", "Buka check yang gagal, bukti aktual dan rekomendasi benchmark; validasi pengecualian yang disetujui.", "Prioritaskan kontrol berdampak tinggi bersama pemilik aset, uji perubahan dan jalankan ulang pemeriksaan.", "Gap hardening"),
        (r"firewall.*exception list|configuration chang", "Konfigurasi keamanan berubah", "Perangkat atau produk keamanan mencatat perubahan konfigurasi. Perubahan perlu dicocokkan dengan otorisasi dan dampaknya.", "Periksa pelaku, objek/rule yang berubah, konfigurasi sebelum/sesudah dan tiket perubahan.", "Nilai apakah proteksi atau pembatasan akses melemah; korelasikan dengan aktivitas akun dan koneksi sebelum mengusulkan pemulihan.", "Perubahan konfigurasi"),
        (r"wmi query|system information discovery", "Informasi sistem diakses melalui WMI", "Query WMI digunakan untuk membaca informasi host. Ini bisa berasal dari inventaris resmi atau tahap discovery penyerang.", "Periksa proses pemanggil, akun, sumber remote dan query.", "Korelasikan dengan eksekusi remote, proses anak serta host lain; validasi alat administrasi sebelum eskalasi.", "Discovery perlu diverifikasi"),
        (r"privileged operation|special privileges", "Aktivitas hak istimewa", "Windows mencatat penggunaan atau pemberian hak khusus. Periksa apakah operasi berhasil, gagal, atau hanya penetapan hak saat login.", "Periksa akun, jenis privilege, Logon ID, proses dan hasil operasi.", "Korelasikan dengan perubahan grup admin, sesi remote dan eksekusi proses untuk mendeteksi eskalasi hak yang tidak sah.", "Audit privilege"),
        (r"scheduled task|task scheduler", "Aktivitas tugas terjadwal", "Windows mencatat aktivitas Task Scheduler. Tugas terjadwal dapat menjalankan pekerjaan resmi maupun mekanisme persistensi.", "Periksa nama task, action/perintah, akun, trigger dan pembuatnya.", "Cocokkan dengan deployment resmi, periksa file yang dieksekusi dan proses turunannya; simpan bukti jika task tidak sah.", "Audit otomasi"),
        (r"process was created|slui.exe launched", "Proses dijalankan pada host", "Sebuah proses tercatat mulai berjalan. Nama proses saja tidak menetapkan status malware.", "Periksa path executable, command line, parent process, hash dan pengguna.", "Validasi signature/hash, korelasikan koneksi serta file yang diubah dan bandingkan dengan baseline aplikasi.", "Audit proses"),
        (r"new external device", "Perangkat eksternal dikenali", "Sistem mengenali perangkat eksternal baru. Tinjau apakah perangkat tersebut diizinkan.", "Periksa jenis perangkat, identitas/serial, host dan pengguna yang aktif.", "Korelasikan akses file dan kebijakan removable media; periksa eksekusi dari media tanpa menyimpulkan kebocoran hanya dari pemasangan.", "Audit perangkat"),
        (r"app passed|traffic.*allow|connection.*allow", "Koneksi diizinkan oleh firewall", "Firewall mengizinkan koneksi sesuai kebijakan. Log ini sendiri bukan bukti serangan.", "Periksa IP sumber/tujuan, port, aplikasi dan policy yang mengizinkan koneksi.", "Bandingkan reputasi IP dengan tujuan bisnis dan log endpoint. Usulkan perubahan policy hanya bila aktivitas tidak sah terbukti.", "Aktivitas jaringan"),
        (r"app blocked|firewall_drop|traffic.*denied|blocked url", "Koneksi diblokir oleh firewall", "Firewall menolak koneksi. Penolakan tidak membuktikan bahwa penyerang berhasil masuk.", "Periksa tujuan, port, alasan blokir dan pengulangan dari sumber yang sama.", "Cari koneksi lain yang berhasil dari sumber tersebut dan dampak pada host tujuan sebelum melakukan eskalasi.", "Koneksi ditolak"),
        (r"mailitemsaccessed", "Isi mailbox diakses", "Sebuah akun atau aplikasi mengakses item email. Aktivitas sinkronisasi normal juga dapat menghasilkan event ini.", "Cocokkan UserId, ClientIP, aplikasi dan waktu dengan aktivitas pemilik mailbox.", "Korelasikan sign-in Entra, sesi/token, perubahan inbox rule dan akses massal. Cabut sesi melalui playbook jika kompromi akun terkonfirmasi.", "Audit akses email"),
        (r"phishing|malware events|threatintelligence", "Deteksi phishing atau malware Microsoft 365", "Layanan keamanan Microsoft melaporkan indikasi phishing atau malware. Baca verdict dan tindakan produk pada event asli.", "Identifikasi pengirim, penerima, URL/hash, verdict dan apakah pesan diblokir atau dikirim.", "Periksa klik, unduhan dan endpoint penerima; validasi indikator dengan intelijen lalu lakukan respons sesuai hasil verifikasi.", "Indikasi ancaman"),
        (r"dlp|data loss", "Kebijakan perlindungan data terpicu", "Aktivitas cocok dengan kebijakan DLP. Pelanggaran kebijakan belum otomatis berarti data berhasil dicuri.", "Periksa policy, jenis data, pemilik, penerima dan action yang tercatat.", "Validasi apakah akses atau transfer benar-benar terjadi dan diizinkan; libatkan pemilik data untuk penanganan.", "Peringatan kebijakan"),
        (r"downloads a file|filedownload", "File cloud diunduh", "File diunduh dari layanan Microsoft 365. Unduhan dapat merupakan aktivitas pengguna yang sah.", "Periksa akun, file, IP klien, perangkat dan waktu unduhan.", "Cari unduhan massal, akun baru atau IP tidak biasa; periksa sensitivitas file sebelum menyimpulkan kebocoran data.", "Audit file"),
        (r"multiple (system|windows) error", "Kesalahan sistem berulang", "Windows melaporkan beberapa error sistem. Gangguan aplikasi atau layanan juga dapat memicu rule ini.", "Periksa Event ID, provider, layanan terdampak dan apakah ada gangguan operasional.", "Korelasikan crash dengan instalasi, perubahan konfigurasi dan event keamanan; jangan menganggap error sebagai malware tanpa bukti tambahan.", "Gangguan sistem"),
        (r"system error|windows_system", "Kesalahan sistem Windows", "Windows mencatat error layanan atau sistem yang perlu diperiksa konteksnya.", "Baca Event ID dan pesan error; cek kesehatan layanan dan perubahan terakhir.", "Bandingkan dengan event autentikasi dan proses pada host; eskalasi ke operasi atau keamanan sesuai bukti.", "Gangguan sistem"),
        (r"logoff|logout|logged out|logged off", "Sesi pengguna berakhir", "Event mencatat pengguna keluar atau sesi ditutup. Ini umumnya merupakan catatan audit.", "Cocokkan akun, host dan waktu dengan sesi login sebelumnya.", "Telusuri aktivitas selama sesi hanya jika ada alert lain yang mencurigakan.", "Audit sesi"),
        (r"anonymous logon|pass.the.hash", "Login remote memerlukan verifikasi", "Rule menandai login remote dengan pola autentikasi yang perlu diselidiki. Nama rule saja belum membuktikan pencurian kredensial atau pass-the-hash.", "Periksa akun, LogonType, AuthenticationPackageName, IP sumber dan otorisasi akses remote.", "Korelasikan sesi dengan proses, akses share dan host lain. Cari bukti pergerakan lateral sebelum menyatakan kompromi.", "Perlu verifikasi akses"),
        (r"brute|authentication_fail|failed password|login failed|logon failure", "Percobaan autentikasi gagal", "Sistem mencatat kegagalan login. Pengulangan dapat mengindikasikan brute force atau salah konfigurasi kredensial.", "Periksa jumlah percobaan, akun sasaran, sumber IP dan apakah ada login sukses setelahnya.", "Korelasikan sesi sukses dengan proses dan akses data; validasi otomatisasi resmi sebelum membatasi akun atau sumber.", "Perlu verifikasi akses"),
        (r"sts.*logon|logon.*sts|signin|authentication_success|logged in", "Aktivitas login atau penerbitan token", "Sebuah autentikasi atau sesi/token tercatat. Login yang berhasil tidak otomatis berarti login berbahaya.", "Periksa akun, IP, aplikasi, hasil autentikasi dan MFA bila tersedia.", "Korelasikan perangkat, pola login, perubahan izin dan aktivitas setelah login untuk menilai penyalahgunaan akun.", "Audit autentikasi"),
        (r"windows.*error|application error|system_error|wsearch.*unavailable|service.*failed", "Kesalahan layanan atau aplikasi Windows", "Layanan atau aplikasi melaporkan error operasional. Pesan ini belum membuktikan aktivitas penyerang.", "Periksa Event ID, provider, pesan lengkap dan layanan yang terdampak.", "Korelasikan dengan perubahan perangkat lunak dan event keamanan; arahkan penanganan ke pemilik aplikasi jika masalah operasional.", "Gangguan aplikasi"),
        (r"local logon|audit failure", "Catatan audit akses Windows", "Windows mencatat akses atau kegagalan operasi yang diaudit. Identifikasi operasi dan hasilnya pada event asli.", "Periksa akun, Logon ID, objek dan kode hasil akses.", "Korelasikan sesi dan hak akses dengan aktivitas host sebelum menilai akses tidak sah.", "Audit akses"),
        (r"windows defender", "Status operasional Windows Defender", "Produk antimalware mencatat status scan, pembaruan atau pemeliharaan. Catatan status bukan dengan sendirinya deteksi malware.", "Periksa Event ID, operasi, hasil scan dan apakah proteksi tetap aktif.", "Cari deteksi atau perubahan proteksi terkait dan validasi kegiatan pemeliharaan sebelum eskalasi.", "Kesehatan proteksi"),
        (r"high traffic|session cleared", "Aktivitas sesi jaringan", "Firewall mencatat volume atau perubahan sesi jaringan. Volume tinggi atau sesi ditutup tidak otomatis membuktikan serangan.", "Periksa aplikasi, endpoint, volume, durasi, action dan policy.", "Bandingkan dengan baseline dan pekerjaan bisnis, lalu cari signature ancaman serta dampak layanan.", "Audit trafik"),
        (r"agent started|shutdown initiated|database engine|software protection|virtual cluster", "Perubahan status layanan", "Sistem mencatat siklus hidup atau pemeliharaan layanan. Cocokkan dengan jadwal operasi yang disetujui.", "Periksa waktu, host, hasil operasi dan pekerjaan pemeliharaan.", "Investigasi bila berulang tanpa rencana, memengaruhi layanan atau berdekatan dengan aktivitas akun mencurigakan.", "Audit operasional"),
        (r"syscheck|fim|integrity", "File atau registry berubah", "Wazuh mendeteksi perubahan objek yang dipantau FIM. Perubahan bisa berasal dari deployment resmi maupun aktivitas tidak sah.", "Periksa path, hash sebelum/sesudah, pengguna dan jadwal perubahan yang disetujui.", "Cari proses yang menulis file dan koneksi terkait; simpan bukti dan pulihkan hanya setelah perubahan tidak sah divalidasi.", "Perubahan integritas"),
        (r"sql injection|xss|web attack|web_scan|sensitive.*path|recon", "Probe atau percobaan serangan aplikasi", "Pola request menyerupai pemindaian atau serangan web. Probe tidak sama dengan eksploitasi yang berhasil.", "Periksa URL/path, kode respons, ukuran respons dan sumber IP.", "Cari file sensitif yang benar-benar terbuka, eksekusi proses dan akses data; cocokkan CVE hanya dengan produk/versi atau signature yang teridentifikasi.", "Percobaan serangan"),
        (r"docker|container", "Aktivitas container", "Event terkait runtime atau perubahan container. Nilai apakah perubahan sesuai deployment yang diizinkan.", "Periksa container/image, perintah, pengguna dan waktu deployment.", "Korelasikan privileged mode, mount host, eksekusi shell dan akses jaringan; lakukan containment sesuai bukti.", "Audit container"),
        (r"office365|sharepoint|onedrive", "Aktivitas audit Microsoft 365", "Layanan cloud mencatat operasi pada akun atau objek. Konteks operasi menentukan apakah aktivitas normal atau mencurigakan.", "Periksa operasi, pengguna, object, workload dan ClientIP pada log asli.", "Bandingkan dengan pola akun dan izin objek, lalu korelasikan event DLP/Defender dan sign-in.", "Audit cloud"),
    ]
    for pattern, title_, meaning_, l1_, l2_, status_ in cases:
        if re.search(pattern, value):
            title, meaning, l1, l2, status = title_, meaning_, l1_, l2_, status_
            basis = "description/groups"
            break
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", original.upper())))
    title_en, meaning_en, l1_en, l2_en, status_en = EN_ANALYSIS_BY_TITLE.get(
        title, EN_ANALYSIS_BY_TITLE["Event terdeteksi oleh rule Wazuh"]
    )
    return {"title": title, "meaning": meaning, "l1": l1, "l2": l2, "status": status,
            "title_en": title_en, "meaning_en": meaning_en, "l1_en": l1_en, "l2_en": l2_en,
            "status_en": status_en,
            "basis": basis, "original": original, "cves": cves,
            "cve_context": "CVE disebut pada deskripsi rule; validasi produk dan versi aset sebelum menyimpulkan paparan." if cves else "Rule tidak menyebut CVE. Jangan menghubungkannya ke CVE hanya dari reputasi IP atau kesamaan jenis serangan.",
            "cve_context_en": EN_CVE_CONTEXT[bool(cves)]}


IOC_FIELDS = {"source_ip": "data.srcip", "m365_ip": "data.office365.ClientIP",
              "destination_ip": "data.dstip", "destination_ip_alt": "data.dst_ip",
              "destination_ip_nested": "data.destination.ip",
              "md5": "syscheck.md5_after", "sha256": "syscheck.sha256_after",
              "domain": "data.dns.question.name", "url": "data.url",
              "source_ip_alt": "data.src_ip", "source_ip_nested": "data.source.ip",
              "win_ip": "data.win.eventdata.ipAddress", "sha1": "syscheck.sha1_after",
              "http_url": "data.http.url", "request_url": "data.request.url"}


def observable_kind(key):
    if "ip" in key:
        return "ip"
    if "url" in key:
        return "url"
    return key


def public_indicator(item):
    value, kind = item["indicator"], item["kind"]
    if len(value) > 256:
        return False
    if kind == "ip":
        try:
            return ipaddress.ip_address(value).is_global
        except ValueError:
            return False
    if kind in {"md5", "sha1", "sha256"}:
        return bool(re.fullmatch(r"[a-fA-F0-9]{%d}" % {"md5": 32, "sha1": 40, "sha256": 64}[kind], value))
    if kind == "url":
        try:
            url = urlparse(value)
            if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.query or url.fragment:
                return False
            value = url.hostname
            try:
                return ipaddress.ip_address(value).is_global
            except ValueError:
                pass
        except ValueError:
            return False
    elif kind != "domain":
        return False
    if value.lower().rstrip('.').endswith(('.local', '.internal', '.localhost', '.lan', '.invalid', '.test')):
        return False
    return bool(re.fullmatch(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", value))


def coverage(search, time_range):
    if isinstance(time_range, dict):
        bounds = time_range.get("bounds") or {"gte": "now-24h"}
        label = time_range.get("label") or time_range.get("requested") or "custom"
        interval = "1h"
        try:
            if "lt" in bounds:
                start = datetime.fromisoformat(str(bounds["gte"]).replace("Z", "+00:00"))
                end = datetime.fromisoformat(str(bounds["lt"]).replace("Z", "+00:00"))
                hours = max(1, (end - start).total_seconds() / 3600)
                interval = "1h" if hours <= 48 else "6h" if hours <= 24 * 14 else "1d"
        except Exception:
            interval = "1h"
    else:
        label = str(time_range)
        bounds = {"gte": "now-" + label}
        interval = "1h" if label == "24h" else "1d"
    filters = [{"range": {"@timestamp": bounds}}]
    rule_details = {"event": {"top_hits": {"size": 1, "sort": [{"@timestamp": "desc"}],
                    "_source": ["rule", "agent", "decoder", "location", "@timestamp"]}}}
    aggs = {
        "severity": {"terms": {"field": "rule.level", "size": 16}},
        "timeline": {"date_histogram": {"field": "@timestamp", "fixed_interval": interval, "min_doc_count": 0}},
        "sources": {"terms": {"field": "decoder.name", "size": 100, "shard_size": 500},
                    "aggs": {"max_level": {"max": {"field": "rule.level"}}, **rule_details}},
        "mitre": {"terms": {"field": "rule.mitre.id", "size": 10}},
        "rules": {"terms": {"field": "rule.id", "size": 200, "shard_size": 1000},
                  "aggs": rule_details},
        "priority_rules": {"filter": {"range": {"rule.level": {"gte": 10}}},
                           "aggs": {"rules": {"terms": {"field": "rule.id", "size": 200, "shard_size": 1000},
                                               "aggs": rule_details}}},
        "with_observable": {"filter": {"bool": {"should": [{"exists": {"field": field}} for field in IOC_FIELDS.values()], "minimum_should_match": 1}}},
    }
    for key, field in IOC_FIELDS.items():
        aggs[key] = {"terms": {"field": field, "size": 30, "shard_size": 300},
                     "aggs": {"max_level": {"max": {"field": "rule.level"}}, "rules": {"terms": {"field": "rule.id", "size": 5}}}}
    query = {"size": 0, "track_total_hits": True,
             "query": {"bool": {"filter": filters}}, "aggs": aggs}
    result = None
    coverage_mode = "enhanced"
    coverage_warning = None
    try:
        enhanced_result = search(query)
        if enhanced_result.get("timed_out", False) or enhanced_result.get("_shards", {}).get("failed", 0):
            coverage_warning = "Enhanced coverage query was incomplete; legacy coverage was used."
        else:
            result = enhanced_result
    except Exception:
        coverage_warning = "Enhanced coverage query was unavailable; legacy coverage was used."

    if result is None:
        legacy_aggs = dict(aggs)
        legacy_aggs.pop("priority_rules", None)
        legacy_aggs["sources"] = {"terms": {"field": "decoder.name", "size": 10}}
        legacy_aggs["rules"] = {"terms": {"field": "rule.id", "size": 200, "shard_size": 1000},
                                "aggs": rule_details}
        try:
            result = search({**query, "aggs": legacy_aggs})
            coverage_mode = "legacy_fallback"
        except Exception:
            if 'enhanced_result' not in locals():
                raise
            result = enhanced_result
            coverage_mode = "enhanced_partial"
            coverage_warning = "Coverage is partial because both the enhanced and compatibility queries were incomplete."
    aggregates = result.get("aggregations", {})
    rules_by_id = {}
    rule_buckets = list(aggregates.get("rules", {}).get("buckets", []))
    rule_buckets.extend(aggregates.get("priority_rules", {}).get("rules", {}).get("buckets", []))
    for bucket in rule_buckets:
        hits = bucket.get("event", {}).get("hits", {}).get("hits", [])
        source = hits[0].get("_source", {}) if hits else {}
        rule = source.get("rule", {})
        item = {"rule_id": str(bucket["key"]), "description": rule.get("description", ""),
                      "level": rule.get("level", 0), "groups": rule.get("groups", []), "mitre": rule.get("mitre"),
                      "count": bucket["doc_count"], "source_ips": [], "affected_agents": [],
                      "latest_agent": source.get("agent", {}),
                      "last_seen": source.get("@timestamp"), "count_scope": "index aggregation",
                      "analysis": explain_rule(rule)}
        existing = rules_by_id.get(item["rule_id"])
        if not existing or (item["level"], item["count"]) > (existing["level"], existing["count"]):
            rules_by_id[item["rule_id"]] = item
    rules = list(rules_by_id.values())
    decoders = []
    for bucket in aggregates.get("sources", {}).get("buckets", []):
        hits = bucket.get("event", {}).get("hits", {}).get("hits", [])
        source = hits[0].get("_source", {}) if hits else {}
        rule = source.get("rule", {})
        decoders.append({"name": str(bucket.get("key") or "unknown"), "count": int(bucket.get("doc_count") or 0),
            "max_level": int(bucket.get("max_level", {}).get("value") or rule.get("level") or 0),
            "latest_rule_id": str(rule.get("id") or ""), "latest_rule": rule.get("description") or "",
            "latest_agent": source.get("agent") or {}, "location": source.get("location"),
            "last_seen": source.get("@timestamp")})
    observables = {}
    for kind, field in IOC_FIELDS.items():
        for bucket in aggregates.get(kind, {}).get("buckets", []):
            value = str(bucket["key"])
            if observable_kind(kind) == "ip":
                try:
                    address = ipaddress.ip_address(value)
                    value = str(address)
                except ValueError:
                    pass
            key = (observable_kind(kind), value)
            public = public_indicator({"kind": key[0], "indicator": value})
            item = observables.setdefault(key, {"indicator": value, "kind": key[0], "public": public, "occurrences": 0, "fields": [], "rules": [], "level": 0})
            item["occurrences"] += bucket["doc_count"]
            item["fields"].append(field)
            item["rules"] = sorted(set(item["rules"] + [str(b["key"]) for b in bucket.get("rules", {}).get("buckets", [])]))
            item["level"] = max(item["level"], bucket.get("max_level", {}).get("value") or 0)
    total = result.get("hits", {}).get("total", {})
    observable_count = aggregates.get("with_observable", {}).get("doc_count", 0)
    return {"ok": not result.get("timed_out", False) and not result.get("_shards", {}).get("failed", 0),
            "range": label, "generated_at": datetime.now(timezone.utc).isoformat(),
            "coverage_mode": coverage_mode, "coverage_warning": coverage_warning,
            "index": "wazuh-alerts-*", "total_events": total.get("value", 0) if isinstance(total, dict) else total,
            "events_with_observable": observable_count, "fields_checked": list(IOC_FIELDS.values()),
            "rules": sorted(rules, key=lambda r: (r["level"], r["count"]), reverse=True),
            "rule_candidates": {"volume": len(aggregates.get("rules", {}).get("buckets", [])),
                                "priority": len(aggregates.get("priority_rules", {}).get("rules", {}).get("buckets", [])),
                                "unique": len(rules)},
            "other_rule_events": aggregates.get("rules", {}).get("sum_other_doc_count", 0),
            "rule_count_error_bound": aggregates.get("rules", {}).get("doc_count_error_upper_bound", 0),
            "observables": sorted(observables.values(), key=lambda r: (r["level"], r["occurrences"]), reverse=True),
            "observable_limit_per_field": 30,
            "severity": aggregates.get("severity", {}).get("buckets", []),
            "timeline": aggregates.get("timeline", {}).get("buckets", []),
            "sources": aggregates.get("sources", {}).get("buckets", []), "decoders": decoders,
            "mitre": aggregates.get("mitre", {}).get("buckets", []),
            "scope_note": "Agregasi seluruh alert terindeks pada rentang terpilih; bukan pembacaan arsip mentah. Rule volume tinggi dan rule level 10+ digabung tanpa duplikasi. Decoder dan kandidat indikator dibatasi agar query tetap aman. Enrichment hanya indikator yang diproses, bukan seluruh log."}


def vulnerability_inventory(search, payload):
    severity = payload.get("severity", "all")
    if severity not in {"all", "Critical", "High", "Medium", "Low"}:
        raise ValueError("Invalid severity")
    sort = payload.get("sort", "cve")
    if sort not in {"cve", "published"}:
        raise ValueError("Invalid inventory sort")
    offset = int(payload.get("offset", 0))
    if offset < 0 or offset > 9900:
        raise ValueError("Invalid offset")
    limit = int(payload.get("limit", 25))
    if limit < 1 or limit > 100:
        raise ValueError("Invalid limit")
    term = str(payload.get("search", "")).strip()
    if len(term) > 150:
        raise ValueError("Search is too long")
    filters = []
    if severity != "all":
        filters.append({"term": {"vulnerability.severity": severity}})
    if term:
        filters.append({"bool": {"should": [{"match_phrase": {field: term}} for field in
                         ["vulnerability.id", "agent.name", "agent.id", "package.name"]], "minimum_should_match": 1}})
    query = {"size": limit, "from": offset, "track_total_hits": True,
        "query": {"bool": {"filter": filters}},
        "sort": ([{"vulnerability.published_at": {"order": "desc", "unmapped_type": "date", "missing": "_last"}}] if sort == "published" else []) + [{"vulnerability.id": "asc"}, {"agent.id": "asc"}]}
    if payload.get("include_summary", True) is not False:
        query["aggs"] = {
            "inventory": {
                "global": {},
                "aggs": {
                    "severity": {"terms": {"field": "vulnerability.severity", "size": 10}},
                    "assets": {"cardinality": {"field": "agent.id"}},
                    "cves": {"cardinality": {"field": "vulnerability.id"}},
                    "published_90d": {
                        "filter": {"range": {"vulnerability.published_at": {"gte": "now-90d/d", "lte": "now"}}},
                        "aggs": {
                            "timeline": {
                                "date_histogram": {
                                    "field": "vulnerability.published_at", "fixed_interval": "1d",
                                    "min_doc_count": 0,
                                    "extended_bounds": {"min": "now-90d/d", "max": "now/d"},
                                },
                                "aggs": {
                                    "severity": {"terms": {"field": "vulnerability.severity", "size": 10}},
                                    "cves": {"cardinality": {"field": "vulnerability.id"}},
                                },
                            },
                        },
                    },
                },
            },
        }
    result = search(query, "wazuh-states-vulnerabilities-*")
    inventory = result.get("aggregations", {}).get("inventory", {})
    hits = result.get("hits", {})
    return {"ok": not result.get("timed_out", False) and not result.get("_shards", {}).get("failed", 0),
            "generated_at": datetime.now(timezone.utc).isoformat(), "index": "wazuh-states-vulnerabilities-*",
            "total": hits.get("total", {}).get("value", 0), "offset": offset, "limit": limit,
            "items": [{"record_id": h.get("_id"), **h.get("_source", {})} for h in hits.get("hits", [])],
            "inventory_total": inventory.get("doc_count", hits.get("total", {}).get("value", 0)), "severity": inventory.get("severity", {}).get("buckets", []),
            "assets": inventory.get("assets", {}).get("value", 0), "unique_cves": inventory.get("cves", {}).get("value", 0),
            "published_timeline": inventory.get("published_90d", {}).get("timeline", {}).get("buckets", [])}
