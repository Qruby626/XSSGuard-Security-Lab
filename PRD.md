# PRD — XSSGuard

**Product Requirements Document**
**Status:** Design Specification Alignment — Proposed
**Konteks:** Implementasi skripsi *"Integrasi Rule-Based Detection dan Content
Security Policy Nonce Dinamis untuk Mitigasi Stored Cross-Site Scripting"*

---

## 1. Ringkasan Eksekutif

`xssguard` adalah package Python yang dapat dipasang ke aplikasi web apa pun
(Flask, Django, Bottle, atau WSGI polos) untuk mendeteksi payload Stored XSS,
membangkitkan nonce CSP dinamis per-request melalui desain Trusted-Script Nonce, dan menganalisis laporan pelanggaran CSP dari browser. Untuk mekanisme Trusted-Script Nonce, XSSGuard mengekspos nonce
per-request kepada aplikasi host melalui API integrasi resmi; aplikasi host
bertanggung jawab menerapkan nonce tersebut hanya pada script yang dipercaya.

Produk ini lahir dari evaluasi pembimbing bahwa purwarupa sebelumnya hanya
berfungsi sebagai laboratorium simulasi XSS internal, bukan sistem yang benar-benar
bisa diterapkan ke sistem lain. `xssguard` menjawab kritik itu dengan portabilitas
sebagai syarat desain utama, bukan tambahan belakangan.

## 2. Latar Belakang & Masalah

Stored XSS tetap menjadi kerentanan umum pada aplikasi web yang menerima input
dinamis dari pengguna (forum, komentar, formulir, chat) dan menyimpannya untuk
ditampilkan kembali ke pengguna lain. Pendekatan mitigasi yang umum (rule-based
filtering saja, atau CSP saja) punya keterbatasan masing-masing bila berdiri
sendiri:

- Rule-based filtering saja rentan terhadap payload yang belum dikenali oleh aturan.
- CSP saja tidak memverifikasi efektivitasnya secara terukur di sisi server.

**Masalah produk**: belum ada mekanisme yang menggabungkan deteksi berbasis aturan
dengan penegakan CSP nonce dinamis *dan* validasi efektivitasnya lewat CSP
Violation Report, dikemas sebagai satu komponen yang bisa dipasang ke aplikasi
Python mana pun tanpa modifikasi besar.

## 3. Tujuan

- **T1.** Mendeteksi payload Stored XSS pada input request menggunakan pola aturan
  (regex) sebelum data diproses aplikasi host.
- **T2.** Membangkitkan nonce CSP unik per-request menggunakan CSPRNG,
  mengekspos nonce kepada aplikasi host melalui API integrasi resmi, dan
  menegakkannya lewat header `Content-Security-Policy`. Aplikasi host menerapkan
  nonce tersebut secara eksplisit hanya pada script yang dipercaya.
- **T3.** Menerima dan mencatat CSP Violation Report dari browser sebagai bukti
  pendukung bahwa pelanggaran terhadap kebijakan CSP dapat terdeteksi dan
  dilaporkan.
- **T4.** Portabel: terpasang ke aplikasi Python berbasis framework apa pun lewat
  WSGI, tanpa perubahan pada kode inti `xssguard`. Integrasi host dapat memerlukan
  perubahan pada template/kode aplikasi untuk menerapkan nonce pada trusted script.
- **T5.** Menyediakan dashboard pemantauan sederhana atas hasil deteksi dan laporan
  CSP untuk admin keamanan.

### Bukan Tujuan (Non-Goals)

- **Bukan** sistem pemblokiran IP otomatis. Mekanisme blocking berdasarkan IP tidak
  menjadi bagian dari produk maupun evaluasi penelitian. `client_ip` tetap boleh
  dicatat sebagai informasi sumber request untuk kebutuhan log/audit, tetapi tidak
  boleh digunakan untuk memblokir request, menghitung ambang pemblokiran, atau
  menentukan keputusan keamanan berbasis IP. Lihat `.agents/rules/rule.md` §3.
- **Bukan** sistem deteksi berbasis machine learning — pendekatan yang dipakai
  murni rule-based sesuai batasan penelitian.
- **Bukan** pengganti Web Application Firewall (WAF) tingkat jaringan — beroperasi
  di level aplikasi (WSGI), bukan di level reverse proxy/infrastruktur.
- **Bukan** sistem autentikasi/otorisasi untuk dashboard — akses dashboard
  diasumsikan sudah dilindungi oleh mekanisme keamanan Aplikasi Host sendiri.

## 4. Target Pengguna

| Aktor | Peran |
|---|---|
| **Developer** | Memasang dan mengonfigurasi `xssguard` ke Aplikasi Host miliknya |
| **Pengguna** | Pengunjung Aplikasi Host yang mengirim input (form, komentar, dst.) |
| **Browser** | Klien yang menegakkan CSP dan mengirim CSP Violation Report secara otomatis |
| **Admin Keamanan** | Memantau hasil deteksi dan laporan CSP lewat dashboard |

(Sesuai Use Case Diagram — `Rancangan_UseCase_Diagram_XSSGuard_revisi.docx`)

## 5. Ruang Lingkup Fungsional

### FR-1 — Rule-Based Detection
- Sistem memindai body request (form data/JSON) terhadap kumpulan pola serangan XSS.
- Setiap payload yang cocok dicatat: payload, aturan yang cocok, endpoint, IP
  pengirim sebagai informasi log/audit, dan waktu deteksi.
- IP pengirim tidak digunakan untuk melakukan pemblokiran atau keputusan keamanan
  berbasis IP.
- Payload yang tidak cocok pola apa pun tidak dicatat (tidak ada log "SAFE").
- **Kriteria penerimaan**: Detection Rate (DR) ≥ 80% terhadap dataset 30 payload
  uji (lihat §8).

### FR-2 — CSP Nonce Dinamis
- Sistem membangkitkan satu nonce baru untuk setiap request menggunakan CSPRNG
  (`secrets`/setara).
- Middleware mengekspos nonce melalui primitive API
  `environ["xssguard.nonce"]` sebelum host application dipanggil.
- Middleware menyisipkan nonce yang sama ke directive `script-src` pada header
  `Content-Security-Policy`.
- Middleware **tidak melakukan HTML rewriting** dan tidak menyisipkan nonce secara
  otomatis ke tag `<script>` pada response body.
- Aplikasi host bertanggung jawab menerapkan nonce tersebut secara eksplisit hanya
  pada trusted inline script. Pada Flask, nonce tersedia kepada template melalui
  context variable `xssguard_nonce`; pada raw WSGI, aplikasi dapat membacanya dari
  `environ["xssguard.nonce"]`.
- Response body diteruskan apa adanya; response non-HTML maupun HTML tidak diubah
  oleh middleware.
- **Kriteria penerimaan**: diverifikasi lewat **pengujian fungsional** dan
  integrasi, mencakup:
  1. Nonce berhasil dibuat untuk setiap request.
  2. Nilai nonce berbeda antar-request (dinamis, bukan statis).
  3. `environ["xssguard.nonce"]` tersedia bagi host application sebelum host
     application dipanggil.
  4. Nonce yang sama tersemat pada directive `script-src` di header
     `Content-Security-Policy`.
  5. Response body tidak diubah oleh middleware.
  6. Integrasi Flask dapat menyediakan nonce sebagai `xssguard_nonce` kepada
     template dan raw WSGI dapat mengakses nonce melalui `environ`.

### FR-3 — CSP Violation Report Analysis
- Sistem menyediakan endpoint yang menerima CSP Violation Report dari browser.
- Laporan yang valid (JSON dengan field yang tersedia) dicatat: resource URI yang
  diblokir oleh CSP (`blocked_uri`), directive yang dilanggar, URI dokumen, IP
  pengirim sebagai informasi log/audit, dan waktu.
- Laporan yang gagal diparsing dilewati tanpa dicatat — endpoint tetap
  mengembalikan `204 No Content` apa pun hasilnya (tidak ada respons error ke
  browser).
- **Kriteria penerimaan**: dievaluasi lewat **pengujian fungsional** (bukan metrik
  persentase), mencakup tiga poin:
  1. Endpoint CSP report menerima payload laporan yang valid, mem-parsing-nya
     dengan benar, dan mencatatnya lewat `store.log_csp_report()`.
  2. Endpoint tetap mengembalikan `204 No Content` untuk laporan yang gagal
     diparsing, tanpa mencatat apa pun.
  3. Pengujian browser E2E dapat membuktikan bahwa inline script tanpa nonce yang
     valid melanggar policy CSP dan dapat menghasilkan CSP Violation Report.

  Ketiga poin diverifikasi lewat pengujian parser/endpoint dan **functional browser
  E2E**. **Tidak ada target persentase untuk FR-3** — lihat §8 untuk alasannya.

### FR-4 — Portabilitas Lintas Aplikasi
- Mekanisme inti (deteksi, nonce, penerimaan laporan) berjalan sebagai WSGI
  Middleware — kompatibel dengan Flask, Django, Bottle, dan WSGI polos.
- Tersedia lapisan kenyamanan khusus Flask (`XSSGuard.init_app()`) yang membungkus
  middleware WSGI dan menyediakan akses nonce kepada template melalui
  `xssguard_nonce`.
- Aplikasi raw WSGI dapat mengakses nonce melalui `environ["xssguard.nonce"]`.
- **Kriteria penerimaan**: terbukti berjalan pada minimal dua aplikasi demo
  berbeda (`examples/flask_demo.py`, `examples/raw_wsgi_demo.py`) tanpa perubahan
  pada kode inti `xssguard`. Demo harus menunjukkan bahwa trusted script
  menggunakan nonce yang diekspos XSSGuard dan response body tidak dimodifikasi
  oleh middleware.

### FR-5 — Dashboard Pemantauan
- Menyediakan satu halaman ringkasan yang menampilkan hasil deteksi terbaru dan
  laporan CSP terbaru.
- Dashboard hanya membaca dari lapisan penyimpanan (`BaseStore`) — tidak pernah
  memanggil logika deteksi/nonce/parsing secara langsung, sehingga bisa
  dikembangkan dan diuji independen dari mekanisme inti.
- **Kriteria penerimaan**: diverifikasi lewat pengujian fungsional, memastikan
  halaman dashboard menampilkan baik entri `DetectionRecord` maupun
  `CspReportRecord` terbaru dari `BaseStore`.

## 6. Arsitektur (Ringkasan)

Modular monolith, empat kelompok/layer internal: **Core** (deteksi, nonce, parsing — pure Python),
**Storage** (`BaseStore` + `MemoryStore`), **Extension** (`XSSGuardMiddleware` +
`XSSGuard`), **Dashboard** (factory function, tanpa kelas).

Detail lengkap struktur kelas, interaksi antar-komponen, dan skema data ada di
enam dokumen UML (Class, Component, Sequence, ERD, Use Case, Activity Diagram —
semuanya versi "Revisi") dan aturan implementasi di `.agents/rules/rule.md`.
Dokumen-dokumen itu adalah sumber kebenaran struktural; PRD ini adalah sumber
kebenaran untuk *requirement*, bukan struktur kode.

### Prinsip Integrasi Trusted-Script Nonce

- XSSGuardMiddleware menghasilkan nonce CSPRNG per-request.
- Nonce diekspos sebelum host application dipanggil melalui
  `environ["xssguard.nonce"]`.
- Header CSP menggunakan nonce yang sama.
- Middleware tidak memodifikasi response body.
- Trusted inline script harus menerapkan nonce secara eksplisit dari API integrasi
  XSSGuard.
- Flask menggunakan `xssguard_nonce` sebagai context variable; raw WSGI menggunakan
  `environ["xssguard.nonce"]`.
- Keputusan trust berada pada aplikasi host/developer, bukan pada isi HTML
  user-controlled.


## 7. Batasan & Asumsi

- Implementasi default (`MemoryStore`) menyimpan data di memori proses — tidak
  persisten lintas restart. Cocok untuk skala skripsi; backend basis data
  sungguhan adalah pekerjaan lanjutan, bukan syarat kelulusan penelitian ini.
- Aplikasi host bertanggung jawab atas transportasi aman (HTTPS) — `xssguard`
  tidak menangani TLS.
- Python ≥ 3.9. Tidak ada dependency wajib di luar pustaka standar untuk modul
  inti; Flask hanya `optional-dependencies`.

## 8. Rencana Pengujian & Evaluasi

- **Dataset payload**: 30 payload XSS pada 4 kategori — Inline Script Injection
  (10), Event Handler Injection (10), Cookie Theft (5), DOM Manipulation (5).
- **Fitur input yang diuji**: forum diskusi, kolom komentar, formulir pengumuman
  akademik, chat sederhana.
- **Metrik kuantitatif**: hanya Detection Rate (DR), dengan ambang batas
  keberhasilan ≥ 80%.

  **Detection Rate (DR)**

  $$
  Detection\ Rate\ (DR) = \frac{Submission\ Terdeteksi}{Total\ Submission\ Diuji} \times 100\%
  $$

  Keterangan: `Submission Terdeteksi` adalah jumlah submission uji yang berhasil
  terdeteksi sebagai payload XSS oleh Rule-Based Detection. `Total Submission
  Diuji` adalah seluruh submission yang digunakan dalam dataset pengujian.

- **Evaluasi CSP: functional browser E2E wajib.** Efektivitas Trusted-Script Nonce dan CSP
  diuji pada browser nyata atau browser automation yang mampu menegakkan CSP.
  Minimal diuji:
  1. trusted inline script dengan nonce yang benar dapat dieksekusi;
  2. inline script tanpa nonce tidak dieksekusi;
  3. inline script dengan nonce yang salah tidak dieksekusi;
  4. Stored XSS yang dirender sebagai inline script tanpa nonce tidak dieksekusi;
  5. pelanggaran policy dapat menghasilkan CSP Violation Report yang diterima
     endpoint `/csp-report`.

  Indikator utama blocking adalah **payload tidak berhasil mengeksekusi
  JavaScript pada browser**. CSP Violation Report menjadi bukti pendukung bahwa
  browser mendeteksi pelanggaran policy, bukan satu-satunya bukti blocking.

  **Blocking Rate (BR) bukan acceptance criterion utama.** BR dapat dihitung
  sebagai metrik tambahan apabila dibutuhkan oleh metodologi penelitian, tetapi
  harus didasarkan pada hasil browser E2E dan didefinisikan bersama environment,
  payload, kondisi eksekusi, serta indikator keberhasilan/gagal eksekusi. Tidak ada
  target BR yang dikunci dalam PRD ini sebelum metodologi E2E disepakati.

  Dengan desain Trusted-Script Nonce, XSSGuard tidak lagi menyisipkan nonce secara
  otomatis ke seluruh tag `<script>`. Karena itu, evaluasi CSP mengukur enforcement
  policy pada boundary browser, bukan keberhasilan regex pada response body.

- **Metodologi**: Prototype Model — Requirement Gathering → Quick Design →
  **Prototype Development (tahap saat ini)** → Prototype Evaluation (Black Box
  Testing) → Refinement.

## 9. Risiko

| Risiko | Mitigasi |
|---|---|
| Fitur baru diam-diam memperluas scope (mis. IP blocking, autentikasi) | Setiap fitur baru dicek dulu terhadap §3 (Non-Goals) sebelum diimplementasikan |
| Kode dan diagram UML menyimpang seiring waktu | Revisi dokumen UML wajib di sesi yang sama dengan perubahan struktural (lihat `.agents/rules/rule.md` §5) |
| Nonce/CSP tidak konsisten pada response | Nonce dibuat sekali per-request, diekspos melalui `environ["xssguard.nonce"]`, dan nilai yang sama digunakan pada directive `script-src` |
| Trusted script tidak menggunakan nonce atau nonce salah | Integrasi Flask/raw WSGI dan pengujian browser E2E memastikan trusted script menggunakan nonce request yang benar |
| Attacker payload memperoleh nonce melalui automatic HTML rewriting | Automatic nonce injection dihapus; middleware tidak lagi memodifikasi response body, sehingga nonce hanya diterapkan secara eksplisit oleh aplikasi host pada trusted script |

## 10. Referensi

- `.agents/rules/rule.md` — aturan implementasi untuk AI coding agent
- `Class_Diagram_XSSGuard.docx`
- `Component_Diagram_XSSGuard.docx`
- `Sequence_Diagram_XSSGuard.docx`
- `ERD_XSSGuard.docx`
- `UseCase_Diagram_XSSGuard.docx`
- `Activity_Diagram_XSSGuard.docx`
