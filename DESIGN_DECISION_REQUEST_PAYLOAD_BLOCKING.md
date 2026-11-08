# DESIGN DECISION — REQUEST / PAYLOAD BLOCKING

**Proyek:** XSSGuard (Python / Flask WSGI Middleware)
**Versi Dokumen:** 1.1 (Design Corrected After Source-Code Audit)
**Tanggal:** 2026-09-25
**Status:** Pending Final Approval Before Implementation
**Sumber Utama:** Hasil Audit Mendalam Source Code XSSGuard (2026-09-25)

---

## DAFTAR ISI

1. [Definisi Status](#1-definisi-status)
2. [Blocking Policy](#2-blocking-policy)
3. [Enforcement Point](#3-enforcement-point)
4. [Blocking Flow](#4-blocking-flow)
5. [HTTP 403 Design](#5-http-403-design)
6. [CSP Dynamic Nonce](#6-csp-dynamic-nonce)
7. [Logging / Evidence](#7-logging--evidence)
8. [Feature Flag](#8-feature-flag)
9. [/csp-report Treatment](#9-csp-report-treatment)
10. [SAFE Request Guarantee](#10-safe-request-guarantee)
11. [Academic Lab Integration](#11-academic-lab-integration)
12. [File Impact Analysis](#12-file-impact-analysis)
13. [Database / Storage Impact](#13-database--storage-impact)
14. [Security Considerations](#14-security-considerations)
15. [Testing Strategy](#15-testing-strategy)
16. [Bukti Route Tidak Dieksekusi](#16-bukti-route-tidak-dieksekusi)
17. [UML Impact](#17-uml-impact)
18. [Design Principles](#18-design-principles)
19. [Final Architectural Decision](#19-final-architectural-decision)
20. [Implementation Checklist](#20-implementation-checklist)

---

## LATAR BELAKANG

Berdasarkan audit mendalam source code XSSGuard per 2026-09-25, dikonfirmasi bahwa:

1. Rule-Based XSS Detection Engine sudah berjalan dan teruji (30 payload benchmark = 100% Detection Rate).
2. Security Logging / Evidence sudah tersimpan melalui BaseStore Protocol.
3. CSP Dynamic Nonce sudah terintegrasi melalui environ["xssguard.nonce"] dan Content-Security-Policy header.
4. CSP Violation Report Endpoint (`/csp-report`) sudah menerima dan memparsing laporan pelanggaran browser.
5. **Request / Payload Blocking BELUM diimplementasikan.** Request yang mengandung payload terdeteksi (status DETECTED) tetap 100% diteruskan ke Flask Application. HTTP 403 Forbidden belum ada sama sekali.

Dokumen ini menetapkan keputusan arsitektur dan teknis SEBELUM implementasi kode dilakukan. Dokumen BUKAN kode implementasi.

---

## 1. DEFINISI STATUS

### 1.1 Status Formal — Dua Dimensi Terpisah

Untuk mempertahankan **Separation of Concerns**, status didefinisikan dalam DUA dimensi yang independen:

| Dimensi | Status | Definisi Formal | Pemilik Komponen |
|---------|--------|-----------------|-----------------|
| **Detection Status** (Apa yang ditemukan detector?) | `SAFE` | Tidak ada satupun `DEFAULT_XSS_PATTERNS` yang cocok terhadap payload input setelah normalisasi `html.unescape()`. | `detector.py` — Rule-Based Detector |
| | `DETECTED` | Sekurang-kurangnya satu pattern regex cocok dengan payload (first-match-wins). | `detector.py` — Rule-Based Detector |
| **Enforcement Action** (Apa yang dilakukan middleware?) | `ALLOWED` | Request diteruskan ke Flask Application tanpa interupsi. | `middleware.py` — WSGI Enforcement Point |
| | `BLOCKED` | Request dihentikan sebelum mencapai Flask Route. Client menerima HTTP 403 Forbidden. | `middleware.py` — WSGI Enforcement Point |

### 1.2 Hubungan Antarstatus

```
Detection Status        Feature Flag          Enforcement Action
(SAFE / DETECTED)    (blocking_enabled)       (ALLOWED / BLOCKED)
       │                      │                         │
       │                      │                         │
       ▼                      ▼                         ▼

  ┌─────────┐            ┌───────────┐            ┌──────────────┐
  │  SAFE   │───────────►│  ANY      │───────────►│   ALLOWED    │
  └─────────┘            └───────────┘            └──────────────┘
                                                              │
  ┌──────────┐           ┌───────────────┐                     │
  │ DETECTED │──────────►│     FALSE     │─────────────────────┘
  └──────────┘           │ (log-only /   │
       │                 │  monitor-only)│
       │                 └───────────────┘
       │
       │                 ┌───────────────┐            ┌──────────────┐
       └────────────────►│     TRUE      │───────────►│   BLOCKED    │
                         │ (enforce)     │            └──────────────┘
                         └───────────────┘
                         (AND request TIDAK
                          dalam whitelist
                          pengecualian)
```

### 1.3 Jawaban Eksplisit: Apakah DETECTED Selalu Berarti BLOCKED?

**TIDAK.** `DETECTED` (dimensi detection) TIDAK SELALU berarti `BLOCKED` (dimensi enforcement). Kondisinya:

| Kombinasi | Kapan Terjadi? | Penjelasan |
|-----------|---------------|-----------|
| `DETECTED → ALLOWED` | Ketika `blocking_enabled = false` (default awal, log-only mode). | Detection berjalan, evidence disimpan, namun request tetap mencapai Flask Application. Ini adalah perilaku XSSGuard SAAT INI sebelum fitur blocking dirilis. Juga berlaku ketika endpoint masuk daftar pengecualian (whitelist). |
| `DETECTED → BLOCKED` | Ketika `blocking_enabled = true` DAN request TIDAK dikecualikan. | Detection berjalan, evidence disimpan DENGAN tindakan `action = "BLOCKED"`, lalu middleware mengembalikan HTTP 403 dan TIDAK memanggil `self.app(environ, ...)`. |

### 1.4 Terminologi

Dokumen ini **tidak menggunakan `LOGGED` sebagai status atau action**.

Terminologi resmi yang dibekukan:
- `SAFE` / `DETECTED` = **Detection Status**.
- `ALLOWED` / `BLOCKED` = **Enforcement Action**.
- `DETECTED + ALLOWED` berarti detection terjadi tetapi request tetap diteruskan.
- `DETECTED + BLOCKED` berarti detection terjadi dan request dihentikan dengan HTTP 403.

Istilah `LOGGED` hanya boleh digunakan sebagai kata kerja/deskripsi proses pencatatan, bukan sebagai nilai status/action.

---

## 2. BLOCKING POLICY

### 2.1 Kebijakan Default (MVP)

```
JIKA DetectionResult list TIDAK KOSONG (length > 0)
  DAN
  blocking_enabled = true
  DAN
  PATH_INFO request TIDAK TERMASUK dalam blocking_exclude_paths
  DAN
  request TIDAK memenuhi kriteria pengecualian valid lainnya
MAKA
  ACTION = BLOCKED
  DAN
  request dihentikan dengan HTTP 403 Forbidden
  DAN
  Flask Application Route TIDAK PERNAH dipanggil
```

### 2.2 Keputusan Eksplisit

**Blocking terjadi SEBELUM Flask Route dieksekusi.**

Secara teknis, ini berarti middleware melakukan early return **SEBELUM** baris kode:

```
return self.app(environ, custom_start_response)
```

pada `XSSGuardMiddleware.__call__()` dieksekusi.

### 2.3 Pengecualian (Whitelist)

- **Alasan:** Ada skenario di mana endpoint LAB atau ADMIN memang dirancang untuk menerima payload XSS (misal: sandbox pengujian stored XSS).
- **Implementasi konseptual:** Daftar `blocking_exclude_paths: list[str] = []` sebagai parameter constructor opsional.
- **Ruang lingkup:** Hanya berlaku untuk path; TIDAK berlaku untuk IP, User-Agent, atau parameter lain (untuk menghindari whitelist bypass yang terlalu luas).
- **Nilai default:** `[]` (kosong, artinya tidak ada pengecualian).
- **Risiko bypass:** Harus didokumentasikan bahwa path dalam whitelist tidak akan ter-protect. Pengguna LAB diingatkan untuk mengisi `blocking_exclude_paths` jika menggunakan fixture seperti `d4_stored_xss_fixture.py`.

---

## 3. ENFORCEMENT POINT

### 3.1 Lokasi yang Ditetapkan

```
XSSGuardMiddleware.__call__(environ, start_response)
```

File: [middleware.py](file:///e:/XSSGuard-Security-Lab/xssguard/middleware.py#L96-L157)

### 3.2 Mengapa Middleware Dipilih?

1. **Wewenang WSGI Penuh:** Middleware adalah WSGI callable yang memiliki wewenang untuk:
   - Membaca seluruh request (query, body, form, JSON)
   - Memanggil `start_response(status, headers)` dengan status apapun (termasuk 403)
   - Mengembalikan `Iterable[bytes]` langsung TANPA memanggil upstream `self.app`
2. **Titik Tunggal:** Semua request (query string, form, JSON, raw body) melewati middleware SEBELUM Flask routing. Tidak ada celah request yang bisa mencapai route tanpa discan.
3. **Framework Agnostic:** Middleware bekerja untuk Flask DAN raw WSGI. Terbukti dari `raw_wsgi_demo.py` yang tidak menggunakan Flask sama sekali.
4. **Urutan Dasar Dipertahankan:** Middleware tetap melakukan detection → nonce preparation → blocking decision → detection evidence logging → response branch. Perubahan blocking tidak mengubah detector dan tidak menempatkan enforcement setelah `self.app`.

### 3.3 Mengapa Blocking TIDAK Dilakukan di Lokasi Lain?

| Lokasi Kandidat | Alasan TIDAK Cocok | Konsistensi Audit |
|-----------------|-------------------|------------------|
| **`detector.py`** | Detector adalah Core Layer framework-agnostic. Tidak tahu objek HTTP, tidak tahu Flask, tidak boleh import werkzeug/flask. Kontrak detector hanya: scan string → return DetectionResult. ✅ Sesuai audit: detector tetap pure detection. | Audit line 3 detector docstring: "framework-agnostic and must not import Flask, SQLAlchemy, or any request/response framework object." |
| **`patterns.py`** | Hanya konstanta list regex. Tidak memiliki execution flow. Tidak mungkin menjadi enforcement point. | ✅ Sesuai. |
| **Route Academic Lab** | Setiap route (forum, comment, chat, announcement, chat) TIDAK BOLEH memiliki logic blocking sendiri. Alasan: (a) Duplikasi logic, (b) Human error ketika developer lupa menambahkan decorator, (c) Tidak konsisten. Jika enforcement di middleware, route TIDAK PERLU diubah = 0 regression risk pada route. | Audit rekomendasikan routes "tidak seharusnya mengetahui mekanisme blocking." ✅ |
| **Chrome Extension** | Extension MV3 adalah **Passive Monitoring / Visualizer**. Secara trust boundary, attacker dapat disable extension, pakai curl/Postman, atau browser lain untuk melewati extension. Invariant service_worker.js: "No blocking handlers, no BlockingResponse, no cancel/redirect." | Audit dan invariant extension code TEGAS menyatakan ini. ✅ |
| **Browser (Client-Side)** | Browser enforcement = CSP Dynamic Nonce. Ini mem-block EKSEKUSI SCRIPT di RESPONSE HTML, BUKAN request HTTP yang masuk. Stored XSS payload tetap akan tersimpan di database jika hanya mengandalkan browser. Dua mekanisme berbeda lapisan. | ✅ Sesuai prinsip: CSP ≠ Server-Side Request Blocking. |

---

## 4. BLOCKING FLOW

### 4.1 Alur Umum

Alur berikut dibekukan agar konsisten dengan lifecycle source code XSSGuard saat ini. Source code saat ini memang menghasilkan nonce **untuk setiap request** sebelum `self.app(...)`; desain blocking tidak mengubah prinsip tersebut. Decision point ditempatkan setelah nonce tersedia di `environ`, sebelum `self.app(...)`.

```
HTTP Request (Client)
    │
    ▼
WSGI Server (Werkzeug / Gunicorn)
    │
    ▼
XSSGuardMiddleware.__call__(environ, start_response)
    │
    ├─ Step 1: Read request body + Replay wsgi.input
    │
    ├─ Step 2: Extract Request → dict
    │
    ├─ Step 3: Rule-Based Detection → DetectionResult list
    │
    ├─ Step 4: Generate CSP Dynamic Nonce (existing lifecycle)
    │       └── environ["xssguard.nonce"] = nonce
    │
    ├─ Step 5: Evaluate Blocking Decision
    │       │
    │       ├─ SAFE
    │       │      └──► action = ALLOWED
    │       │
    │       ├─ DETECTED + blocking_enabled = FALSE
    │       │      └──► action = ALLOWED
    │       │
    │       ├─ DETECTED + excluded path
    │       │      └──► action = ALLOWED
    │       │
    │       └─ DETECTED + blocking_enabled = TRUE + non-excluded path
    │              └──► action = BLOCKED
    │
    ├─ Step 6: Security Logging
    │       └── DetectionRecord diisi action = ALLOWED / BLOCKED
    │
    ├─ Step 7A: BLOCKED
    │       └──► HTTP 403 → EARLY RETURN
    │                    Flask Route TIDAK DIPANGGIL
    │
    └─ Step 7B: ALLOWED
            ├──► define/use custom_start_response
            └──► self.app(environ, custom_start_response)
                         │
                         └──► Flask Application / Route
```

**Keputusan penting:** `generate_nonce()` **tidak lagi ditempatkan setelah blocking decision dalam dokumentasi**. Hal ini mengikuti lifecycle source code aktual dan menghilangkan kontradiksi antara Bagian 4, 5, dan 6. Nonce yang sudah tersedia pada blocked request tidak berarti request diteruskan; nonce hanya merupakan data environment yang sudah disiapkan sebelum enforcement branch.

### 4.2 Alur Detail — KASUS A: SAFE Request

```
Client → GET /search?q=hello+world
  │
  ▼
Middleware:
  body_bytes = b""
  data = {"q": "hello world"}
  results = scan_mapping(data) → [] (empty list = SAFE)
  │
  ▼
  nonce = generate_nonce()
  environ["xssguard.nonce"] = nonce
  │
  ▼
  Decision: results kosong → tidak dibuat DetectionRecord
  │
  ▼
  self.app(environ, custom_start_response)
        │
        ▼
  Flask Route Handler → render template
        │
        ▼
  custom_start_response: append Content-Security-Policy header
        │
        ▼
  HTTP 200 + HTML + CSP + nonce cocok dengan {{ xssguard_nonce }}
```
### 4.3 Alur Detail — KASUS B: DETECTED + ALLOWED (Log-Only Mode / blocking_enabled=FALSE)

```
Client → POST /comment dengan body "text=<script>alert(1)</script>"
  │
  ▼
Middleware:
  body_bytes = b"text=%3Cscript%3Ealert(1)%3C/script%3E"
  data = {"text": "<script>alert(1)</script>"}
  results = [DetectionResult(status="DETECTED", matched_rule=r"(?i)<\s*/?\s*script\b", ...)]
  │
  ▼
  nonce = generate_nonce()
  environ["xssguard.nonce"] = nonce
  │
  ▼
  Decision: results ada + blocking_enabled=FALSE → ALLOWED
  │
  ▼
  Create DetectionRecord(action="ALLOWED")
  store.log_detection(record)
  │
  ▼
  self.app(environ, custom_start_response)
        │
        ▼
  Flask Route /comment → simpan payload ke DB (stored XSS terjadi di app layer)
        │
        ▼
  Response HTML
        │
        ▼
  Browser menerima response → CSP memblokir script TANPA nonce (defense layer-2)
        │
        ▼
  Browser mengirim CSP Violation Report → POST /csp-report
```

**Ini adalah perilaku XSSGuard SAAT INI (sebelum blocking diimplementasikan).**

### 4.4 Alur Detail — KASUS C: DETECTED + BLOCKED (Enforcement Mode / blocking_enabled=TRUE)

```
Client → POST /comment dengan body "text=<script>alert(1)</script>"
  │
  ▼
Middleware:
  body_bytes = b"text=%3Cscript%3Ealert(1)%3C/script%3E"
  data = {"text": "<script>alert(1)</script>"}
  results = [DetectionResult(status="DETECTED", matched_rule=r"(?i)<\s*/?\s*script\b", ...)]
  │
  ▼
  nonce = generate_nonce()
  environ["xssguard.nonce"] = nonce
  │
  ▼
  Decision: results ADA + blocking_enabled=TRUE + /comment TIDAK di-whitelist → BLOCKED
  │
  ▼
  Create DetectionRecord(action="BLOCKED")
  store.log_detection(record)
      │
      └──► BLOCKED BRANCH (EARLY RETURN)
             │
             ├─ Generate HTTP 403 response body (text/html, informatif, di-escape)
             ├─ Set Content-Type header
             ├─ start_response("403 Forbidden", headers)
             │   (OPSI: tetap menyertakan CSP header untuk konsistensi)
             │
             └─ return [b"<html>...Request Blocked...</html>"]
                    │
                    ▼
             Flask Route /comment TIDAK DIPANGGIL
             Payload TIDAK disimpan oleh route target
```

**Invarian:** `generate_nonce()` hanya dipanggil satu kali. Setelah `store.log_detection(record)`, branch BLOCKED melakukan early return dan tidak pernah mencapai `self.app(...)`.

### 5.1 Spesifikasi Response Minimum

| Komponen | Nilai yang Ditetapkan |
|----------|----------------------|
| **HTTP Status Code** | `403 Forbidden` |
| **HTTP Reason Phrase** | `Forbidden` (mengikuti RFC 7231 standar WSGI) |
| **Content-Type** | `text/html; charset=utf-8` |
| **Content-Length** | Dihitung otomatis dari response body bytes (atau biarkan WSGI server menentukan berdasarkan chunk). |
| **CSP Header** | **DISERTAKAN** (opsi direkomendasikan) — tetap gunakan `custom_start_response` wrapper untuk konsistensi, walaupun body 403 tidak membutuhkan trusted script. (Alasan: uniformity response header, CSP tidak merugikan, defense-in-depth jika 403 page memiliki static resource referensi.) |
| **CSP Nonce pada 403** | **TIDAK DIPERLUKAN secara fungsional untuk body 403.** Namun nonce sudah tersedia pada `environ` karena mengikuti lifecycle middleware existing. Jika CSP header 403 menyertakan nonce, gunakan nonce yang sudah tersedia; jangan memanggil `generate_nonce()` kedua kali. |

### 5.2 Bentuk Response Body (Konseptual)

Body 403 harus:

1. **Sederhana dan informatif** — Jelaskan secara singkat request diblokir karena mengandung indikasi XSS.
2. **TIDAK memuat payload mentah** — Jika ingin menampilkan field / rule yang memicu blocking, WAJIB melakukan HTML escaping terlebih dahulu pada matched_rule dan nama field.
3. **TIDAK memuat link balik otomatis** yang dapat menyebabkan attacker melakukan phishing redirect.
4. **TIDAK memuat script inline apapun** (agar tidak butuh nonce sama sekali, walaupun CSP header tetap ada).

**Konsep body minimum:**

```html
<!DOCTYPE html>
<html lang="en">
<head><title>403 Forbidden — XSSGuard</title></head>
<body>
  <h1>403 Forbidden</h1>
  <p>Your request has been blocked by XSSGuard.</p>
  <p>Reason: Potential XSS payload detected in request input.</p>
  <p>Reference: matched rule pattern (escaped).</p>
  <hr>
  <small>XSSGuard Security Enforcement</small>
</body>
</html>
```

### 5.3 Keputusan: Apakah 403 Membutuhkan CSP Dynamic Nonce?

**TIDAK DIPERLUKAN secara fungsional.** Nonce sudah dibuat sebelum decision point karena mengikuti lifecycle middleware existing. Nonce tersebut tidak dipakai oleh body 403. Jika CSP header disertakan, gunakan nonce yang sudah tersedia.

Alasan:
- Blocked request berhenti sebelum Flask Application. Body 403 adalah static error page. Tidak ada script aplikasi yang harus diberi trust attribute.
- Tetap menyertakan CSP header → uniformity. Tidak ada downsides.
- Jika nantinya 403 page direferensikan dari static asset (CSS, image), directive default-src 'self' melindungi.

---

## 6. CSP DYNAMIC NONCE

### 6.1 Prinsip Dasar yang Dipertahankan

| Mekanisme | Lapisan | Tujuan | Hubungan dengan Request Blocking |
|-----------|---------|--------|-------------------------------|
| **CSP Dynamic Nonce** | Browser-Side (Enforcement terhadap Response) | Menandai inline script MANA yang boleh dieksekusi oleh browser (trusted script yang diberi nonce melalui template `{{ xssguard_nonce }}`). Script tanpa nonce / nonce salah = diblokir browser. | **INDEPENDEN.** Nonce adalah perlindungan terhadap STORED / REFLECTED XSS yang sudah terlanjur lolos ke response HTML. |
| **Request / Payload Blocking** | Server-Side (Enforcement terhadap Request Masuk) | Menghentikan HTTP request YANG MASIH di perbatasan middleware, SEBELUM payload menyentuh route handler, database, atau template. | **INDEPENDEN.** Blocking mencegah payload masuk sama sekali. |

**Dua mekanisme ini berjalan di layer berbeda dan saling melengkapi (defense-in-depth):**
- Jika blocking = false positive (payload aman ter-block) → user gagal submit, tapi data aman.
- Jika blocking = false negative (payload XSS lolos) → CSP nonce + browser enforcement menahan eksekusi script di response, dan CSP violation report dikirim ke `/csp-report`.

### 6.2 Urutan Eksekusi yang Ditetapkan

**URUTAN FINAL — SELARAS DENGAN LIFECYCLE SOURCE CODE:**

```
Step 1: Read / replay request body
    ↓
Step 2: Extract + Detection
    ↓
Step 3: Generate Dynamic Nonce sekali per request
    ↓
Step 4: environ["xssguard.nonce"] = nonce
    ↓
Step 5: Evaluate Blocking Decision
    │
    ├── SAFE / DETECTED + ALLOWED
    │       ↓
    │   action = "ALLOWED"
    │       ↓
    │   Security Logging
    │       ↓
    │   custom_start_response
    │       ↓
    │   self.app(environ, custom_start_response)
    │
    └── DETECTED + BLOCKED
            ↓
        action = "BLOCKED"
            ↓
        Security Logging
            ↓
        HTTP 403 EARLY RETURN
        self.app(...) TIDAK DIPANGGIL
```

**Alasan keputusan:** source code existing menghasilkan nonce sebelum membuat `custom_start_response` dan sebelum `self.app(...)`. Agar perubahan blocking minimal, fitur baru ditempatkan setelah nonce tersedia di `environ`, lalu menentukan action dan enforcement branch.

**Invariant:** `generate_nonce()` hanya dipanggil **satu kali per request**. Blocking branch tidak boleh memanggil `generate_nonce()` kedua kali.

### 6.2.1 Invariant Urutan Logging dan Enforcement

Untuk menghindari ambiguitas implementasi, urutan berikut adalah **satu-satunya urutan kanonik** untuk middleware:

```
Detection
    ↓
Generate nonce tepat satu kali
    ↓
Set environ["xssguard.nonce"]
    ↓
Determine action
    ↓
Create DetectionRecord(action)
    ↓
store.log_detection(record)
    ↓
┌───────────────────────────────┐
│ action = "BLOCKED"             │ → HTTP 403 early return; self.app TIDAK dipanggil
│ action = "ALLOWED"             │ → custom_start_response → self.app(...)
└───────────────────────────────┘
```

**Catatan SAFE:** jika `results` kosong, tidak dibuat `DetectionRecord`; request langsung melanjutkan ke `self.app(...)` setelah nonce tersedia.

**Catatan penting:** `action = "ALLOWED"` tidak hanya berarti `blocking_enabled=False`; action ini juga berlaku ketika `blocking_enabled=True` tetapi `PATH_INFO` termasuk `blocking_exclude_paths`.

---

### 6.3 Urutan yang DITOLAK

Skema berikut **tidak dipakai** karena tidak konsisten dengan lifecycle source code existing:

```
❌ Detection → Blocking Decision → Generate Nonce
```

Skema berikut juga **dilarang**:

```
❌ Generate Nonce → Blocking Decision → Generate Nonce lagi pada BLOCKED branch
```

Alasan: satu request harus memiliki satu dynamic nonce yang dihasilkan satu kali oleh middleware.

---

## 7. LOGGING / EVIDENCE

### 7.1 Pemisahan Detection vs Enforcement Action

Dokumen ini TEGAS mempertahankan:

| Data Object | Tujuan | Dimensi | Dimodifikasi? |
|-------------|--------|---------|--------------|
| **DetectionResult** (di `detector.py`) | Mengembalikan hasil scan string terhadap patterns. | Detection (`SAFE` / `DETECTED`) | **TIDAK BOLEH DIUBAH** menambah field HTTP atau enforcement. Detector harus tetap framework-agnostic pure. |
| **DetectionRecord** (di `storage.py`) | Bukti tersimpan bahwa suatu detection terjadi pada suatu request, DAN tindakan apa yang diambil middleware. | Detection status + **Enforcement Action** (ALLOWED / BLOCKED) | **WAJIB DITAMBAH FIELD BARU** (field `action`) untuk membedakan kedua skenario. |

### 7.2 Kebutuhan Field Baru pada DetectionRecord

Berdasarkan audit: field `status` saat ini redundan (nilainya selalu `"DETECTED"` karena `scan_mapping()` hanya mengembalikan DETECTED). Kita TIDAK MENGUBAH makna `status` (backward compat). Sebagai gantinya:

| Field Baru | Tipe Konseptual | Makna | Possible Values | Default | Kapan Diisi |
|-----------|----------------|-------|-----------------|---------|-------------|
| **`action`** | `Optional[str]` | Tindakan enforcement yang diambil oleh middleware setelah detection. | `"ALLOWED"`: Request diteruskan ke Flask App (log-only / safe).<br>`"BLOCKED"`: Request dihentikan dengan HTTP 403.<br>`None`: Rekaman lama sebelum field ini ada (backward compat). | `None` | Selalu di-isi oleh middleware pada saat `log_detection(...)`. |

**Alternatif nama field (jika lebih disukai, tapi prioritas = `action`):**
- `enforcement_result` (lebih eksplisit tapi panjang)
- `blocked: Optional[bool]` (nilai `True` / `False` / `None`, tapi tidak bisa membedakan "diblokir" vs "aman" vs "legacy" dengan jelas → **TIDAK DIPILIH**)

### 7.3 Contoh Evidence Setelah Perubahan

**Logika pengisian di middleware (KONSEPTUAL, bukan kode):**

```
untuk setiap result dalam results:

    JIKA blocking_enabled = FALSE:
        record.action = "ALLOWED"

    JIKA blocking_enabled = TRUE DAN PATH_INFO ada di blocking_exclude_paths:
        record.action = "ALLOWED"

    JIKA blocking_enabled = TRUE DAN PATH_INFO TIDAK ada di blocking_exclude_paths:
        record.action = "BLOCKED"

    store.log_detection(record)
```

Untuk SAFE request (results = []), saat ini **TIDAK ADA record DetectionRecord** sama sekali (invariant scan_mapping). Desain ini TIDAK DIUBAH (menghindari log explosion dari safe traffic).

### 7.4 Contoh Perbandingan Records

| Skenario | DetectionRecord.status | DetectionRecord.action | DetectionRecord.matched_rule |
|----------|----------------------|----------------------|----------------------------|
| Safe request | — (tidak ada record) | — | — |
| XSS `<script>` detected + blocking OFF | `"DETECTED"` | `"ALLOWED"` | `(?i)<\s*/?\s*script\b` |
| XSS `<img onerror>` detected + blocking ON | `"DETECTED"` | `"BLOCKED"` | `(?i)\bon[a-z][a-z0-9_-]*\s*=` |
| Legacy record (sebelum upgrade) | `"DETECTED"` | `None` | `(?i)\bdocument\s*\.\s*cookie\b` |

---

## 8. FEATURE FLAG

### 8.1 Desain

```
blocking_enabled: bool = false
```

**Default awal = FALSE (Log-Only / Monitor-Only Mode).**

### 8.2 Konsekuensi Nilai Flag

| Nilai `blocking_enabled` | Detection Berjalan? | Logging Evidence Berjalan? | Request Diteruskan? | HTTP 403 Muncul? |
|--------------------------|--------------------|--------------------------|-------------------|-----------------|
| **`false`** (default) | ✅ Ya | ✅ Ya, `action = "ALLOWED"` untuk yang DETECTED | ✅ Ya, selalu mencapai `self.app(...)` | ❌ Tidak pernah |
| **`true`** (enforce) | ✅ Ya | ✅ Ya, `action = "BLOCKED"` untuk yang DETECTED | ❌ Tidak, jika ada DetectionResult + tidak di whitelist | ✅ Ya, untuk request terdeteksi |

### 8.3 Lokasi Parameter

| Class | Parameter Constructor |
|-------|----------------------|
| `XSSGuardMiddleware.__init__()` | `blocking_enabled: bool = False` |
| `XSSGuard` (Flask Extension) `.__init__()` dan `init_app()` | `blocking_enabled: bool = False` → diteruskan ke middleware |

### 8.4 Alasan Default OFF (Minimal Change + Safe Rollout)

1. **Backward Compatibility:** Existing integrasi (contoh: `flask_demo.py`, fixture E2E, apps Academic Lab) akan berjalan PERSIS tanpa perubahan perilaku. Tidak ada test regression yang gagal karena upgrade.
2. **Regression Testing:** Developer dapat meng-enable `blocking_enabled=True` di staging environment terlebih dahulu, membandingkan detection false positive selama beberapa minggu (shadow mode dengan `action="ALLOWED"`), sebelum benar-benar enforce.
3. **Safe Rollout:** Jika tiba-tiba terjadi false positive masif, user hanya perlu flip flag ke False tanpa rollback kode.
4. **Validasi Detection Existing Tidak Rusak:** Karena default OFF, detection flow yang sudah stabil 100% tidak berubah. Dapat memverifikasi tidak ada perubahan DR (Detection Rate) pada benchmark 30 payload.

### 8.5 UI Toggle

**TIDAK DIPERLUKAN untuk MVP.** Toggle berupa constructor parameter / app config sudah cukup. UI dapat ditambahkan kemudian jika ada kebutuhan.

---

## 9. /csp-report TREATMENT

### 9.1 Tiga Mekanisme Terpisah

TIDAK BOLEH dicampuraduk:

| ID | Mekanisme | Lapisan | Tujuan |
|----|----------|---------|--------|
| 1 | **Server-Side Request/Payload Blocking** | Python WSGI Middleware | MENCEGAH request HTTP mengandung XSS mencapai Flask App (fitur BARU yang didesain di dokumen ini). |
| 2 | **Browser-Side CSP Enforcement** | User Browser (Chrome/Firefox/Edge) | MEMBLOKIR eksekusi inline script TANPA nonce / nonce salah pada RESPONSE HTML. |
| 3 | **CSP Violation Reporting** | Browser POST JSON → Endpoint `/csp-report` → Flask → Storage | MENGIRIM BUKTI pelanggaran CSP (dari mekanisme #2) ke server untuk audit post-hoc. |

### 9.2 Perlakuan terhadap Endpoint `/csp-report`

**KEPUTUSAN FINAL:** `/csp-report` dan custom CSP report path **WAJIB diperlakukan sebagai excluded path** pada enforcement middleware.

**Alasan:** Struktur CSP violation report JSON:
- Keys: `document-uri`, `violated-directive`, `blocked-uri`, `original-policy`, dll.
- Value: adalah string URL, directive CSP (contoh: `"script-src-elem"`), dan string policy.
- Tidak ada field apapun dalam standar CSP report JSON yang nilainya akan match dengan `DEFAULT_XSS_PATTERNS`.
- Contoh: `"script-src-elem"` tidak mengandung `onerror=`, `document.cookie`, `<script`, `javascript:`, dll.

**Namun demikian, untuk keamanan desain:**

**Whitelist path `/csp-report` SECARA EKSPLISIT direkomendasikan sebagai safety net.** Detail:

| Komponen Whitelist | Nilai |
|-------------------|-------|
| **Endpoint** | `/csp-report` (path default dari `register_csp_report_route()`), DAN custom path apapun yang diberikan user ke parameter `path` di fungsi tersebut. |
| **Alasan** | CSP report adalah POST dari browser berisi data pelanggaran. Walaupun kemungkinan match XSS pattern sangat tipis, kita TIDAK BOLEH memblokir data audit trail. Ini adalah "safety mechanism" — jika suatu hari attacker berhasil injeksi data ke field CSP report yang mengandung pattern, endpoint tetap berjalan. Pemisahan mekanisme adalah prinsip yang harus dijunjung. |
| **Scope** | Hanya berlaku untuk POST request ke path `/csp-report` (atau custom path). |
| **Risiko Bypass** | RENDAH. Attacker dapat POST ke `/csp-report` dengan payload XSS, namun: (a) endpoint `/csp-report` TIDAK MENYIMPAN payload ke DetectionRecord table (hanya ke CspReportRecord), (b) field CSP report TIDAK PERNAH di-render kembali ke response browser sebagai HTML. |

**Mekanisme yang dibekukan untuk implementasi:** source code saat ini **belum** memiliki auto-exclude tersebut. Karena itu mekanisme harus dibuat eksplisit pada integrasi Flask Extension, bukan diasumsikan sudah tersedia.

Kontrak implementasi minimal:
1. `register_csp_report_route(...)` tetap mendaftarkan route seperti sekarang.
2. Path yang benar-benar didaftarkan oleh fungsi tersebut harus tersedia kembali kepada `XSSGuard.init_app()` agar dapat dimasukkan ke `self.blocking_exclude_paths`.
3. Default `/csp-report` dan custom `path` harus diperlakukan dengan mekanisme yang sama.
4. Perubahan ini tidak boleh mengubah parser, storage, response `204`, atau context processor nonce.

**Keputusan:** custom CSP report path juga otomatis masuk exclusion karena fungsi menerima parameter `path`.

---

## 10. SAFE REQUEST GUARANTEE

### 10.1 Jaminan Eksplisit

Request dengan status `SAFE` (dimensi detection):

1. **TIDAK DIBLOKIR** — tidak akan terkena HTTP 403 karena blocking decision.
2. **TETAP MENCAPAI Flask Application** — route handler akan dieksekusi normal.
3. **TETAP MENDAPATKAN Dynamic CSP Nonce** — `generate_nonce()` dipanggil, `environ["xssguard.nonce"]` terset.
4. **TETAP MEMPEROLEH CSP Header** — `custom_start_response` menambahkan `Content-Security-Policy` dengan `script-src 'self' 'nonce-XXX'; ...`
5. **TETAP MENGHASILKAN RESPONSE NORMAL** — body response, content-type, content-length, status code (200/302/404 sesuai app logic) TIDAK DIPENGARUHI oleh fitur blocking sedikitpun.

### 10.2 Bukti Regression Prevention

Perubahan di middleware untuk safe request path HANYA menambahkan **satu boolean check** setelah detection:

```
if results and self.blocking_enabled:    ← HANYA INI penambahan logic.
    ... branch BLOCKED ...
```

Jika `results` adalah list kosong (safe request), kondisi boolean `results and ...` = `False`. Branch blocked TIDAK PERNAH diambil. Alur code 100% identik dengan existing.

---

## 11. ACADEMIC LAB INTEGRATION

### 11.1 Prinsip

```
Academic Lab Routes = Target Application.
Mereka TIDAK PERLU memiliki logic blocking sendiri.
Blocking dilakukan SEBELUM route handler dipanggil — di perbatasan middleware.
```

### 11.2 Daftar Route Tipe yang Terproteksi Otomatis

Tidak peduli apakah route adalah:
- Forum (submit thread / reply)
- Comment section
- Announcement / Pengumuman
- Chat / message
- Profile bio / user settings
- Upload description / caption

**SEMUA secara otomatis terproteksi TANPA PERUBAHAN SATU PUN BARIS KODE di route.**

### 11.3 Manfaat Utama Desain Ini

1. **Payload Malicious TIDAK MASUK DATABASE:** Jika blocking aktif dan user submit form komentar berisi `<script>`, middleware mengembalikan 403 SEBELUM route `/comments/create` dijalankan. SQL INSERT / UPDATE ke tabel komentar TIDAK PERNAH terjadi. Database lab bersih dari payload XSS.
2. **Zero Touch Refactoring pada Route Logic:** Tim pengembang route tidak perlu mengubah decorator, menambahkan middleware per route, atau memanggil validator baru. Enforcing transparan.
3. **Consistent Enforcement:** Tidak ada human error "route A lupa pasang decorator anti XSS." SEMUA request (GET query param, POST form, JSON body API) melewati gerbang yang sama.
4. **Stored XSS Hilang di Akar:** Kasus stored XSS (payload tersimpan di DB lalu di-render tanpa sanitize) tidak akan terjadi karena payload tidak pernah masuk DB. CSP hanya menjadi defense layer-2 JIKA ada false negative detection.

### 11.4 Pengecualian Khusus LAB Fixture

Dua fixture E2E di test dirancang SENGGARA rentan untuk riset browser:

| Fixture | Path | Alasan Butuh Pengecualian |
|---------|------|--------------------------|
| `d4_stored_xss_fixture.py` | `/store` (POST) | Desain fixture: user POST payload XSS script ke `/store`, payload disimpan di `StoredPayloadStore`, lalu di-render tanpa nonce di `/stored`. Tujuan = BUKTIKAN bahwa CSP di browser MEMBLOKIR script yang tidak punya nonce. JIKA blocking aktif, payload akan ditolak di middleware dan fixture TIDAK BERKERJA. |
| `d3_csp_fixture.py` | (tidak menerima input user berbahaya) | `/no-nonce` dan `/wrong-nonce` hanya GET, menerima POST hanya `/csp-report` yang sudah di-exclude. TIDAK BUTUH pengecualian tambahan. |

**Rekomendasi:** Fixture dijalankan dengan `blocking_enabled=False`, ATAU path `/store` ditambahkan ke `blocking_exclude_paths`.

---

## 12. FILE IMPACT ANALYSIS

### 12.1 Tabel Analisis

| File | Kategori | Fungsi Saat Ini | Dampak Blocking | Perlu Diubah? | Alasan Detail |
|------|----------|----------------|----------------|--------------|---------------|
| [middleware.py](file:///e:/XSSGuard-Security-Lab/xssguard/middleware.py) | **MUST CHANGE** | WSGI Middleware: extract body, call detector, log detection, generate nonce, wrap self.app, inject CSP header. | **TINGGI.** Ini adalah satu-satunya enforcement point. Decision branch BLOCKED harus ditambahkan. | ✅ **WAJIB** | Tambah parameter constructor `blocking_enabled`, `blocking_exclude_paths`. Tambah conditional early return 403 setelah logging detection. Satu-satunya lokasi yang dapat menghentikan request sebelum Flask. |
| [storage.py](file:///e:/XSSGuard-Security-Lab/xssguard/storage.py) | **MUST CHANGE** | Definisi `DetectionRecord`, `CspReportRecord`, `BaseStore` Protocol, `MemoryStore`. | **SEDANG-TINGGI.** Perlu membedakan DETECTED+ALLOWED vs DETECTED+BLOCKED untuk auditability. | ✅ **WAJIB** | Tambah field `action: Optional[str] = None` pada `DetectionRecord` dataclass. `BaseStore` signature `log_detection` TIDAK BERUBAH (hanya attribute yang bertambah). `MemoryStore` TIDAK PERLU perubahan logic karena hanya append list. |
| [flask_ext.py](file:///e:/XSSGuard-Security-Lab/xssguard/flask_ext.py) | **MUST CHANGE** | Flask Extension wrapper: bind `XSSGuardMiddleware` ke `app.wsgi_app`, inject context_processor nonce, register `/csp-report`. | **SEDANG.** Harus melewatkan parameter `blocking_enabled` ke middleware, dan auto-exclude path CSP report. | ✅ **WAJIB** | Tambah parameter `blocking_enabled: bool = False` dan `blocking_exclude_paths: Optional[list[str]] = None` pada constructor `XSSGuard` dan `init_app()`. Teruskan nilai-nilai ini ke constructor `XSSGuardMiddleware` pada line 77-81. Auto-append path CSP report ke exclude list. |
| [detector.py](file:///e:/XSSGuard-Security-Lab/xssguard/detector.py) | **SHOULD NOT CHANGE** | Pure rule-based XSS detector framework-agnostic. `DetectionResult` frozen dataclass + `scan()` + `scan_mapping()`. | **RENDAH.** DetectionResult sudah menyediakan informasi cukup (`status`, `matched_rule`, `field`, `payload`). Decision blocking hanya butuh `len(results) > 0`. | ❌ **TIDAK BOLEH DIUBAH** (kecuali ada alasan kuat belakangan) | Audit menetapkan detector = Detection Engine, bukan enforcement. Menambah field "action", "http_status", dll ke DetectionResult akan mencampur concern dan merusak invariant framework-agnostic. Jika suatu hari butuh severity / confidence, baru evaluasi terpisah. |
| [patterns.py](file:///e:/XSSGuard-Security-Lab/xssguard/patterns.py) | **SHOULD NOT CHANGE** | Konstanta `DEFAULT_XSS_PATTERNS` (10 regex string). | **NOL.** Blocking menggunakan detection result yang sama. Tidak perlu tambah pattern khusus blocking. | ❌ **TIDAK** | Regex patterns sama persis digunakan. Perbedaan hanya apa yang DILAKUKAN terhadap hasil match (dicatatan vs ditindak). |
| [nonce.py](file:///e:/XSSGuard-Security-Lab/xssguard/nonce.py) | **SHOULD NOT CHANGE** | `generate_nonce()` via CSPRNG + base64url, `build_csp_header()` policy template + nonce token. | **NOL SANGAT RENDAH.** Nonce generation dan CSP header bekerja PERSIS sama untuk ALLOWED path. Untuk BLOCKED path, CSP header opsional disertakan dengan logic fungsi yang sama. | ❌ **TIDAK** | Fungsi kedua bersifat pure function dari input string. Tidak ada dependency pada detection / blocking state. |
| [report.py](file:///e:/XSSGuard-Security-Lab/xssguard/report.py) | **SHOULD NOT CHANGE** | `CspReportData` frozen dataclass + `parse_csp_report()` parse JSON CSP violation browser. | **NOL.** Terpisah total dari server-side request blocking. | ❌ **TIDAK** | Dimensi berbeda. Dokumen ini secara eksplisit memisahkan CSP Violation Reporting dari Request Blocking. |
| [dashboard.py](file:///e:/XSSGuard-Security-Lab/xssguard/dashboard.py) | **MAY CHANGE** | Presentation layer read-only Blueprint. Renders table DetectionRecord + CspReportRecord via Jinja. | **RENDAH (Enhancement).** Jika DetectionRecord punya field `action`, dashboard dapat menampilkan badge berbeda. Tapi ini NICE-TO-HAVE saja, tidak mandatory untuk security. | ⚠️ **OPSIONAL** (MAY) | Saat ini dashboard menampilkan badge `<span class="badge">{{ d.status }}</span>` (hanya "DETECTED"). Dapat ditambahkan conditional: jika `d.action == "BLOCKED"` → badge merah; jika `"ALLOWED"` → badge kuning; jika `None` → default badge (legacy). Namun tanpa perubahan ini, dashboard tetap fungsional; user hanya tidak melihat label action. Tidak mengubah security. |
| **Configuration (constructor params)** | **MUST CHANGE** | Saat ini middleware/extension menerima `patterns` dan `store` saja. | **WAJIB.** Parameter `blocking_enabled` dan `blocking_exclude_paths` harus ditambahkan agar user dapat mengaktifkan. | ✅ **WAJIB** | Lihat bagian Feature Flag. Tanpa parameter ini, flag tidak dapat dinyalakan tanpa patch. |
| **Academic Lab Routes / Source Code Lab** | **SHOULD NOT CHANGE** | Route handler forum, comment, announcement, chat, dll. | **NOL (secara desain).** Route seharusnya TIDAK TAHU bahwa blocking ada. Blocking transparan. | ❌ **TIDAK (idealnya)** | Jika semua enforcement di middleware, route 0 perubahan. Kecuali jika route memang BUTUH menerima payload XSS untuk riset (fixture stored XSS), maka path tersebut DIDAFTARKAN ke `blocking_exclude_paths` — tapi kode route TETAP TIDAK diubah. |
| **Chrome Extension (semua file di `extension/`)** | **SHOULD NOT CHANGE** | Manifest V3: passive CSP header observation, badge, popup visualizer, CSP violation event listener. | **NOL SAMA SEKALI.** Extension scope adalah Passive Monitoring/Visualizer. Invariant di service_worker.js TEGAS: "No blocking handlers, no BlockingResponse, no cancel/redirect." | ❌ **TEGAS TIDAK BOLEH** | Trust boundary: extension dijalankan di sisi CLIENT. Attacker bisa disable extension, pakai curl, bypass. Hanya enforcement di middleware server-side yang dapat diandalkan. Menambah blocking ke extension = scope creep + false sense of security. MELANGGAR audit rekomendasi dan user profile preferensi. |
| **storage_adapter.py** | **NEEDS CONFIRMATION** | File ini DISEBUTKAN dalam ringkasan audit point nomor 14, TAPI TIDAK DITEMUKAN dalam struktur direktori xssguard/. Hanya ada `storage.py`. | — | ⚠️ **KONFIRMASI DIBUTUHKAN** | Jika di lingkungan PROD terdapat storage_adapter.py (misal adapter SQLAlchemy / SQLite yang belum dimasukkan ke repo), file ini JUGA WAJIB diperbarui untuk menangani field `action` baru pada DetectionRecord schema DB (tambah kolom). Untuk MemoryStore saat ini, tidak ada file adapter terpisah. |
| `__init__.py` | **SHOULD NOT CHANGE** | Package version marker. | NOL. | TIDAK. | |

### 12.2 Ringkasan Jumlah File

| Kategori | Jumlah File |
|---------|------------|
| **MUST CHANGE** | 4 file: `middleware.py`, `storage.py`, `flask_ext.py`, **Configuration (parameter constructor)** |
| **MAY CHANGE** | 1 file: `dashboard.py` (opsional enhancement badge) |
| **SHOULD NOT CHANGE** | 8+ item: `detector.py`, `patterns.py`, `nonce.py`, `report.py`, Lab routes, Chrome Extension, test detector/report, examples |
| **NEEDS CONFIRMATION** | 1: `storage_adapter.py` (apakah ada?) |

---

## 13. DATABASE / STORAGE IMPACT

### 13.1 Schema Saat Ini Cukup?

**TIDAK CUKUP** untuk auditability. Saat ini `DetectionRecord` hanya memiliki field `status`. Statusnya selalu `"DETECTED"` (karena `scan_mapping()` tidak pernah mengembalikan SAFE). Tidak ada mekanisme membedakan:

- Record X dihasilkan dari request yang **DETECTED + DITERUSKAN (ALLOWED)** ke app.
- Record Y dihasilkan dari request yang **DETECTED + DIBLOKIR (BLOCKED)** sebelum app.

Untuk penelitian / forensik / perbandingan mode log-only vs enforce, perbedaan ini KRITIAL.

### 13.2 Field Baru yang Ditetapkan (Konseptual)

| Terdampak | Detail | Nilai yang Ditetapkan |
|-----------|--------|----------------------|
| **Field Name** | Nama field pada DetectionRecord | **`action`** |
| **Type** | Tipe data Python | `Optional[str]` (bisa `None` untuk backward compat data lama) |
| **Meaning** | Makna semantik | Tindakan enforcement yang diambil oleh middleware terhadap request yang memicu detection record ini. |
| **Possible Values** | Himpunan nilai yang valid (MVP) | `"ALLOWED"`: Request mencapai Flask Application (log-only mode / blocking OFF atau path whitelisted)<br>`"BLOCKED"`: Request dihentikan dengan HTTP 403 (blocking ON + tidak dikecualikan)<br>`None`: Rekaman sebelum upgrade, nilai tidak diketahui / legacy. |
| **Default** | Nilai jika tidak di-isi explicit | `None` (melindungi backward compatibility) |
| **When Populated** | Kapan field ini diisi? | SELALU diisi oleh middleware pada saat membuat DetectionRecord (di dalam loop `for result in results:`) SEBELUM memanggil `store.log_detection()`. Jika `blocking_enabled=False` → isi `"ALLOWED"`. Jika `blocking_enabled=True` DAN `PATH_INFO` termasuk `blocking_exclude_paths` → isi `"ALLOWED"`. Jika `blocking_enabled=True` DAN `PATH_INFO` tidak termasuk `blocking_exclude_paths` → isi `"BLOCKED"`. |

### 13.3 Terdampak Tabel / Storage Backend

| Backend Storage | Dampak | Migration Diperlukan? |
|----------------|--------|----------------------|
| **MemoryStore (saat ini)** | DetectionRecord adalah Python dataclass instance. Menambah field dengan `default=None` berarti data LAMA dalam list `_detections` TIDAK PERLU dimigrasi (sudah dibuat tanpa field `action`, tapi ketika diakses attribute default akan mengembalikan None? — **NEEDS CONFIRMATION**: Dataclass field dengan default ditambahkan setelah instance dibuat tidak otomatis memiliki attribute. Sebaiknya saat pembuatan instance DetectionRecord BARU selalu mengisi `action` secara eksplisit. Data record lama sebelum upgrade akan kekurangan attribute `action`. **Strategi:** Gunakan `getattr(record, 'action', None)` ketika mengakses untuk backward compat.) | TIDAK ada migration (MemoryStore in-memory, hilang setiap restart). |
| **SQLite / SQLAlchemy / Relational DB (jika storage_adapter.py ada)** | Tabel `detection_records` membutuhkan kolom baru. | YA — migration DDL `ALTER TABLE detection_records ADD COLUMN action VARCHAR(16) NULL;` lalu update existing row menjadi NULL atau "ALLOWED". **TIDAK DILAKUKAN pada tahap ini.** |
| **CspReportRecord** | NOL DAMPAK. Sama sekali tidak berhubungan dengan blocking. | TIDAK PERLU. |
| **BaseStore Protocol** | Signature method `log_detection(record: DetectionRecord)` **TIDAK BERUBAH**. Tidak perlu menambah parameter atau method baru. | TIDAK PERLU. |

### 13.4 Alternatif: BlockingRecord Terpisah?

TIDAK DIPILIH untuk MVP. Membuat tipe record `BlockingRecord` terpisah dengan field sendiri:

- Pro: Separation sempurna.
- Con: Duplikasi field (payload, client_ip, source, matched_rule, timestamp), menambah complexity BaseStore harus punya `log_blocking()` + query method baru, dashboard harus render dua table terpisah atau gabung.

Decision: Gunakan field `action` pada DetectionRecord yang ada. Sederhana, cukup untuk MVP.

---

## 14. SECURITY CONSIDERATIONS

### 14.1 False Positive Blocking

**Deskripsi:** Input user LEGITIMATE secara tidak sengaja match dengan XSS pattern. Contoh: user menulis tutorial HTML yang mengandung string `<script>` dalam field bio / postingan forum. Atau field "judul" berisi "Panduan document.cookie untuk Pemula".

**Mitigasi dalam desain:**
- `blocking_enabled=false` DEFAULT → user mengaktifkan enforce HANYA setelah observasi false positive di log-only mode.
- `blocking_exclude_paths` → endpoint yang memang menangani content HTML / edukasi (misal admin documentation editor) dapat di-whitelist.
- Response 403 INFORMATIF (jika diimplementasikan nanti) → user tahu field mana yang kena rule apa, bukan cuma "Forbidden" membingungkan.

**TIDAK DIAKUI:** "100% bebas false positive". Tidak ada regex pattern engine yang sempurna. Trade-off antara DR (Detection Rate) dan FPR (False Positive Rate) harus diterima.

### 14.2 False Negative

**Deskripsi:** Payload XSS SESUNGGUHNYA lolos dari `DEFAULT_XSS_PATTERNS` (tidak terdeteksi), sehingga decision = SAFE / ALLOWED, payload mencapai Flask App / DB, berharap CSP nonce menahan di browser.

**Mitigasi:**
- Defense-in-depth: Blocking (layer-1) TIDAK PERNAH menggantikan CSP (layer-2) dan Output Encoding (layer-3 di route). Audit sendiri mencatat 10 regex patterns tidak menutup semua vektor XSS (contoh: polyglot, UTF-7, mutation XSS, dll tidak ada pattern-nya).
- CSP Violation Report akan tetap menangkap kejadian ini untuk post-hoc analysis.
- Benchmark 30 payload research dataset = 100% terdeteksi. Untuk payload di luar dataset, TIDAK ADA klaim coverage.

### 14.3 Whitelist Bypass

**Deskripsi:** Attacker memanfaatkan endpoint yang masuk `blocking_exclude_paths` (misal `/csp-report`) untuk menaruh payload XSS, lalu berharap payload tersebut di-render kembali di halaman admin dashboard CSP report viewer.

**Mitigasi:**
- Dashboard CSP report menggunakan Jinja autoescape. Terbukti di test `test_xss_in_csp_report_fields_is_escaped` pada test_dashboard.py. Field `document_uri`, `blocked_uri` dll DI-ESCAPE sebelum render → stored XSS di dashboard dicegah.
- Scope whitelist hanya untuk PATH. Tidak ada whitelist berdasarkan IP, cookie, user-agent yang dapat dipalsukan attacker.
- Pengembang diwajibkan mengaudit path apapun yang masuk ke `blocking_exclude_paths`.

### 14.4 HTTP 403 Response Leakage

**Deskripsi:** Badan response 403 secara tidak sengaja merefleksikan payload attacker tanpa escaping (self-XSS via reflected HTML di 403 page).

**Mitigasi (desain wajib):**
- Jika 403 body ingin menampilkan informasi rule yang match / field, WAJIB HTML-escape value sebelum inject ke template.
- 403 body TIDAK PERNAH menampilkan FULL payload user mentah. Cukup nama field / rule ID (jika ada), atau pesan generik saja.
- MVP: 403 body BISA generic TANPA menampilkan apapun tentang payload. Benar-benar aman.

### 14.5 Logging Consistency

**Deskripsi:** Permintaan BLOCKED tidak tercatat di log (hanya return 403 tanpa evidence), sehingga attacker bisa melakukan brute force pattern tanpa jejak.

**Mitigasi WAJIB di desain:** Blocking action DITENTUKAN SEBELUM DetectionRecord disimpan. Detection evidence TETAP tersimpan dengan `action="BLOCKED"` sebelum early return 403. Tidak ada silent block. Audit trail lengkap.

### 14.6 Request Body Handling

**Deskripsi:** Body replay ke `BytesIO` terjadi SEBELUM decision. Ketika BLOCKED early return, apakah ada resource leak / WSGI protocol violation?

**Mitigasi:** Body sudah dibaca dan disimpan di memory. Early return adalah WSGI-compliant — start_response DIPANGGIL dengan status 403, lalu return iterable bytes. Sesuai PEP 3333. Test WSGI lifecycle close() — pada blocked path tidak ada app iterable yang perlu di-close, jadi tidak masalah.

### 14.7 JSON Nested Payload, Form, Query Parameter

**Deskripsi:** Attacker menyembunyikan XSS di nested field JSON array[2].items[3].text. Apakah blocking masih berfungsi?

**Mitigasi:** Detection sudah menggunakan `scan_mapping()` dengan `_walk_iterative()` — iterative DFS stack-based depth 3000+ sudah teruji di test. Seluruh string leaf node discan. Field path dotted notation dikembalikan. Artinya: detection → logging → decision → blocking berjalan konsisten untuk query, form flat, JSON nested, list/tuple bersarang. Tidak ada celah struktur data.

### 14.8 CSP Report Handling

**Deskripsi:** Request POST ke `/csp-report` dengan report payload yang kebetulan mengandung string match pattern → ter-block sehingga laporan CSP hilang.

**Mitigasi (sudah diatur di Bagian 9):** Path `/csp-report` dan custom variantnya MASUK `blocking_exclude_paths` SECARA OTOMATIS oleh Flask Extension. Walaupun suatu hari field CSP report aneh match pattern, endpoint tetap menerima.

### 14.9 Regression terhadap SAFE Request

**Deskripsi:** Penambahan code branch malah merusak safe request path (nonce salah generate, CSP header tidak masuk, environ tidak terekspos).

**Mitigasi desain:**
- Safe request path (`results == []`) TIDAK MASUK branch blocked sama sekali. Hanya menambah 1 boolean check `if results and self.blocking_enabled:` yang dievaluasi menjadi `False`.
- Feature flag default OFF → seluruh existing test suite berjalan di mode ini = 0 behavioral change.
- Wajib regression test full suite sebelum enable enforce di staging.

### 14.10 WSGI Response Lifecycle

**Deskripsi:** Iterable return pada blocked path tidak memiliki close() method. Host app yang sebelumnya punya closeable iterable tidak terpanggil.

**Mitigasi:** HOST APP iterable close() hanya perlu dipanggil jika HOST APP benar-benar dijalankan (self.app dipanggil). Pada blocked path, self.app TIDAK dipanggil → tidak ada iterable host app yang perlu di-close. Iterable blocked path hanyalah `[bytes]` Python list sederhana yang tidak butuh resource cleanup. Valid.

---

## 15. TESTING STRATEGY

Dokumen design decision ini MENETAPKAN BAGAIMANA blocking nantinya DIBUKTIKAN bekerja, bukan menjalankan test.

### 15.1 Test Matrix

| Test ID | Skenario | blocking_enabled | Kondisi Request | Expected Output | Evidence |
|---------|---------|------------------|----------------|-----------------|----------|
| **Test A1** | SAFE Request — Query String | False (default) | GET `/search?q=hello+world` | HTTP 200, response body normal, route TEReksekusi (counter bertambah), CSP header ada + nonce | Store: 0 DetectionRecord baru. environ nonce == CSP nonce. |
| **Test A2** | SAFE Request — Form POST | False | POST `/submit` data `{"comment": "Hi semuanya!"}` | HTTP 200, route handler dipanggil, form data masuk app | Store: 0 DetectionRecord. |
| **Test A3** | SAFE Request — JSON Body | False | POST `/api/feedback` JSON bio aman | HTTP 200, JSON diterima app | Store: 0 DetectionRecord. |
| **Test A4** | SAFE Request + Blocking Flag TRUE | True | GET `/page` tanpa payload | HTTP 200, route terpanggil, nonce tetap | Tidak ada false positive. |
| **Test B1** | XSS Query Detected, Blocking OFF | False | GET `/search?q=<script>alert(1)</script>` | HTTP 200, route DIPANGGIL, payload di-echo di response | Store: DetectionRecord baru, `status=DETECTED`, `action=ALLOWED`, matched_rule benar. TIDAK ADA HTTP 403. |
| **Test B2** | XSS Form Body Detected, Blocking OFF | False | POST `/submit` comment XSS | HTTP 200, route dipanggil, payload masuk StoredPayloadStore / DB | Store: record `action=ALLOWED`. |
| **Test B3** | XSS Nested JSON Detected, Blocking OFF | False | POST JSON nested field `articles[0].content` berisi onerror | HTTP 200, route terpanggil | Store: record dengan field path dotted `articles.0.content`, `action=ALLOWED`. |
| **Test C1** | XSS Query Detected, Blocking ON | True | GET `/search?q=<script>alert(1)</script>` | HTTP **403 Forbidden**, Content-Type text/html, body blocked page, route TIDAK terpanggil, DB tidak berubah | Store: DetectionRecord `status=DETECTED`, `action=BLOCKED`. |
| **Test C2** | XSS Form Body Detected, Blocking ON | True | POST `/submit` comment XSS | HTTP 403, route TIDAK dipanggil, comment TIDAK tersimpan | Store: record `action=BLOCKED`. |
| **Test C3** | XSS Nested JSON, Blocking ON | True | POST nested JSON XSS | HTTP 403, route handler TIDAK dieksekusi | Store: record `action=BLOCKED` dengan dotted path field benar. |
| **Test C4** | XSS + Path Whitelist, Blocking ON | True + exclude path `/store` | POST `/store` payload XSS | HTTP 302 redirect normal (sesuai fixture), payload MASUK DB (whitelisted) | Store: DetectionRecord `status=DETECTED`, `action=ALLOWED` (meskipun flag True, path dikecualikan). |
| **Test D1** | Database Integrity, Blocking ON | True | Submit stored XSS 10x ke fixture | Tabel `StoredPayloadStore` atau DB target TETAP KOSONG dari payload XSS. | Tidak ada side effect DB dari route handler. |
| **Test D2** | Database Integrity, Blocking OFF | False | Submit stored XSS 5x | Payload 5x SEMUA TERSEDIA di StoredPayloadStore. | Perbandingan kontras dengan Test D1. |
| **Test E1** | CSP Report Endpoint, Blocking ON | True + explicit exclusion `/csp-report` | POST valid CSP violation JSON ke `/csp-report` | HTTP 204, CspReportRecord tersimpan | Store: `len(csp_reports) = 1`. DetectionRecord TIDAK dibuat. Tidak ada HTTP 403 meskipun (jika anehnya) field match pattern. |
| **Test E2** | Invalid CSP Report, Blocking ON | True | POST invalid JSON ke `/csp-report` | HTTP 204, TIDAK ada record apapun | Sesuai kontrak existing. |
| **Test F1** | Regression All Existing Tests | False (default) | Run seluruh `tests/` dengan pytest | **SEMUA LULUS 100%.** Karena default OFF = behavior 0 perubahan. | Termasuk `test_repeated_attacks_from_same_ip_not_blocked` yang memverifikasi HTTP 200 — harus tetap lulus. |
| **Test F2** | Nonce Regression, Blocking OFF/ON | Keduanya | Safe request → check `environ["xssguard.nonce"] == nonce token di CSP header` | NONCE MATCH. | |
| **Test F3** | Fixture d3_csp_fixture, Blocking OFF | False | GET `/no-nonce` → CSP violation | HTTP 200, script blocked di browser, report ke `/csp-report` normal | Kompatibilitas dengan fixture research. |

### 15.2 Urutan Prioritas Testing Saat Implementasi

1. Test A1-A3 (SAFE baseline, tanpa ubah behavior) → pastikan safe tidak rusak.
2. Test F1 (Regression ALL existing) → pastikan default OFF backward compat.
3. Test B1-B3 (Detection ON, Block OFF) → pastikan detection tidak rusak.
4. Test C1-C3 (Block ON dasar) → pastikan HTTP 403 keluar.
5. Test C4, E1 (Whitelist, CSP report) → edge case.
6. Test D1-D2 (DB Integrity) → stored XSS cegah.

---

## 16. BUKTI ROUTE TIDAK DIEKSEKUSI

### 16.1 Mengapa HTTP 403 SAJA TIDAK CUKUP?

HTTP 403 hanya membuktikan bahwa **response** yang dikembalikan middleware adalah 403. Itu **TIDAK MEMBUKTIKAN** bahwa `self.app(environ, start_response)` tidak pernah dipanggil di balik layar. Ada skenario buruk dimana:

```
middleware salah urutan:
  1. panggil self.app(...) → route jalan → payload masuk DB
  2. baru kemudian check "oh ada results" → overwrite status jadi 403

Akibat: HTTP 403 keluar TAPI route TETAP dieksekusi = stored XSS tetap terjadi.
```

Karena itu, butuh bukti INDEPENDEN bahwa route handler body tidak dijalankan sama sekali.

### 16.2 Mekanisme Pembuktian yang Ditetapkan

**Pendekatan yang dipilih: **Route Execution Counter / Side-Effect Marker** (paling sesuai dengan arsitektur Flask test client yang ada).

Detail implementasi konseptual:

```python
# Dalam test file (contoh: test_blocking.py) — BUKAN di production code.

def test_blocked_route_not_executed():
    execution_tracker = {"called": False, "received_payload": None}

    # Flask route yang sensitif
    @app.route("/comment", methods=["POST"])
    def create_comment():
        execution_tracker["called"] = True                    # ← MARKER INI
        execution_tracker["received_payload"] = request.form.get("comment")
        return Response("Comment saved", status=200)

    # Kirim request XSS dengan blocking_enabled=True
    client.post("/comment", data={"comment": "<script>alert(1)</script>"})

    # PEMBUKTIAN UTAMA:
    assert execution_tracker["called"] is False, (
        "Route handler was EXECUTED despite blocking being enabled. "
        "Blocking decision did not happen BEFORE self.app() call."
    )
    assert execution_tracker["received_payload"] is None
```

### 16.3 Metode Alternatif (sebagai cross-check)

| Metode | Mekanisme | Kapan Digunakan |
|--------|----------|----------------|
| **Route Execution Boolean Flag** (Primer) | Variable closure mutable atau class attribute yang di-flip hanya ketika code dalam route handler berjalan. | Test unit level dasar. Primer. |
| **Mock / Spy pada Dependency Route** | Jika route memanggil `db.session.add()`, mock object tersebut dan assert `add.assert_not_called()`. | Test integration pada app yang benar-benar punya DB session. |
| **Database Insertion Check** | Sebelum test hitung count row DB. Setelah request XSS, count row TIDAK BERUBAH. | End-to-end test pada fixture yang benar-benar menyimpan (d4_stored_xss). Cross-check apakah `StoredPayloadStore.get_all()` tetap kosong meskipun request dikirim. |
| **Integration Test — Response Content** | Jika route biasanya meng-echo payload ("Search results for: XSS"), maka pada blocked assert body 403 TIDAK mengandung string echo tersebut. | Bukti tidak langsung tapi sederhana. Bukan bukti kuat primer, tapi melengkapi. |
| **Middleware Step Tracker** | Instrumentasi sementara pada middleware untuk mencetak log step (log step 1, step 2, ..., sebelum self.app, sesudah self.app). Assert bahwa log "setelah self.app" TIDAK MUNCUL ketika blocked. | Debugging jika terjadi bug urutan. |

### 16.4 Kriteria Lulus Test C (Blocking ON)

Untuk Test C1/C2/C3, KEDUA kondisi di bawah WAJIB terpenuhi:

1. ✅ HTTP response status code = **403 Forbidden**.
2. ✅ Route execution marker = **False** (route TIDAK dipanggil).

Kedua syarat HARUS ADA. Jika hanya 1 yang terpenuhi → FAIL (menunjukkan bug implementasi urutan atau early return tidak sempurna).

---

## 17. UML IMPACT

**PERINGATAN:** UML TIDAK DIUBAH PADA TAHAP INI. Dokumen hanya menentukan APA yang nantinya perlu diubah setelah implementasi + testing selesai dan approve.

### 17.1 Tabel Dampak UML

| Diagram UML | Status Nanti | Perubahan Konseptual yang Diperlukan (Setelah Implementasi) |
|-------------|-------------|----------------------------------------------------------|
| **Use Case Diagram** | **BERUBAH** | Tambah Use Case baru: "Memblokir Request/Payload XSS" atau extend use case "Mendeteksi XSS" dengan include keputusan enforcement. Actor "System" / "Security Engine" akan berasosiasi dengan use case baru ini. Juga tambah include untuk "Menyimpan Bukti Blocking" ke actor Storage / Audit Trail. |
| **Activity Diagram** | **BERUBAH** | Decision node BARU setelah "Simpan Log Detection": kondisi "blocking_enabled AND detection found". Dua merge branch: (a) Ya → node "Kembalikan HTTP 403" → Final Flow. (b) Tidak → lanjut ke existing node "Generate Nonce" → "Panggil Flask App" → "Response". |
| **Sequence Diagram** | **BERUBAH** | Message flow BARU: `XSSGuardMiddleware → XSSGuardMiddleware: evaluate_blocking_decision(results, flag)`. Jika true: lifeline middleware memanggil `start_response("403 Forbidden")` lalu `return [body_403]` — TIDAK ADA message ke `FlaskRouter` / `Database`. Jika false: message ke `FlaskRouter` berlanjut seperti existing. Dibutuhkan diagram sequence terpisah untuk scenario BLOCKED vs existing ALLOWED. |
| **Component Diagram** | **BERUBAH (Minor)** | Komponen `XSSGuardMiddleware` sekarang MENGEKSPOS responsibility tambahan: "Request Enforcement" selain "Detection Invocation". Interface provided component: `IEnforcementPoint` (opsional), atau cukup tambahkan annotation pada garis koneksi Middleware → HTTP Response Channel bahwa status 403 dapat dihasilkan. Komponen Detector, Storage, Extension, CSP Report TIDAK BERUBAH koneksi. |
| **Deployment Diagram** | **TIDAK BERUBAH** | Tidak ada server baru, tidak ada process baru, tidak ada node deployment baru. Blocking dijalankan di Python process yang sama dengan Flask App WSGI. WSGI Middleware component = deployment node yang sama. |
| **Class Diagram** | **BERUBAH** | (1) Class `XSSGuardMiddleware`: tambah attribute `- blocking_enabled: bool` dan `- blocking_exclude_paths: list[str]`. Tambah private method opsional `- _should_block(results, environ) -> bool` dan `- _build_blocked_response(environ, start_response, results) -> Iterable[bytes]`. (2) Class `DetectionRecord`: tambah field `+ action: Optional[str]` dengan stereotype `<<version_added>>`. (3) Class `XSSGuard` (Flask Extension): tambah attribute `- blocking_enabled: bool` dan `- blocking_exclude_paths: list[str]` untuk diteruskan. |
| **ERD (Entity Relationship Diagram)** | **BERUBAH KETIKA SQL persistence ada** | Jika implementasi storage adapter SQL ada, Entity `DetectionRecord` menambah atribut: `action VARCHAR(16) NULL` dengan deskripsi "ALLOWED / BLOCKED / NULL". Relationship ke entity lain TIDAK BERUBAH. Selama masih MemoryStore, ERD TIDAK BERUBAH (tidak ada tabel fisik). |

### 17.2 Rule Perubahan UML

Perubahan UML HANYA DILAKUKAN setelah:
1. Implementasi kode blocking SELESAI.
2. Seluruh Test A-F matrix LULUS 100%.
3. Route execution marker TERBUKTI tidak dipanggil.
4. Audit implementasi sudah dilakukan.
5. Stakeholder approve.

Sampai saat itu, UML existing = referensi, dan perubahan di atas = status "rencana".

---

## 18. DESIGN PRINCIPLES

Sepuluh prinsip yang menjadi landasan seluruh keputusan di dokumen ini. Pelanggaran satu saja = design dianggap invalid dan perlu direvisi:

| # | Prinsip | Makna Operasional |
|---|--------|------------------|
| 1 | **Minimal Change** | Menyentuh file sesedikit mungkin (4 MUST CHANGE file). Tidak membuat class baru, modul baru, pattern baru yang tidak perlu. Fokus tambah 1 decision branch + 1 field storage + 2 parameter constructor. |
| 2 | **Separation of Concerns** | Detector = Detection Engine (pure). Middleware = Enforcement Point (HTTP-aware). Storage = Audit Evidence (persistent). CSP = Browser Trusted Script. Extension = Passive Client Visualizer. Tidak ada percampuran tugas. |
| 3 | **Backward Compatibility** | `blocking_enabled=false` default. User upgrade library, seluruh perilaku existing PERSIS sama. Test suite existing 100% lulus TANPA modifikasi test. |
| 4 | **Server-Side Enforcement** | Enforcement hanya di Python WSGI middleware. Percaya 100% pada server-side. Bukan di browser, bukan di JS extension. |
| 5 | **Detector Tetap Framework-Agnostic** | Detector TIDAK BOLEH tahu HTTP, Flask, WSGI, response status. Hanya menerima string → return DetectionResult. |
| 6 | **Chrome Extension Tetap Passive** | Extension = monitor / visualizer saja. Tidak ada BlockingResponse, tidak ada cancel request. Invariant service_worker.js dijunjung. |
| 7 | **CSP Tetap Independen dari Request Blocking** | Dua mekanisme beda layer, beda tujuan. Saling melengkapi, tidak saling bergantung. Salah satu mati, yang lain tetap bekerja. |
| 8 | **SAFE Request Tidak Terganggu** | Safe request path = nol perubahan perilaku. Hanya boolean check tambahan yang evaluate False. Performance degradation mikroskopis. |
| 9 | **Blocking Terjadi SEBELUM self.app()** | Ini adalah hard requirement. Jika nanti implementasi di-code dan keputusan blocking TERJADI SETELAH self.app() dipanggil (walaupun HTTP 403 keluar) → FAIL, harus diperbaiki. Bukti: route execution marker. |
| 10 | **Evidence Harus Dapat Diaudit** | DetectionRecord membedakan action "ALLOWED" vs "BLOCKED". Decision action ditentukan sebelum record disimpan, dan record disimpan sebelum response branch dieksekusi. Tidak ada silent enforcement tanpa jejak. |
| 11 | **Tidak Merubah Route Jika Middleware Sudah Cukup** | Academic Lab route 0 perubahan. Jika enforcement dapat dilakukan transparan di perbatasan middleware, JANGAN menambahkan decorator / logic ke tiap route secara terpisah. |

---

## 19.0 RESOLUSI BLOCKER HASIL AUDIT

Bagian ini membekukan koreksi dari audit Design Decision terhadap source code sebelum implementasi.

| ID | Hasil Resolusi | Keputusan Final |
|---|---|---|
| BLOCKER-01 | **DITUTUP** | Nonce dibuat **sekali** sesuai lifecycle existing, `environ["xssguard.nonce"]` diset, kemudian blocking decision dilakukan. Tidak ada `generate_nonce()` kedua pada blocked branch. |
| BLOCKER-02 | **DITUTUP** | `/csp-report` dan custom CSP report path harus diteruskan secara eksplisit dari route registration ke exclusion set. Source code saat ini belum auto-exclude; implementasi nanti wajib menambah mekanisme tersebut. |
| BLOCKER-03 | **DITUTUP** | Path exclusion menggunakan exact `PATH_INFO`; case-sensitive; query string tidak diperhitungkan; trailing slash harus eksplisit. |
| BLOCKER-04 | **DITUTUP** | `LOGGED` bukan nilai status/action. Nilai enforcement resmi hanya `ALLOWED` dan `BLOCKED`. |
| BLOCKER-05 | **DITUTUP** | Akses kompatibel terhadap record lama menggunakan `getattr(record, "action", None)` jika attribute belum tersedia. |

**Status:** Kelima blocker desain telah memiliki keputusan eksplisit. Source code **belum diubah** oleh dokumen ini.

---

## 19. FINAL ARCHITECTURAL DECISION

### FINAL DECISION

| Topik | Keputusan Final |
|-------|----------------|
| **Decision** | **Request/Payload Blocking dirancang diimplementasikan sebagai fitur BARU pada XSSGuardMiddleware dengan prinsip Minimal Change + Feature Flag Default OFF. Blocking HANYA aktif ketika `blocking_enabled=True`. Blokir berarti early return HTTP 403 SEBELUM `self.app(environ, start_response)` dipanggil. Detection tetap berjalan terlepas dari flag. |
| **Enforcement Point** | **`XSSGuardMiddleware.__call__(environ, start_response)`.** Decision point ditempatkan setelah detection dan setelah `generate_nonce()` + `environ["xssguard.nonce"]` diset, lalu sebelum `self.app()` invocation. Security logging menggunakan action yang sudah ditentukan oleh decision. |
| **Detection** | **TETAP menggunakan `detector.py` existing tanpa modifikasi.** DetectionResult status `SAFE` / `DETECTED` tidak berubah. `scan_mapping()` invariant hanya mengembalikan DETECTED. Detector tetap pure framework-agnostic. |
| **Blocking Condition** | **`if len(results) > 0 AND self.blocking_enabled is True AND environ["PATH_INFO"] not in self.blocking_exclude_paths → ACTION = BLOCKED`.** Semua kondisi lain = ALLOWED (request diteruskan). |
| **Blocked Response** | **HTTP 403 Forbidden, Content-Type text/html; charset=utf-8, Body sederhana dan informatif (tanpa refleksi payload mentah).** Jika CSP header disertakan, gunakan nonce yang sudah dibuat pada lifecycle request; **tidak ada generate nonce kedua**. |
| **Logging** | **Decision action ditentukan terlebih dahulu, kemudian DetectionRecord dibuat dan disimpan sebelum response branch dieksekusi.** Field BARU `action: Optional[str] = None`: `"ALLOWED"` atau `"BLOCKED"`. |
| **Default Configuration** | **`blocking_enabled = False` (log-only / monitor-only).** `blocking_exclude_paths = []` secara default sebelum path CSP report didaftarkan. Path `/csp-report` dan custom path CSP report kemudian ditambahkan secara eksplisit melalui integrasi Flask Extension. |
| **CSP Nonce** | **TETAP dibuat tepat satu kali untuk setiap request**, mengikuti lifecycle source code existing. Nonce diset ke `environ["xssguard.nonce"]` sebelum blocking decision. ALLOWED request menggunakannya melalui `custom_start_response`; BLOCKED request tidak meneruskan request ke Flask dan tidak memanggil `generate_nonce()` kedua kali. |
| **CSP Report** | **Endpoint `/csp-report` dan custom path-nya wajib dimasukkan secara eksplisit ke `blocking_exclude_paths` melalui integrasi Flask Extension.** Source code saat ini belum melakukan auto-exclude; implementasi nanti wajib menambah mekanisme tersebut tanpa mengubah parser/storage/response report. |
| **Chrome Extension** | **TETAP Passive Monitoring / Visualization 100%.** TIDAK ADA perubahan apapun. Tidak ada BlockingResponse di service worker. Tidak ada request modification. Invariant existing dijunjung. Scope extension TIDAK DIPERLUAS. |
| **Academic Lab** | **Route Forum, Comment, Announcement, Chat TIDAK PERLU diubah SATU PUN BARIS KODE.** Blocking transparan dari middleware. Manfaat: payload XSS blocked tidak masuk DB target app. Fixture stored XSS (d4) dapat diberi `blocking_enabled=False` ATAU masuk exclude path `/store` jika tetap ingin dijalankan untuk riset. |
| **Database** | **Schema saat ini (DetectionRecord di MemoryStore) perlu tambah 1 field `action: Optional[str] = None`.** Jika storage_adapter.py / SQL persistence ada (NEEDS CONFIRMATION), migration `ALTER TABLE detection_records ADD COLUMN action VARCHAR(16) NULL` diperlukan nantinya. Belum dilakukan di tahap ini. |
| **Testing Requirement** | **WAJIB lulus Test A (SAFE), B (Detected+Allowed), C (Detected+Blocked), D (DB Integrity), E (CSP Report), F (Regression Existing).** Terutam WAJIB ada mekanisme **Route Execution Marker** untuk membuktikan branch BLOCKED benar-benar mencegah `self.app()` dipanggil, bukan hanya mengganti status code setelah terlanjur eksekusi. |
| **UML Status** | **TIDAK DIUBAH SEKARANG.** Status rencana: Use Case, Activity, Sequence, Class → BERUBAH nantinya setelah implementasi + test lulus. Deployment → TIDAK BERUBAH. Component → BERUBAH Minor. ERD → BERUBAH jika SQL adapter. |

---

## 20. IMPLEMENTATION CHECKLIST

> Catatan: Checklist ini HANYA RENCANA. JANGAN dikerjakan pada tahap design decision. Fase eksekusi hanya boleh dimulai setelah dokumen ini di-approve.

### Phase 0: Pre-Implementation (Sebelum Sentuh Kode)

- [x] Audit mendalam source code existing SELESAI (hasil audit = sumber utama dokumen ini)
- [x] Design Decision Document dibuat dan di-review
- [ ] Stakeholder approve FINAL DECISION di Bagian 19
- [ ] Konfirmasi final keberadaan/ketiadaan `storage_adapter.py` atau SQL persistence
- [ ] Backup / snapshot codebase sebelum mulai coding

### Phase 1: Storage Layer (Pertama, karena Middleware bergantung pada field baru)

- [ ] Tambah `action: Optional[str] = None` pada `DetectionRecord` dataclass di [storage.py](file:///e:/XSSGuard-Security-Lab/xssguard/storage.py#L27-L37)
- [ ] Verifikasi `MemoryStore` TIDAK BUTUH perubahan (hanya append list)
- [ ] Pastikan backward compat: record lama (jika ada) dapat di-akses dengan `getattr(r, 'action', None)`
- [ ] Update typing detection untuk semua akses DetectionRecord.action di seluruh codebase
- [ ] Unit test DetectionRecord dengan action = None, "ALLOWED", "BLOCKED"

### Phase 2: Middleware Enforcement Point (Core Fitur)

- [ ] Tambah parameter constructor `blocking_enabled: bool = False` dan `blocking_exclude_paths: Optional[Sequence[str]] = None` pada `XSSGuardMiddleware.__init__()` di [middleware.py](file:///e:/XSSGuard-Security-Lab/xssguard/middleware.py#L85-L94)
- [ ] Simpan sebagai `self.blocking_enabled` (bool) dan `self.blocking_exclude_paths: set[str]` (convert list ke set untuk O(1) lookup)
- [ ] DI DALAM `__call__()`: setelah detection selesai dan nonce sudah dibuat sekali serta disimpan di `environ`, tentukan conditional decision point **SEBELUM membuat `DetectionRecord`**
- [ ] Tentukan blocking action dengan urutan: `blocking_enabled=False` → `"ALLOWED"`; `blocking_enabled=True` + `PATH_INFO` termasuk exclude → `"ALLOWED"`; `blocking_enabled=True` + `PATH_INFO` tidak termasuk exclude → `"BLOCKED"`
- [ ] Buat `DetectionRecord` dengan `record.action` sesuai hasil decision, lalu panggil `store.log_detection(record)` **sebelum enforcement branch**
- [ ] Implementasi blocking branch: jika `results AND self.blocking_enabled AND PATH_INFO not in exclude` → jalankan early return 403
- [ ] Di blocking branch: JANGAN memanggil `generate_nonce()` lagi; gunakan nonce yang sudah tersedia jika CSP 403 membutuhkan nonce, lalu panggil `start_response("403 Forbidden", headers)` dan `return [blocked_body_bytes]`
- [ ] PASTIKAN blocking branch SECARA TEKNIS TIDAK PERNAH mencapai `return self.app(...)` di line terakhir
- [ ] Buat blocked body HTML sederhana yang sudah pasti di-escape, TIDAK merefleksikan payload mentah

### Phase 3: Flask Extension Integration

- [ ] Tambah parameter `blocking_enabled: bool = False` dan `blocking_exclude_paths: Optional[Sequence[str]] = None` pada class `XSSGuard.__init__()` dan `init_app()` di [flask_ext.py](file:///e:/XSSGuard-Security-Lab/xssguard/flask_ext.py#L56-L88)
- [ ] Teruskan parameter ini ke constructor `XSSGuardMiddleware` pada line 77-81
- [ ] Buat mekanisme eksplisit agar path yang didaftarkan `register_csp_report_route()` diteruskan ke `XSSGuard.init_app()` lalu ditambahkan ke `blocking_exclude_paths` set. Berlaku untuk `/csp-report` dan custom path.
- [ ] Pastikan context_processor nonce dan route registration TIDAK BERUBAH

### Phase 4: Safety & Regression (Safe Request)

- [ ] Jalankan `pytest tests/test_detector.py -v` → 100% LULUS
- [ ] Jalankan `pytest tests/test_middleware.py -v` → 100% LULUS (blocking default OFF, termasuk test_absence_of_ip_blocking)
- [ ] Jalankan `pytest tests/test_flask_ext.py -v` → 100% LULUS
- [ ] Jalankan `pytest tests/test_report.py -v` → LULUS
- [ ] Jalankan `pytest tests/test_dashboard.py -v` → LULUS
- [ ] Jalankan `pytest tests/test_security_hardening.py -v` → LULUS
- [ ] Jalankan `pytest tests/e2e/ -v` → LULUS (fixture d3, d4 di mode default OFF = kompatibel)
- [ ] Test manual safe request flow di Flask client: environ["xssguard.nonce"] == nonce token di CSP header

### Phase 5: Blocking Test Suite (Test A-F Matrix)

- [ ] Buat `tests/test_blocking.py` baru
- [ ] Test A1-A3: SAFE query/form/json di blocking OFF vs ON → HTTP 200 / route executed
- [ ] Test B1-B3: DETECTED XSS di blocking OFF → HTTP 200, `action="ALLOWED"`, route executed
- [ ] Test C1-C3: DETECTED XSS di blocking ON → HTTP 403, `action="BLOCKED"`
- [ ] **Test C ROUTE EXECUTION MARKER:** closure boolean flag di dalam route handler → assert called is False when blocked (PRIORITAS PALING TINGGI — bukti blocking sebelum self.app)
- [ ] Test C4: blocking ON + path whitelisted `/store` → `action="ALLOWED"`, route executed
- [ ] Test D1-D2: Database Integrity StoredPayloadStore count — blocked payloads tidak tersimpan
- [ ] Test E1-E2: /csp-report explicit exclusion — POST report ke /csp-report di blocking ON → HTTP 204, CspReportRecord tersimpan
- [ ] Test F1: Seluruh test existing di-run ulang dengan konfigurasi `blocking_enabled=True` pada SAFE test case

### Phase 6: Dashboard Enhancement (OPSIONAL, MAY)

- [ ] Jika diputuskan mau menampilkan badge BLOCKED: update template `_DASHBOARD_HTML` di [dashboard.py](file:///e:/XSSGuard-Security-Lab/xssguard/dashboard.py#L17-L87) pada bagian DetectionRecord table row
- [ ] Tambah CSS class badge merah / kuning di `static/dashboard.css` jika perlu
- [ ] Test rendering detection dengan `action="BLOCKED"` vs `"ALLOWED"` vs `None`

### Phase 7: Bukti & Audit

- [ ] Audit hasil implementasi: lakukan code review memastikan blocking branch TIDAK PERNAH memanggil `self.app`
- [ ] Jalankan route execution marker test sampai 100% hijau (bukti terkuat)
- [ ] Cek false positive sederhana: submit form dengan teks aman yang mengandung kata "script" tanpa tag → tidak ter-block
- [ ] Cek false negative benchmark 30 payload: 30/30 tetap terdeteksi, dan ketika blocking ON → 30/30 HTTP 403

### Phase 8: Documentation & UML (Setelah Test 100%)

- [ ] Update README / docs jika ada (jika diperlukan)
- [ ] HANYA SETELAH implementasi + audit + test LULUS SEMUA: Update Use Case Diagram, Activity Diagram, Sequence Diagram, Class Diagram, Component Diagram sesuai Bagian 17
- [ ] Jika storage adapter SQL ada: jalankan migration DB
- [ ] Release dengan changelog: New feature — Request/Payload Blocking (flag default OFF)

---

**END OF DOCUMENT**


## 21. REVISION HISTORY

| Versi | Tanggal | Perubahan |
|---|---|---|
| 1.0 | 2026-09-25 | Draft Pre-Implementation. |
| 1.1 | 2026-09-25 | Menutup BLOCKER-01 s.d. BLOCKER-05 berdasarkan audit source code: lifecycle nonce, mekanisme CSP report exclusion, path matching, terminologi ALLOWED/BLOCKED, dan backward compatibility DetectionRecord. Tidak ada source code yang diubah melalui dokumen ini. |
