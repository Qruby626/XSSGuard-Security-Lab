# AUDIT TEKNIS — DESIGN DECISION REQUEST / PAYLOAD BLOCKING
## Verifikasi Desain terhadap Source Code XSSGuard Aktual

**Tanggal Audit:** 2026-09-25
**Sumber Audit:** 
- [DESIGN_DECISION_REQUEST_PAYLOAD_BLOCKING.md](file:///e:/XSSGuard-Security-Lab/DESIGN_DECISION_REQUEST_PAYLOAD_BLOCKING.md)
- Source code aktual `e:\XSSGuard-Security-Lab\xssguard\` package (8 file Python)
- Test suite, examples, Chrome extension (existing)

---

# 1. EXECUTIVE SUMMARY

## Rekapitulasi Klasifikasi Temuan

| Klasifikasi | Jumlah Butir | Catatan |
|-------------|-------------|---------|
| 🟢 **SESUAI** | 47 butir | Sebagian besar keputusan desain konsisten dengan source code aktual dan arsitektur SoC existing. |
| 🟡 **PERLU DIKOREKSI** | 4 butir | Ada ketidaksesuaian antara klaim desain dengan kemampuan source code saat ini (khusus mekanisme auto-exclude path dan CSP nonce uniformity). |
| 🟠 **POTENSI MASALAH IMPLEMENTASI** | 5 butir | Risiko teknis lifecycle WSGI, backward compat storage, path matching whitelist, dataclass attribute pada object lama, dan enforcement order. |
| 🔴 **KONTRADIKSI KRITIS** | 1 butir | Ketidak-konsistenan internal dokumen tentang urutan Blocking Decision vs Generate Nonce pada alur request. Ada dua flow yang bertentangan. |
| ⚪ **TIDAK TERBUKTI** | 2 butir | (1) `storage_adapter.py` tidak ditemukan dalam repo; (2) `academic_lab` directory tidak ada sehingga kompatibilitas route berdasarkan asumsi fixture dan pola umum. |

## Keputusan Kesiapan Implementasi

**BUTUH KOREKSI DESAIN TERLEBIH DAHULU (Klasifikasi B)** sebelum memasuki tahap coding.

Alasan:
1. Ada **1 KONTRADIKSI KRITIS** tentang urutan Blocking Decision vs Generate Nonce yang berdampak pada seluruh lifecycle dan implementation checklist. Harus diselesaikan terlebih dahulu agar seluruh code konsisten.
2. Ada **4 PERLU DIKOREKSI** yang berupa asumsi desain tentang mekanisme yang BELUM ADA di source code (auto-exclude `/csp-report`, storage adapter, dll).
3. Secara substansi **arsitektur besar sudah benar** (enforcement point di middleware, detector pure, extension passive, status model 2 dimensi). Tidak perlu perubahan fundamental. Hanya klarifikasi detail sebelum coding.

---

# 2. ACTUAL XSSGUARD REQUEST FLOW (BERDASARKAN SOURCE CODE)

Berikut adalah rekonstruksi request flow yang DAPAT DIVERIFIKASI dari source code aktual tanpa asumsi:

```
HTTP Request (werkzeug / gunicorn WSGI server)
    ↓
    [flask_ext.py:77]  app.wsgi_app WRAPPED oleh XSSGuardMiddleware instance
    ↓
    [middleware.py:96]  XSSGuardMiddleware.__call__(environ, start_response)
    ↓
    Step 1 — Body Read + Replay
       [middleware.py:101-122]
       CONTENT_LENGTH > 0 → wsgi.input.read(n) → environ["wsgi.input"] = BytesIO(body_bytes)
       Fallback: wsgi.input.getvalue() → seek(0)
       Output: body_bytes: bytes
    ↓
    Step 2 — Request Extraction
       [middleware.py:125] data = _extract_request_data(environ, body_bytes)
       [middleware.py:27-79] _extract_request_data handles:
           QUERY_STRING → urllib.parse.parse_qs → data[k] = scalar or list
           JSON body (if Content-Type contains application/json OR body starts with { / [)
               → json.loads, dict flatten into data (merge list with _body if list)
           form-urlencoded (if body contains '=') → urllib.parse.parse_qs → merge
           plain body → data["_raw_body"] = body_str
       PATH_INFO / REQUEST_METHOD TIDAK di-extract dan TIDAK di-scan.
       Output: data: dict[str, Any]
    ↓
    Step 3 — Rule-Based Detection
       [middleware.py:126] results = scan_mapping(data, self.patterns)
       [detector.py:193-222] scan_mapping invariant:
           Returns ONLY list of DetectionResult with status="DETECTED".
           len(results) == 0 ⇔ SEMUA PAYLOAD DALAM mapping = SAFE.
       Output: results: list[DetectionResult] (DETECTED only, never SAFE entries)
    ↓
    Step 4 — Security Logging (DetectionRecord)
       [middleware.py:129-138] for result in results:
           DetectionRecord(
               payload=f"{result.field}={result.payload}",
               status=result.status,          # selalu "DETECTED"
               matched_rule=result.matched_rule,
               source=environ["PATH_INFO"],
               client_ip=environ["REMOTE_ADDR"],
           )
           → self.store.log_detection(record)
       Invariant saat ini: record.status SELALU "DETECTED".
       Belum ada field action. Belum ada konsep ALLOWED/BLOCKED.
    ↓
    Step 5 — Generate Dynamic CSP Nonce
       [middleware.py:141] nonce = generate_nonce()
       [nonce.py:42-59] secrets.token_bytes(16) → base64url encode (no padding)
       Output: nonce: str, 22 char, random
    ↓
    Step 6 — Expose Nonce ke WSGI Environment
       [middleware.py:144] environ["xssguard.nonce"] = nonce
    ↓
    Step 7 — Wrap start_response (Inject CSP Header)
       [middleware.py:147-154] def custom_start_response(status, response_headers, exc_info=None):
           headers = list(response_headers)
           headers.append(("Content-Security-Policy", build_csp_header(nonce)))
           return start_response(status, headers, exc_info)
       [nonce.py:93-133] build_csp_header(nonce):
           - always injects 'nonce-{nonce}' into script-src directive
           - default template includes report-uri /csp-report
    ↓
    Step 8 — Forward ke Flask Application (SECARA TIDAK KONDISIONAL 100%)
       [middleware.py:157]  return self.app(environ, custom_start_response)
       ⚠️ KRITIS: TIDAK ADA conditional branch pada `results`.
       Meskipun results mengandung 100 DetectionResult, baris ini SELALU dieksekusi.
       ↓
    Step 9 — Flask Routing
       app.wsgi_app matching URL rules → route handler function
       route bisa mengakses environ["xssguard.nonce"] via request.environ
       context_processor [flask_ext.py:83-86] expose ke Jinja sebagai xssguard_nonce
    ↓
    Step 10 — Flask Response
       Response body from Flask app
       + CSP header injected by custom_start_response wrapper
       ↓
    Client HTTP Response
```

### Jawaban 16 Item Checklist Bagian C (Actual Flow)

| # | Pertanyaan | Jawaban Aktual + Source Evidence |
|---|-----------|---------------------------------|
| 1 | Entry point request sebenarnya | Flask `app.wsgi_app` di-wrap oleh `XSSGuardMiddleware` instance. Entry callable = `__call__()` pada [middleware.py:96](file:///e:/XSSGuard-Security-Lab/xssguard/middleware.py#L96). |
| 2 | Class middleware | `XSSGuardMiddleware` pada [middleware.py:82](file:///e:/XSSGuard-Security-Lab/xssguard/middleware.py#L82). |
| 3 | Method yang menerima request | `__call__(environ: dict, start_response: StartResponse) -> Iterable[bytes]`. |
| 4 | Function extraction | `_extract_request_data(environ, body_bytes)` private helper pada [middleware.py:27](file:///e:/XSSGuard-Security-Lab/xssguard/middleware.py#L27). Handles query, JSON, form, raw body. |
| 5 | Function panggil detector | `scan_mapping(data, self.patterns)` pada [middleware.py:126](file:///e:/XSSGuard-Security-Lab/xssguard/middleware.py#L126). Import dari xssguard.detector. |
| 6 | Bentuk DetectionResult sebenarnya | Frozen dataclass pada [detector.py:27-42](file:///e:/XSSGuard-Security-Lab/xssguard/detector.py#L27-L42) dengan fields {status: str, matched_rule: Optional[str], payload: str, field: Optional[str]}. Status yang dihasilkan scan_mapping = SELALU "DETECTED". |
| 7 | Kapan DetectionResult dibuat | Di dalam `scan_mapping()` → `_walk_iterative()` → `_scan_str()` → first-match-wins return DetectionResult("DETECTED", pattern, value, dotted_field). |
| 8 | Kapan logging dilakukan | Setelah detection selesai, SEBELUM nonce dan self.app. Loop [middleware.py:129-138](file:///e:/XSSGuard-Security-Lab/xssguard/middleware.py#L129-L138). |
| 9 | Kapan nonce dibuat | Setelah logging detection selesai, sebelum self.app. [middleware.py:141](file:///e:/XSSGuard-Security-Lab/xssguard/middleware.py#L141). |
| 10 | Kapan CSP header dibuat | Di dalam custom_start_response wrapper yang di-invoke oleh host app ketika host app memanggil `start_response` [middleware.py:147-154](file:///e:/XSSGuard-Security-Lab/xssguard/middleware.py#L147-L154). |
| 11 | Kapan self.app(...) dipanggil | BARIS TERAKHIR method __call__ secara TIDAK KONDISIONAL. [middleware.py:157](file:///e:/XSSGuard-Security-Lab/xssguard/middleware.py#L157). |
| 12 | Request terdeteksi tetap mencapai Flask? | **YA, 100% SELALU.** Diverifikasi oleh test `test_repeated_attacks_from_same_ip_not_blocked` (10x attack semua HTTP 200). |
| 13 | Route tetap dieksekusi? | **YA.** Karena `self.app` dipanggil selalu. |
| 14 | Mekanisme blocking sudah ada? | **BELUM ADA SAMA SEKALI.** |
| 15 | HTTP 403 sudah ada? | **BELUM ADA.** Tidak ada `start_response("403")`, tidak ada `Response(status=403)`, tidak ada `abort(403)` di source xssguard package. |
| 16 | Early return sebelum self.app(...)? | **BELUM ADA.** Hanya satu return point yaitu baris 157 return self.app(...). |

---

# 3. SECTION-BY-SECTION AUDIT

| # | Section Dokumen | Keputusan Desain | Source Code Evidence | Status | Masalah | Tindakan Sebelum Coding |
|---|----------------|-----------------|---------------------|--------|--------|------------------------|
| 1 | **Definition of Status** | 2 dimensi terpisah: Detection Status (SAFE/DETECTED) milik detector; Enforcement Action (ALLOWED/BLOCKED) milik middleware. | DetectionResult frozen class di detector tidak memiliki field action → hanya detection concern. DetectionRecord storage class di storage tidak punya action field → benar 2 dimensi saat ini. | 🟢 SESUAI | Minor: Terminologi "LOGGED" vs "ALLOWED" perlu konsistensi final. | Pastikan satu istilah final ALLOWED untuk detection tanpa enforcement. |
| 2 | **Blocking Policy** | DETECTED ∧ blocking_enabled=true ∧ path tidak ter-exclude → ACTION=BLOCKED. | Saat ini tidak ada blocking_enabled parameter, tidak ada exclude path, tidak ada branch conditional. Kondisi ini valid dan dapat ditambahkan secara konsisten. | 🟢 SESUAI | — | — |
| 3 | **Enforcement Point** | `XSSGuardMiddleware.__call__()` = enforcement point. | `__call__()` adalah lokasi tunggal dimana extraction, detection, logging, nonce, self.app digabung. Merupakan satu-satunya tempat yang bisa early return sebelum self.app. | 🟢 SESUAI | — | — |
| 4 | **Blocking Flow (Safe)** | Safe request → ALLOWED → self.app normal | Saat ini len(results)=0 → loop log tidak berjalan → lanjut ke nonce + self.app. Logic ini tetap persis. | 🟢 SESUAI | — | — |
| 4 | **Blocking Flow (Detected + OFF)** | DETECTED + blocking_enabled=False → ALLOWED → self.app normal, log action=ALLOWED | Sesuai flow existing: saat ini memang semua DETECTED → diteruskan. Hanya perlu tambah action=ALLOWED field. | 🟢 SESUAI | — | — |
| 4 | **Blocking Flow (Detected + ON)** | DETECTED + blocking_enabled=True → BLOCKED → HTTP 403 → EARLY RETURN → Flask Route TIDAK dipanggil | Secara WSGI layak: middleware dapat memanggil start_response + return iterable tanpa panggil self.app. TAPI saat ini BELUM ADA implementasi, dan ada KONTRADIKSI URUTAN dengan section 6. | 🟡 PERLU DIKOREKSI | Lihat 🔴 C1 (kontradiksi urutan Nonce vs Decision). | Pilih SATU urutan final untuk Decision Point terhadap Generate Nonce. |
| 5 | **HTTP 403 Design** | Status=403, Content-Type=text/html, body informatif ter-escape, CSP header disertakan, nonce dibuat untuk uniformity | Secara WSGI start_response dapat return status apapun. Body return [bytes] valid. TAPI pertanyaan apakah nonce dibutuhkan = tidak konsisten dengan section 6. | 🟡 PERLU DIKOREKSI | Kontradiksi "blocked tidak butuh nonce" vs "nonce dibuat uniformity". | Pilih SATU kebijakan nonce untuk 403, lalu konsistenkan seluruh dokumen. |
| 6 | **CSP Dynamic Nonce** | Prinsip: Blocking (layer server) ≠ CSP Nonce (layer browser). Decision ALLOWED → kemudian Generate Nonce. Blocked branch opsional buat nonce (OPSI-A uniformity). | **AKTUAL FLOW di source code:** Generate Nonce DILAKUKAN SELALU, SEBELUM self.app dipanggil. Artinya saat ini TIDAK ADA conditional nonce → generate selalu. Dokumen menyatakan dua flow yang berbeda di dua section berbeda → KONTRADIKSI. | 🔴 KONTRADIKSI KRITIS C1 | Section 4 diagram flow: Generate Nonce terjadi HANYA di ALLOWED branch; Decision POINT sebelum nonce. Section 5-6 menyatakan OPSI-A: nonce dibuat pada BLOCKED juga. Actual code: generate selalu sebelum decision. | Selesaikan: Decision Point di INSERT sebelum baris 141 (sekarang generate nonce selalu), ATAU sesudah nonce dibuat tapi sebelum self.app. KEDUA SKENARIO harus dijelaskan impactnya lalu PILIH SATU. |
| 7 | **Logging / Evidence** | DetectionResult (detector) → TIDAK BERUBAH. DetectionRecord (storage) → TAMBAH field action: Optional[str]=None. Isi action saat buat DetectionRecord di middleware loop log. | DetectionRecord adalah mutable dataclass (bukan frozen). Menambah field dengan default backward compat valid. BaseStore Protocol signature `log_detection(record: DetectionRecord)` → parameter type TIDAK BERUBAH. MemoryStore TIDAK perlu perubahan (hanya append list). | 🟢 SESUAI | 🟠 M1 Backward compat object lama: record DetectionRecord yang sudah terlanjur dibuat sebelum upgrade dalam MemoryStore TIDAK memiliki attribute action. | Paksa populate action SELALU pada saat pembuatan record BARU di middleware. Di sisi consumer (dashboard / queries), akses action dengan pola `getattr(record, 'action', None)`. Dokumentasikan behavior ini. |
| 8 | **Feature Flag** | `blocking_enabled = False` default. Constructor parameter XSSGuardMiddleware dan XSSGuard Flask extension. | Constructor middleware saat ini parameter: (app, *, patterns, store). Dapat di-extend dengan kwargs tambahan tanpa breaking call existing positional. Flask XSSGuard constructor sama. Default False = existing user yang tidak kasih parameter → behavior 0 perubahan. | 🟢 SESUAI | — | — |
| 9 | **/csp-report Treatment** | /csp-report harus dipisahkan dari blocking; register_csp_report_route() OTOMATIS memasukkan path ke blocking_exclude_paths. | **KLAIM INI TIDAK ADA IMPLEMENTASINYA SAAT INI.** Fungsi register_csp_report_route() pada [flask_ext.py:22-50](file:///e:/XSSGuard-Security-Lab/xssguard/flask_ext.py#L22-L50) HANYA: `app.add_url_rule(path, view_func=csp_report, methods=["POST"])`. TIDAK ADA MEKANISME yang mengembalikan path ke daftar whitelist middleware. | 🟡 PERLU DIKOREKSI | Mekanisme auto-exclude di-desain tapi BELUM ADA titik integrasi. Middleware adalah object terpisah dari Flask route registration. Tidak ada callback channel hari ini. | Definisikan SECARA TEKNIS bagaimana path CSP report dikomunikasikan dari flask_ext ke middleware instance. Contoh: (1) XSSGuard.init_app() setelah memanggil register_csp_report_route, mem-pass path ke middleware.exclude_paths. ATAU (2) register_csp_report_route mengembalikan path yang didaftarkan lalu caller (init_app) menambahkan exclude. TIDAK BOLEH ada asumsi implisit. |
| 10 | **SAFE Request Guarantee** | Safe request: tidak diblokir, dapat Flask, dapat nonce, dapat CSP, response normal. | Safe path saat ini: results=[]. Boolean check `if results and blocking_enabled:` → pasti False. Alur code 100% identik dengan existing. | 🟢 SESUAI | — | — |
| 11 | **Academic Lab Integration** | Route tidak perlu diubah. Enforcement transparan sebelum route. Fixture d4 StoredPayloadStore (path /store) butuh whitelist atau blocking OFF. | Fixture d4_stored_xss_fixture.py menerima POST /store payload. Route TIDAK memiliki dependency logic xssguard apapun. Middleware wrap secara transparan. | 🟢 SESUAI | ⚪ A1: academic_lab directory tidak ditemukan, hanya fixture e2e. Kompatibilitas route umum forum/chat/announcement berdasarkan pola umum. | Tidak ada blocker. Seluruh route Flask standard compatible. |
| 12 | **File Impact Analysis** | MUST CHANGE=middleware, storage, flask_ext, config; MAY=dashboard; SHOULD NOT=detector, patterns, nonce, report, lab routes, extension. | Lihat Bagian 4 untuk audit terperinci per file. | 🟢 SESUAI (secara substansi) | Minor: file "Configuration" disebut MUST CHANGE → perlu dikonfirmasi apakah ini file terpisah atau hanya constructor parameter. | Secara implisit configuration = constructor parameter inline. Jika ada file config.py academic lab, perlu diketahui. |
| 13 | **Database / Storage Impact** | DetectionRecord tambah field action Optional[str]=None. Jika SQL adapter ada → migration. MemoryStore tidak butuh migration. | Cocok: dataclass mutable, field dengan default value = valid syntax Python. BaseStore signature tidak berubah. | 🟢 SESUAI | ⚪ A2: storage_adapter.py TIDAK DITEMUKAN di repo. | Konfirmasi keberadaan storage adapter SQL sebelum menulis migration. |
| 14 | **Security Considerations (12 poin)** | 12 aspek: False Pos, False Neg, Whitelist Bypass, 403 Leakage, Log Consistency, Body Handling, Nested JSON, Form/Query, CSP report, SAFE regression, WSGI lifecycle. | Semua 12 poin relevan dengan source code. | 🟢 SESUAI | 🟠 P1: Path matching whitelist trailing slash, blueprint prefix, URL encoding. Potensi bypass. | Tentukan spec path comparison (match exact PATH_INFO? normalize trailing slash? strip SCRIPT_NAME?). |
| 15 | **Testing Strategy (A-F Matrix)** | Test A safe, B detected+off, C detected+on, D DB integrity, E CSP report, F regression existing. | Semua dapat diimplementasikan dengan pytest + Flask test client yang existing. | 🟢 SESUAI | — | — |
| 16 | **Bukti Route Tidak Dieksekusi** | Route Execution Marker (closure boolean flag inside route handler). Assert marker is False when blocked. Assert != HTTP 403 response alone. | Flask test client dapat: define route di test function, mutable closure variable. | 🟢 SESUAI | — | — |
| 17 | **UML Impact** | 7 diagram: Use Case, Activity, Sequence, Component, Deployment, Class, ERD. | Sesuai scope perubahan. | 🟢 SESUAI | — | — |
| 18 | **Design Principles (11)** | Minimal Change, SoC, Backward Compat, Server-Side Enforcement, Detector Agnostic, Extension Passive, CSP independent, Safe Request tidak terganggu, Before self.app(), Evidence Auditable, No route changes. | Semua 11 sesuai source code. | 🟢 SESUAI | — | — |
| 19 | **Implementation Checklist 8 Phase** | Phase 0→8 (Storage → Middleware → Flask_ext → Regression Test → Blocking Test → Dashboard → Audit → UML). Urutan implementasi konsisten dengan dependency. | Phase 1 (Storage) dulu benar, karena Middleware butuh field action baru. | 🟢 SESUAI | 🟠 P2: Phase 2 (Middleware) harus membuat 2 helper (should_block, build_403_response) agar __call__ tidak terlalu panjang. Tapi checklist tidak mention private helper. | Tambah item untuk private method extraction decision dan response builder agar maintainable. |
| 20 | **Final Decision** | Konsolidasi seluruh keputusan. | Sebagian besar tervalidasi. Hanya 1 kontradiksi kritis dan 4 koreksi. | 🟡 PERLU DIKOREKSI | — | Selesaikan 🔴 C1 dan 4 🟡 sebelum approve. |

---

# 4. FILE-BY-FILE IMPACT AUDIT

| File | Peran Saat Ini (Source Evidence) | Klaim Dokumen | Hasil Audit | Alasan Detail | Perubahan Potensial (Jika Diimplementasi) |
|------|----------------------------------|--------------|------------|--------------|------------------------------------------|
| [middleware.py](file:///e:/XSSGuard-Security-Lab/xssguard/middleware.py) | Core: extraction (L27), detection invoke (L126), logging (L129), nonce (L141), CSP wrapper (L147), self.app forward (L157). | **MUST CHANGE** | 🟢 SESUAI | Satu-satunya enforcement point valid. Semua data tersedia di __call__. Early return WSGI compliant. Hanya lokasi ini yang dapat intercept sebelum Flask. | Tambah constructor params `blocking_enabled`, `blocking_exclude_paths`. Tambah conditional branch sebelum L157 (atau sebelum L141 nonce, bergantung resolusi 🔴C1). Tambah action populate saat buat DetectionRecord. Implement build_403_response(). |
| [detector.py](file:///e:/XSSGuard-Security-Lab/xssguard/detector.py) | Pure DetectionResult frozen, scan, scan_mapping. Module docstring: "framework-agnostic, must not import Flask/SQLAlchemy/WSGI/request/response". | **SHOULD NOT CHANGE** | 🟢 SESUAI | Semua informasi untuk decision blocking SUDAH TERSEDIA di hasil scan_mapping (empty list = safe, non-empty = detected). Tidak perlu menambah field apapun ke DetectionResult. | NONE (idealnya). |
| [patterns.py](file:///e:/XSSGuard-Security-Lab/xssguard/patterns.py) | DEFAULT_XSS_PATTERNS list of 10 (?i) regex. | **SHOULD NOT CHANGE** | 🟢 SESUAI | Blocking menggunakan detection result yang sama. Tidak perlu pattern khusus blocking. | NONE. |
| [storage.py](file:///e:/XSSGuard-Security-Lab/xssguard/storage.py) | DetectionRecord (payload,status,matched_rule,source,client_ip,created_at), CspReportRecord, BaseStore Protocol runtime_checkable, MemoryStore in-memory list Lock. | **MUST CHANGE** | 🟢 SESUAI | Field action TIDAK ADA saat ini. DetectionRecord adalah MUTABLE dataclass (bukan frozen). Tambah field `action: Optional[str] = None` valid syntax Python. | Tambah `action: Optional[str] = None` baris setelah client_ip pada DetectionRecord. Tidak ubah BaseStore Protocol signature. Tidak ubah MemoryStore impl. |
| **storage_adapter.py** | TIDAK DITEMUKAN dalam repo xssguard/ maupun directory workspace. | Disebut MUST CHANGE / NEEDS CONFIRMATION. | ⚪ TIDAK TERBUKTI | Hanya ada storage.py tunggal. Mungkin ada di env lain atau bagian academic lab terpisah. | Jika adapter SQL ada nanti → DDL `ALTER TABLE detection_records ADD COLUMN action VARCHAR(16) NULL;` + default value untuk existing row. |
| [flask_ext.py](file:///e:/XSSGuard-Security-Lab/xssguard/flask_ext.py) | XSSGuard extension class, init_app wrap app.wsgi_app dengan middleware, context_processor expose nonce, register_csp_report_route(). | **MUST CHANGE** | 🟢 SESUAI | Harus melewatkan parameter blocking_enabled + exclude_paths ke constructor call middleware L77. Juga harus mengkomunikasikan path CSP report ke exclude list. | Tambah constructor params `blocking_enabled: bool=False` dan `blocking_exclude_paths: Optional[list[str]]=None`. Di init_app() L77-81: teruskan parameter + path /csp-report ke set exclude middleware. |
| [nonce.py](file:///e:/XSSGuard-Security-Lab/xssguard/nonce.py) | generate_nonce CSPRNG, build_csp_header inject nonce ke script-src. Pure functions no state. | **SHOULD NOT CHANGE** | 🟢 SESUAI | Dua fungsi adalah pure dan independen dari detection state. Tidak butuh ubah. Blocking tidak mengubah cara generate atau build header. | NONE (kecuali jika memutuskan 403 TANPA CSP → maka tidak ubah juga; hanya caller yang skip memanggil). |
| [report.py](file:///e:/XSSGuard-Security-Lab/xssguard/report.py) | parse_csp_report bytes → CspReportData. Pure parsing. | **SHOULD NOT CHANGE** | 🟢 SESUAI | CSP violation report parsing adalah concern terpisah. Tidak terpengaruh request blocking. | NONE. |
| [dashboard.py](file:///e:/XSSGuard-Security-Lab/xssguard/dashboard.py) | Blueprint render template table DetectionRecord + CspReportRecord. Access d.status, d.payload, d.source, d.matched_rule. | **MAY CHANGE** | 🟠 BERPOTENSI BERUBAH | Saat ini tidak read attribute `action`. Jika field action ada, dashboard tetap jalan (tidak crash). Namun NICE-TO-HAVE menampilkan badge action BLOCKED/ALLOWED. | Optional: tambah conditional badge class CSS dan tampilan action column. |
| **Configuration** | SAAT INI: Semua config via constructor kwargs. Tidak ada file konfigurasi terpisah di package xssguard. | **MUST CHANGE** (tambah constructor params) | 🟢 SESUAI | Mengacu pada constructor parameter addition → benar. | Jika academic_lab/config.py terpisah, perlu menambah entry BLOCKING_ENABLED. Tapi di package xssguard → constructor params. |
| **Academic Lab Integration (routes)** | ⚪ TIDAK DITEMUKAN directory academic_lab. Hanya fixture e2e d3/d4. | **SHOULD NOT CHANGE (transparan)** | 🟢 SESUAI | Middleware wrap sebelum routing → route TIDAK PERLU diubah. | NONE pada route code. Hanya konfigurasi app saat init XSSGuard extension. |
| **Chrome Extension (entire folder)** | Manifest V3, permissions: [storage, webRequest, tabs] (no webRequestBlocking). service_worker.js comment L14-18 eksplisit: "No blocking handlers, no BlockingResponse, no cancel/redirect. No network/XSS blocking." | **SHOULD NOT CHANGE, tetap PASSIVE** | 🟢 SESUAI (KONSISTEN 100%) | Invariant kode extension secara eksplisit TEGAS melarang blocking. Trust boundary: server-side middleware adalah enforcement yang andal. | NONE sama sekali. |

---

# 5. CRITICAL DESIGN CONTRADICTIONS & ISSUES

### 🔴 C1 — Kontradiksi Urutan: Blocking Decision Point vs Generate Nonce

**Section yang bertentangan dalam dokumen desain:**

1. **Section 4.1 — Alur Umum Blocking Flow (diagram):**
   ```
   Step 4: Security Logging
   Step 5: BLOCKING DECISION POINT (BARU)
       ├─ KASUS A/B: ALLOWED → Step 6 Generate Nonce → Step 7 dst → Flask
       └─ KASUS C:     BLOCKED → Step 6 Generate Nonce SKIP → HTTP 403
   ```
   Implikasi: Generate nonce HANYA untuk ALLOWED request. Decision SEBELUM generate nonce.

2. **Section 5.3 + 6.2 — OPSI-A Uniformity:**
   ```
   BLOCKED Branch juga Generate Nonce + CSP Header tetap ada.
   Biaya satu call secrets.token_bytes(16). Tidak signifikan.
   ```
   Implikasi: Generate nonce DILAKUKAN untuk BLOCKED juga. Decision bisa SESUDAH atau SEBELUM, tapi nonce tetap dipanggil.

3. **Actual Code di middleware.py (BARIS 141 sebelum 157):**
   ```python
   # Step 4 — Log
   # Step 5 — Generate nonce: nonce = generate_nonce()
   # Step 6 — environ["xssguard.nonce"] = nonce
   # Step 7 — custom_start_response wrapper pakai nonce
   # Step 8 — return self.app(...)
   ```
   Actual code: Generate nonce SELALU, DI LUAR kondisi apapun, sebelum self.app.

**Konflik:**
Dokumen desain memiliki DUA interpretasi. Jika implementer mengikuti Section 4.1 secara letter → Decision Point DITANAM sebelum L141 (sekarang generate nonce), maka nonce TIDAK dibuat untuk blocked request. Jika mengikuti Section 5.3 → Decision Point ditanam SETELAH L144 (environ set nonce), maka nonce SELALU dibuat, untuk semua request, persis seperti code actual.

**Dampak:**
- Environment `environ["xssguard.nonce"]` consistency.
- Test expectation: apakah ketika blocked, environ masih memiliki key xssguard.nonce?
- WSGI server logging / instrumentation downstream.
- custom_start_response wrapper saat ini DI-DEFINE setelah nonce dibuat. Jika decision sebelum nonce, maka wrapper harus didefine di dua tempat (allowed vs blocked) → logic duplication + maintainability cost.

**Status:**
🔴 KONTRADIKSI KRITIS

**Keputusan yang HARUS dibuat SEBELUM coding (PILIH SALAH SATU, DAN KONSISTENKAN SELURUH DOKUMEN + CHECKLIST + TEST EXPECTATION):**

| PILIHAN | Lokasi Decision Point | Generate Nonce Untuk Blocked? | Pro | Kontra |
|---------|----------------------|------------------------------|-----|--------|
| **X (Direkomendasikan Audit)** | **SETELAH L138 (loop log selesai), SEBELUM L141 (generate nonce)** — TAPI generate nonce TETAP dipanggil pada blocked branch secara eksplisit. Hanya environ["xssguard.nonce"] + custom_start yang conditional. Atau lebih sederhana: Decision sebelum L141, lalu BOTH branch generate nonce juga. | YA (selalu) | 1. Mirip code actual → minim change footprint. 2. custom_start_response wrapper HANYA perlu didefinisikan SATU KALI, SEBELUM decision. 3. Tidak ada percabangan nonce. | Satu call secrets.token_bytes yang "terbuang" untuk blocked request. (cost: ~2μs, negligible.) |
| **Y** | Setelah environ set nonce (setelah L144) sebelum define wrapper. | YA (nonce sudah dibuat terlebih dahulu) | Paling minim ubah existing code structure. | Tidak ada — sebenarnya ini paling mudah, tapi Section 4.1 flow harus di-update gambarnya. |
| **Z** | Sebelum L141, blocked branch SKIP generate nonce. | TIDAK | Menghemat 2μs. | (1) KONTRADIKSI dengan Section 5.3 OPSI-A. (2) Perlu define 2x start_response wrapper → logic duplikat. (3) Semua test expectation untuk CSP header pada 403 harus di-update "tidak ada CSP header". (4) Inconsistent response headers → downstream WAF / analytics bingung. |

**Rekomendasi audit → PILIHAN Y (paling minim perubahan, paling backward compatible):** Decision Point TEPAT di ANTARA L144 (setelah environ nonce) dan L146 (sebelum define custom_start_response). Atau PILIHAN X sama baiknya. **APAPUN PILIHANNYA: PASTIKAN SATU KEPUTUSAN FINAL dan UPDATE SELURUH SECTION dokumen desain agar tidak ada kontradiksi.**

---

### 🟡 C2 — Asumsi Auto-Exclude `/csp-report` Tidak Didukung Mekanisme Apapun

**Dokumen Section 9.2:**
> "Fungsi register_csp_report_route() pada flask_ext.py secara otomatis mendaftarkan path ke blocking_exclude_paths internal Flask Extension instance."

**Source code flask_ext.py register_csp_report_route L22-50:**
Hanya memanggil `app.add_url_rule(path, ...)`. TIDAK ADA return value path. TIDAK ADA side effect set attribute di `self.blocking_exclude_paths`. TIDAK ADA callback. Function berdiri sendiri.

**Konflik:** Ada jarak antara desain "auto exclude" dengan mekanisme actual.

**Status:** 🟡 PERLU DIKOREKSI

**Keputusan sebelum coding:**
Pilih SATU mekanisme:
1. Ubah signature `register_csp_report_route()` → mengembalikan `registered_path: str`. Lalu `XSSGuard.init_app()` menangkap return value dan menambahkannya ke `blocking_exclude_paths` sebelum instantiate middleware.
2. Tambahkan `store_or_ext_ref` parameter ke `register_csp_report_route()` agar dapat mutate extension instance exclude list.
3. Cara termudah: di `XSSGuard.init_app()` sebelum `app.wsgi_app = XSSGuardMiddleware(...)`, hardcode append `/csp-report` + parameter `path` custom jika diberikan.

---

### 🟡 C3 — Terminologi Action Value: LOGGED vs ALLOWED

**Dokumen Section 1.4 Terminologi:** "LOGGED = DETECTED + ALLOWED. Terminologi resmi yang dipilih untuk evidence field: action dengan nilai ALLOWED atau BLOCKED."

**Masalah:** Ada dua istilah untuk hal sama. Berpotensi test name, log message, dashboard label tidak konsisten.

**Status:** 🟡 PERLU DIKOREKSI

**Keputusan:** Dijelaskan EXPLISIT bahwa "LOGGED" adalah alias informal, sementara NILAI FIELD RESMI di storage = HANYA `"ALLOWED"` dan `"BLOCKED"`, dengan `None` untuk legacy.

---

### 🟡 C4 — DetectionRecord Default Action = None vs Isi Selalu

**Dokumen Section 7.2:** Field action Optional[str], default None. Tapi Section 7.3 mengatakan: "Selalu di-isi oleh middleware pada saat log_detection".

**Potensi:** Jika pengembang lupa mengisi, record action=None tercipta untuk record BARU. Tidak ada enforcement.

**Status:** 🟡 PERLU DIKOREKSI (minor)

**Rekomendasi:** Tulis secara eksplisit bahwa pada constructor `DetectionRecord(...)` di middleware loop, WAJIB menyertakan keyword argument `action=<computed_value>` dan TEST WAJIB memverifikasi bahwa tidak ada record BARU dengan action=None setelah upgrade.

---

### 🟠 P1 — Whitelist Path Matching Spec Kosong

**Dokumen menggunakan `blocking_exclude_paths` tapi tidak menspesifikasikan:**
- Apakah exact match string terhadap `environ["PATH_INFO"]`?
- Bagaimana dengan trailing slash? `/store` vs `/store/`?
- Bagaimana dengan `SCRIPT_NAME` prefix WSGI (jika app di-mount di subpath)?
- Bagaimana dengan Blueprint url_prefix (misal `/api` menjadi `/api/store`)?
- Case sensitive?
- URL decoding?

**Status:** 🟠 POTENSI MASALAH IMPLEMENTASI

**Konsekuensi jika tidak di-spec: Path bypass attacker via `/csp-report/` (trailing slash), `/CSP-REPORT` (case uppercase), `/v1/csp-report` (mounted subpath).**

**Perlu ditambahkan sebelum coding:** Standarisasi comparison spec. Rekomendasi audit: Normalisasi path sebelum comparison.

---

### 🟠 P2 — DetectionRecord AttributeError pada Objek Legacy (MemoryStore)

**Storage impact analysis:**
DetectionRecord object yang SUDAH DIBUAT sebelum upgrade (misalnya: web server sudah running 2 jam, ada 500 detection di MemoryStore._detections list) dibuat dengan constructor LAMA (tanpa parameter `action`). Python dataclass TIDAK menambahkan attribute default secara retroaktif ke instance yang sudah ada. Ketika dashboard rendering loop mengakses `d.action` → AttributeError.

**Status:** 🟠 POTENSI MASALAH IMPLEMENTASI

**Mitigasi wajib sebelum coding:** Seluruh pembacaan attribute `action` di codebase (khususnya dashboard.html rendering dan test) menggunakan pola:
```python
action = getattr(detection_record, 'action', None)
```
bukan direct `detection_record.action`. Ini harus dicantumkan eksplisit di design decision bagian storage impact.

---

### 🟠 P3 — WSGI Iterable Close() pada Blocked Path

**Audit lifecycle WSGI:**
Saat ini `return self.app(...)` mengembalikan iterable dari host app yang mungkin memiliki `.close()` method (contoh: Flask app menggunakan Response with file attachment). Middleware adalah pass-through dan tidak perlu khawatir.

Jika blocked branch mengembalikan `return [blocked_body_bytes]` → ini adalah list Python biasa. Tidak memiliki `.close()`. Secara WSGI spec valid.

TAPI: Jika host app wrapper (contoh: session middleware) membutuhkan `close()` dipanggil → karena self.app TIDAK dipanggil di blocked branch, maka tidak ada closeable iterable dari host app → valid.

**Status:** 🟠 POTENSI MASALAH IMPLEMENTASI (Low Risk)

**Mitigasi:** Dokumentasikan bahwa blocking early return TIDAK memanggil resource app downstream. Test E2E dengan middleware chaining.

---

### 🟠 P4 — Ordering: Populate Action DetectionRecord SEBELUM Decision

**Inconsistency desain section 4.1: Logging Step 4 sebelum Decision Step 5. Artinya log action harus DI-ISI SEBELUM decision diambil (karena log dicatat sebelum decision). Tapi action = BLOCKED / ALLOWED ditentukan oleh decision itu sendiri.**

Ini bisa membingungkan developer. Alur yang benar:
```
1. Compute decision_value = should_block(results) → bool
2. Compute action_value = "BLOCKED" if decision_value else "ALLOWED"
3. Create DetectionRecord(..., action=action_value) → write store
4. Eksekusi decision: jika block → early return. jika tidak → lanjut.
```

Design decision saat ini tidak memisahkan langkah 1-3 secara eksplisit. Berpotensi detection dicatat dengan action value yang salah.

**Status:** 🟠 POTENSI MASALAH IMPLEMENTASI

---

### ⚪ A1 — academic_lab/ directory tidak ditemukan

Tidak ada bukti source code route forum/comment/chat/announcement dalam repo. Semua klaim kompatibilitas berdasarkan pola umum Flask + fixture e2e yang ada.

---

### ⚪ A2 — storage_adapter.py tidak ditemukan

Tidak ada file storage adapter terpisah (SQL/SQLAlchemy/SQLite) dalam repo. Hanya MemoryStore.

---

# 6. BLOCKING FLOW VALIDATION

Validasi tiga flow inti terhadap source code aktual.

### Flow 1. SAFE → ALLOWED → Flask App

```
Conditional check proposal: if results and self.blocking_enabled: → FALSE
    ↓
Seluruh execution path identik dengan existing code:
    nonce dibuat,
    environ xssguard.nonce diset,
    self.app(environ, custom_start) di-return.
```
**Hasil:** 🟢 DAPAT DITERAPKAN. Zero risk.

### Flow 2. DETECTED + blocking OFF → ALLOWED → Flask App

```
results = non-empty list. blocking_enabled = False.
Conditional: True AND False → FALSE.
    ↓
Execution path identik existing code, KECUALI:
  DetectionRecord(..., action="ALLOWED") ditambahkan field.
```
**Hasil:** 🟢 DAPAT DITERAPKAN. Hanya tambah 1 field.

### Flow 3. DETECTED + blocking ON → BLOCKED → HTTP 403 → Flask TIDAK dipanggil

```
results non-empty. blocking_enabled = True. path tidak di-exclude.
Conditional: True AND True AND True → TRUE.
    ↓
Masuk branch BLOCKED:
  start_response("403 Forbidden", headers) dipanggil oleh middleware SECARA LANGSUNG.
  return [blocked_html_bytes].
  (kata kunci: TIDAK PERNAH MEMANGGIL self.app(...))
    ↓
Flask Routing TIDAK terpanggil.
Route Handler Function TIDAK di-eksekusi.
Database Insert (side effect route) TIDAK terjadi.
```

**Hasil:** 🟢 DAPAT DITERAPKAN secara WSGI-compliant.

**⚠️ Syarat blocking flow valid:**
1. Kondisi IF harus dievaluasi SETELAH logging detection record selesai (untuk audit trail lengkap).
2. Kondisi IF dievaluasi SEBELUM `return self.app(...)` dijalankan.
3. Blocked branch MEMANGGIL `start_response("403 Forbidden", ...)` secara eksplisit SEBELUM return list bytes (jika tidak → error "start_response was not called before writing body").
4. Blocked branch TIDAK PERNAH JATUH ke baris `return self.app(...)`.

---

# 7. STORAGE / EVIDENCE VALIDATION

### Kompatibilitas DetectionResult + DetectionRecord dengan konsep action:

| Komponen | Perubahan Diusulkan | Dapat Diterapkan? | Alasan |
|---------|-------------------|-----------------|--------|
| `DetectionResult` (detector frozen dataclass) | **TIDAK DIUBAH** | 🟢 Ya | Detector tetap pure. Tidak butuh knowledge tentang enforcement. |
| `DetectionRecord` (storage mutable dataclass) | Tambah field `action: Optional[str] = None` | 🟢 Ya | Dataclass mutable → valid. Default value memberikan backward compat pada CONSTRUCTOR call (baru). |
| `BaseStore` Protocol | **TIDAK DIUBAH** | 🟢 Ya | Signature `log_detection(record: DetectionRecord)` → param type sama. Liskov substitution satisfied. |
| `MemoryStore` | **TIDAK DIUBAH** | 🟢 Ya | Hanya append record ke list. Tidak peduli field baru. |
| `Dashboard Query (recent_detections)` | Opsional: template read `action` via getattr | 🟡 Perlu getattr | Mencegah AttributeError pada record lama yang tidak punya attribute action. |
| `SQL Adapter (jika ada)` | Migration add column | ⚪ TIDAK TERBUKTI | storage_adapter.py tidak ada di repo. |

### Ringkasan:
**Action ALLOWED / BLOCKED DAPAT DITERAPKAN tanpa merusak struktur storage yang ada, DENGAN CATATAN getattr pattern access untuk backward compat record legacy dalam MemoryStore runtime.**

---

# 8. CSP / NONCE VALIDATION

### Mekanisme yang divalidasi:

1. **generate_nonce() [nonce.py:42]**: Pure CSPRNG function. Tidak ada state. Tidak terpengaruh blocking. ✅ 🟢

2. **environ["xssguard.nonce"] [middleware.py:144]**: Diset sebelum self.app. Blocking yang early return TIDAK akan mengekspos nonce ke app. Tergantung resolusi 🔴C1. ⚠️ 🔴 TUNGGU FINAL.

3. **CSP Header Injection via custom_start_response [middleware.py:147-154]**: Wrapper dibuat di dalam __call__ dan selalu menangkap closure variable `nonce`. Hanya di-invoke oleh host app ketika host app call start_response. Pada blocked branch, middleware BISA memanggil custom_start_response sendiri (jika wrapper sudah dibuat) ATAU membuat headers list secara hardcode. ✅ 🟢.

4. **CSP report parsing [report.py]**: Terpisah total. Terima POST JSON /csp-report. Endpoint ini perlu masuk exclude list. Mekanisme auto-exclude BELUM ADA di source code (lihat 🟡C2). ⚠️ 🟡.

5. **/csp-report endpoint [flask_ext.py:22]**: Flask route. Hanya menerima POST. Detection dapat terjadi JIKA field CSP report JSON aneh match pattern. Whitelist PATH_INFO exclusion secara teknis work tapi perlu mekanisme.

### Potensi Konflik Sudah Ditandai:
🔴 C1 (Urutan Nonce vs Decision). Perlu finalisasi.
🟡 C2 (Auto exclude /csp-report). Perlu mekanisme integrasi.

---

# 9. TESTING GAP ANALYSIS

Berikut adalah gap testing — item yang TIDAK BISA dijalankan DENGAN SENDIRINYA dengan infrastructure yang ADA SAAT INI (tanpa menambah test fixture baru).

| Gap ID | Test yang Dimiliki Desain | Infrastructure Existing | Gap / Yang Perlu Ditambahkan |
|--------|--------------------------|------------------------|------------------------------|
| G1 | Route Execution Marker (Test C1-C3: assert route tidak dipanggil) | Tidak ada fixture closure marker yang ready. Existing test hanya assert HTTP status + body content. | Test file baru `tests/test_blocking.py` perlu menyertakan pattern mutable closure variable explicit. |
| G2 | Database Integrity Stored XSS (Test D1-D2: assert payload tidak masuk DB) | Hanya MemoryStore pada fixture d4_stored_xss_fixture `StoredPayloadStore` in-memory list. | Integrasikan fixture d4 ke dalam test suite blocking. Assert `len(StoredPayloadStore.get_all()) == 0` setelah blocked attack. |
| G3 | Test blocking_enabled=True dengan Path Whitelist exclude (Test C4) | Tidak ada test fixture untuk testing whitelist. | Buat fixture dengan middleware parameterized `blocking_exclude_paths=["/store"]` → POST XSS to /store → assert ALLOWED action dan route terpanggil. |
| G4 | Test bahwa action field selalu di-populate pada DetectionRecord (tidak ada None baru) | Existing test hanya assert `len(recent_detections)`. | Assert pada setiap detection record BARU di dalam post-upgrade test: `getattr(record, 'action', None) in ("ALLOWED", "BLOCKED")`. |
| G5 | Test backward compat DetectionRecord legacy attribute action (getattr pattern) | Tidak ada test buat record legacy lalu render dashboard. | Simulasi buat DetectionRecord TANPA action (via setattr del atau buat object dari constructor lama — tricky) → assert dashboard render TIDAK lempar AttributeError. |
| G6 | Test WSGI lifecycle close() pada blocked response (termasuk middleware chaining) | Tidak ada test untuk close behavior. | Buat custom WSGI app yang memiliki close() method dengan counter → assert ketika request ALLOWED, close dipanggil. Ketika BLOCKED, app TIDAK dipanggil → close counter tidak naik. |
| G7 | Path matching whitelist edge cases (trailing slash, case, script_name prefix) | Belum ada spec → belum ada test. | Tambahkan test matrix setelah spec final di 🟠P1 ditetapkan. |

---

# 10. IMPLEMENTATION BLOCKERS

Berikut hal-hal **HARUS** diselesaikan sebelum menulis baris kode pertama implementasi.

### BLOCKER-01
**Resolve 🔴 KONTRADIKSI KRITIS C1 — Finalisasi Urutan Decision Point vs Generate Nonce.**
- Pilih satu: Pilihan X, Y, atau Z (audit merekomendasikan PILIHAN Y: decision point SETELAH environ["xssguard.nonce"] di-set, SEBELUM define custom_start_response wrapper).
- Konsistenkan SELURUH section dokumen desain:
  - Section 4.1 General Flow diagram.
  - Section 4.4 KASUS C alur detail blocked request step-by-step.
  - Section 5.3 HTTP 403 Design: apakah 403 memiliki CSP nonce?
  - Section 6.2 Urutan Eksekusi Final: TULIS urutan final yang konsisten.
  - Bagian 20 Implementation Checklist step: urutan conditional placement.
  - Test expectation Step Test C: apakah environ nonce ada setelah blocked?

### BLOCKER-02
**Resolusi 🟡C2 — Mekanisme Auto-Exclude Path /csp-report secara TEKNIS eksplisit.**
- Pilih satu mekanisme: return value dari register_csp_report_route, atau mutation attribute di init_app.
- Tulis eksplisit bagaimana path custom parameter `path=...` juga ikut di-exclude.
- Tulis spec path matching yang akan dipakai (stub untuk 🟠P1).

### BLOCKER-03
**Spec path matching whitelist explicit 🟠P1 (minimal):**
- Exact match `PATH_INFO`?
- Trailing slash policy: `/store` sama dengan `/store/`?
- Case sensitive?
- Bagaimana dengan blueprint prefix dan SCRIPT_NAME?

### BLOCKER-04 (Opsional tapi direkomendasikan)
**Resolusi 🟡C3 Terminologi Final:**
- Putuskan kata final: `"ALLOWED"` (bukan `"LOGGED"`) untuk action.
- Pastikan seluruh dokumen tidak ada kata "LOGGED" untuk field value.

### BLOCKER-05 (Opsional tapi direkomendasikan)
**Mitigasi 🟠P2 Backward compat record legacy DetectionRecord:**
- Cantumkan wajib `getattr(d, 'action', None)` pattern access di seluruh document untuk dashboard dan consumer lain.
- Jelaskan implikasi field default None vs instance attribute tidak ada pada object legacy.

---

# 11. SAFE TO IMPLEMENT CHECKLIST

| Item | Status (Selesai/Belum/Sebelum Coding) | Bukti / Catatan |
|------|--------------------------------------|-----------------|
| [x] Design Decision konsisten dengan middleware Enforcement | ⚠️ HAMPIR. Menunggu BLOCKER-01 resolve. | Minor urutan nonce vs decision. |
| [x] Enforcement point tervalidasi (middleware.__call__) | ✅ SELESAI | Source middleware.py L96, L157. |
| [x] Detection/Blocking separation tervalidasi | ✅ SELESAI | Detector frozen pure, TIDAK ADA WSGI/Flask import. |
| [x] HTTP 403 response tervalidasi (WSGI compliant) | ✅ SELESAI | start_response + return [bytes] valid pattern. |
| [x] `blocking_enabled` default False backward compat | ✅ SELESAI | Constructor kwargs extendable tanpa breaking existing call. |
| [x] Storage impact tervalidasi | ✅ SELESAI (dengan catatan P2 mitigasi) | DetectionRecord add field Optional[str] valid syntax. |
| [ ] CSP nonce decision FINAL (blocked request generate? tidak?) | ❌ BELUM. BLOCKER-01. | Butuh keputusan. |
| [ ] /csp-report exclusion behavior FINAL dan mekanisme jelas | ❌ BELUM. BLOCKER-02. | Hari ini TIDAK ADA mekanisme auto exclude. |
| [ ] Excluded path behavior FINAL dan spec matching | ❌ BELUM. BLOCKER-03. | Kosong spec. |
| [x] Academic Lab integration transparan tervalidasi | ✅ SELESAI (asumsi fixture) | Route standard Flask 0 perubahan. Directory academic_lab tidak ditemukan tapi pola umum valid. |
| [x] Test strategy matrix tervalidasi | ✅ SELESAI | 9 kategori testing. 7 GAP teridentifikasi tapi resolvable saat test nanti. |
| [x] Route non-execution proof (marker pattern) tervalidasi | ✅ SELESAI | Flask closure mutable pattern valid di Python. |
| [x] Chrome Extension scope tetap passive | ✅ SELESAI | service_worker.js comment + manifest permissions. |
| [x] UML impact diketahui 7 diagram | ✅ SELESAI | Detail section 17. |
| [ ] Tidak ada kontradiksi kritis | ❌ BELUM (1 tersisa). | 🔴C1 belum terselesaikan. |

---

# KESIMPULAN UTAMA AUDIT

**Pertanyaan:** "Apakah DESIGN_DECISION_REQUEST_PAYLOAD_BLOCKING.md sudah benar-benar sinkron dengan source code XSSGuard sehingga kita dapat masuk ke tahap implementasi tanpa mengubah desain secara fundamental?"

**Jawaban Audit:**

**ARSITEKTUR BESAR SUDAH SINKRON 95%** (enforcement point di middleware, detector pure, extension passive, status model 2 dimensi, feature flag default off, safe request tidak terganggu, storage field action baru di DetectionRecord). **TAPI BUTUH KOREKSI 4 ITEM DAN RESOLUSI 1 KONTRADIKSI KRITIS TERLEBIH DAHULU** sebelum menulis kode.

Tiga hal yang harus dilakukan terlebih dahulu:
1. ✅ **SELESAIKAN BLOCKER-01** (pilih urutan decision vs nonce).
2. ✅ **SELESAIKAN BLOCKER-02** (mekanisme auto exclude /csp-report).
3. ✅ **SELESAIKAN BLOCKER-03** (spec path whitelist matching).

Setelah ketiga blocker selesai, dan checklist item "tidak ada kontradiksi kritis" menjadi ✅, desain dapat dinyatakan **SIAP IMPLEMENTASI**.
