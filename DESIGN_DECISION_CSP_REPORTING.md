# DESIGN DECISION — CSP VIOLATION REPORTING v1.0

| Field | Nilai |
|---|---|
| Versi | 1.0 |
| Tanggal | 21 September 2026 |
| Scope | CSP Violation Reporting — Phase D5 |
| Hubungan | Terpisah dari `DESIGN_DECISION_TRUSTED_SCRIPT_NONCE.md` |
| Status | Proposed |

---

## 1. Problem / Context

XSSGuard saat ini sudah memiliki infrastruktur CSP Violation Reporting yang
berfungsi:

- **Endpoint `/csp-report`** sudah terdaftar melalui Flask extension
  (`flask_ext.py` → `register_csp_report_route()`). Endpoint ini bertindak
  sebagai **passive receiver** — hanya menerima report yang dikirim browser,
  bukan aktif meminta atau memvalidasi report.

- **`report.py`** menyediakan `parse_csp_report()` yang mem-parsing raw request
  body menjadi `CspReportData`. Parser ini mengharapkan format CSP violation
  report **legacy** berupa JSON object, baik dalam bentuk langsung maupun
  dibungkus `{"csp-report": {...}}`.

- **Model data/storage** sudah mengikuti format tersebut. `CspReportRecord`
  menyimpan `document_uri`, `violated_directive`, `blocked_uri`, dan `client_ip`
  (audit only).

- **Browser E2E Phase D5** membutuhkan pembuktian bahwa CSP violation yang terjadi
  di browser dapat menghasilkan report yang diterima dan dicatat oleh XSSGuard.

Kondisi saat ini: endpoint sudah ada dan berfungsi sebagai passive receiver,
tetapi CSP header yang dihasilkan `build_csp_header()` belum menyertakan
directive `report-uri` sehingga browser belum tahu ke mana harus mengirim report.

---

## 2. Decision

XSSGuard Phase D5 menggunakan:

```text
report-uri /csp-report;
```

sebagai mekanisme browser CSP violation reporting.

Default report endpoint:

```text
/csp-report
```

Directive `report-uri /csp-report` akan ditambahkan ke default CSP policy template
agar browser secara otomatis mengirim CSP violation report ke endpoint yang sudah
tersedia.

Tidak ada mekanisme reporting lain yang ditambahkan pada Phase D5.

---

## 3. Passive Receiver Contract

Endpoint `/csp-report` **hanya** bertanggung jawab untuk:

1. Menerima HTTP POST.
2. Membaca raw request body.
3. Memanggil `parse_csp_report()`.
4. Apabila report valid, memanggil `store.log_csp_report()`.
5. Selalu mengembalikan HTTP 204 No Content.

Endpoint **TIDAK** bertanggung jawab untuk:

- Generate nonce.
- Menentukan trusted script.
- HTML rewriting.
- Script injection.
- Response-body modification.
- IP blocking.
- Rate limiting.
- Request blocking tambahan.

Kontrak ini sesuai dengan `IMPLEMENTATION_CONTRACT.md` §4 (Kontrak CspReportRoute)
dan `.agents/rules/rule.md` §8.

---

## 4. Why report-uri Only in Phase D5

Phase D5 **hanya** menggunakan:

```text
report-uri /csp-report
```

dan **TIDAK** menggunakan:

```text
report-to
Reporting-Endpoints
```

**Alasan:**

Implementasi parser saat ini (`report.py` → `parse_csp_report()`) mengikuti format
CSP violation report legacy yang diterima melalui `report-uri`. Parser ini
mengharapkan:

- **JSON object tunggal** (bukan array).
- Format `{"csp-report": {...}}` atau object langsung.
- Field names menggunakan konvensi dash (`document-uri`, `violated-directive`,
  `blocked-uri`, `original-policy`) atau underscore.

Parser ini **belum dirancang** untuk menangani Reporting API modern, yang mencakup:

- Top-level JSON array (`[{"type": "csp-violation", "body": {...}}, ...]`).
- Struktur report modern dengan field `type`, `age`, `url`, `user_agent`, `body`.
- Field names modern di dalam `body` object.

Menggunakan `report-uri` pada Phase D5 memastikan kompatibilitas penuh antara
format yang dikirim browser dan parser yang sudah teruji.

---

## 5. Deferred Reporting API

Dukungan untuk:

```text
report-to
Reporting-Endpoints
```

**DITUNDA** dan **bukan bagian dari Phase D5**.

Jika dukungan tersebut akan ditambahkan di masa depan, perubahan tersebut **harus
menjadi Design Decision/feature terpisah**. Perubahan masa depan tersebut
sekurang-kurangnya harus mempertimbangkan:

- **Top-level JSON array**: Reporting API mengirim batch report dalam array.
- **Report type**: Field `type` pada level report (e.g., `"csp-violation"`).
- **Body object**: Payload CSP violation berada di dalam `body`, bukan di
  top-level object.
- **Modern field names**: Perbedaan nama field antara legacy dan modern format.
- **Mapping ke CspReportData**: Bagaimana field modern dipetakan ke
  `CspReportData` yang existing atau perlu perubahan dataclass.
- **Parser compatibility**: Apakah parser mendeteksi format secara otomatis atau
  memerlukan konfigurasi explicit.
- **Tests**: Unit test dan integration test untuk format modern.
- **Browser E2E**: Verifikasi bahwa browser modern mengirim report dalam format
  yang diharapkan melalui Reporting API.

---

## 6. Custom Report Path

Custom report path **bukan bagian dari Phase D5**.

Endpoint default:

```text
/csp-report
```

tetap digunakan.

Meskipun `register_csp_report_route()` menerima parameter `path`, pada Phase D5
**tidak dilakukan perubahan** untuk menghubungkan parameter custom path tersebut
dengan `build_csp_header()`. Artinya, directive `report-uri` pada CSP header
selalu menunjuk ke `/csp-report` terlepas dari apakah `register_csp_report_route()`
dipanggil dengan path berbeda.

Propagasi custom path ke CSP header merupakan pekerjaan lanjutan jika dibutuhkan.

---

## 7. Architectural Boundary

CSP Violation Reporting dan Trusted-Script Nonce adalah dua concern yang
**terpisah** dan **tidak boleh digabung** menjadi satu mekanisme.

### Trusted-Script Nonce

```text
Middleware
    |
    +--> generate_nonce()
    |
    +--> environ["xssguard.nonce"]
    |
    v
Host Application
    |
    +--> trusted inline script memakai nonce
```

Concern: mengatur trusted inline script melalui CSP nonce per-request.

### CSP Violation Reporting

```text
Browser
    |
    +--> CSP violation terjadi
    |
    +--> POST /csp-report
    |
    v
XSSGuard
    |
    +--> parse_csp_report()
    |
    +--> store.log_csp_report()
    |
    v
HTTP 204
```

Concern: menyediakan observability/detection signal dari pelanggaran CSP yang
terjadi di browser.

### Titik Kontak

Satu-satunya titik kontak antara kedua concern:

- `build_csp_header()` menghasilkan CSP header yang memuat **baik** nonce
  (`script-src 'nonce-{nonce}'`) **maupun** report directive
  (`report-uri /csp-report`).
- Keduanya berada pada CSP header yang sama, tetapi menjalankan fungsi berbeda.

Nonce menentukan **enforcement** (script mana yang boleh dieksekusi), sedangkan
report-uri menentukan **reporting** (ke mana violation dilaporkan).

---

## 8. Nonce Architecture Protection

Design Decision D5 (CSP Violation Reporting) secara eksplisit **TIDAK mengubah**:

- Request-scoped nonce (satu nonce per request).
- Exactly-one nonce generation per request via `generate_nonce()`.
- `environ["xssguard.nonce"]` sebagai primitive API resmi.
- Trusted inline script contract (host application menerapkan nonce secara
  eksplisit).
- Host application responsibility atas penentuan trust.
- CSP nonce matching (`script-src 'nonce-{nonce}'`).
- Non-response-body-rewriting (middleware tidak memodifikasi response body).
- Non-automatic HTML nonce injection (middleware tidak menyisipkan nonce ke
  tag `<script>` secara otomatis).

Seluruh invariant Trusted-Script Nonce yang ditetapkan dalam
`DESIGN_DECISION_TRUSTED_SCRIPT_NONCE.md` **tetap berlaku tanpa perubahan**.

---

## 9. Implementation Consequence

Pada **Phase D5.2**, perubahan minimal yang akan dilakukan adalah menambahkan:

```text
report-uri /csp-report;
```

ke default CSP policy template di `xssguard/nonce.py`.

Secara spesifik, `_DEFAULT_POLICY_TEMPLATE` akan diperluas dari:

```text
default-src 'self'; script-src 'self' {script_src_tokens}; object-src 'none';
```

menjadi:

```text
default-src 'self'; script-src 'self' {script_src_tokens}; object-src 'none'; report-uri /csp-report;
```

**Perubahan ini TIDAK dilakukan pada Phase D5.1.** Phase D5.1 hanya
mendokumentasikan keputusan arsitektur.

---

## 10. Testing Consequence

Phase D5 setelah implementasi harus membuktikan alur end-to-end:

```text
CSP violation
      ↓
Browser generates report
      ↓
POST /csp-report
      ↓
parse_csp_report()
      ↓
valid report
      ↓
store.log_csp_report()
      ↓
HTTP 204
```

### Unit/Integration Test

Unit dan integration test yang sudah ada **harus tetap dipertahankan**:

- `tests/test_report.py` — validasi parser CSP report.
- `tests/test_flask_ext.py` — validasi endpoint `/csp-report` (valid, invalid,
  wrapped format, record separation).
- `tests/test_middleware.py` — validasi middleware (nonce, body preservation,
  detection logging).

Test baru (jika diperlukan) harus memverifikasi bahwa `report-uri /csp-report`
hadir pada CSP header setelah implementasi Phase D5.2.

### Browser E2E

Browser E2E digunakan untuk membuktikan browser-side reporting:

1. Inline script tanpa nonce valid melanggar CSP.
2. Browser menghasilkan CSP violation report.
3. Report dikirim ke `/csp-report`.
4. XSSGuard menerima dan mencatat report.
5. Endpoint mengembalikan HTTP 204.

---

## 11. Scope Exclusions

Phase D5 **TIDAK** mencakup:

- `report-to` directive.
- `Reporting-Endpoints` header.
- Modern Reporting API parser.
- Perubahan `CspReportData` dataclass.
- Custom report endpoint propagation (menghubungkan custom path dengan CSP header).
- Perubahan Trusted-Script Nonce (contract, primitive, atau mekanisme).
- Middleware redesign.
- HTML rewriting.
- Automatic nonce injection.
- IP blocking.
- Rate limiting.
- ML/AI detection.
- Network WAF.

---

## 12. Referensi

- `.agents/rules/rule.md` — aturan implementasi dan scope boundary.
- `IMPLEMENTATION_CONTRACT.md` §1.3, §1.4, §3.1, §3.3, §4 — kontrak modul.
- `PRD.md` FR-3 — CSP Violation Report Analysis.
- `DESIGN_DECISION_TRUSTED_SCRIPT_NONCE.md` — ADR Trusted-Script Nonce (FROZEN).
- `xssguard/report.py` — parser CSP violation report.
- `xssguard/nonce.py` — CSP nonce generator dan `build_csp_header()`.
- `xssguard/middleware.py` — WSGI middleware.
- `xssguard/flask_ext.py` — Flask extension dan `register_csp_report_route()`.

---

## 13. Sign-off

| Peran | Nama | Tanggal | Status |
|---|---|---|---|
| Peneliti | Malvin (NPM 301220020) | 21 Sept 2026 | Proposed |
| Pembimbing | | | Menunggu |
