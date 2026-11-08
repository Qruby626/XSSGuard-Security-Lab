---
trigger: always_on
---

# XSSGuard — Engineering Rules

## 1. Scope

XSSGuard adalah package Python framework-agnostic untuk tiga mekanisme inti:

1. Rule-Based XSS Detection pada request masuk.
2. Trusted-Script Nonce dengan nonce CSP dinamis per-request.
3. CSP Violation Report ingestion dan pencatatan.

Arsitektur wajib mengikuti UML final: Core (`detector`, `nonce`, `report`),
Storage (`BaseStore`, `MemoryStore`), Extension (`XSSGuardMiddleware`,
`XSSGuard`, `CspReportRoute`), Dashboard, dan Aplikasi Host.

Jangan menambahkan mekanisme keamanan baru tanpa revisi PRD dan UML terlebih dahulu.

## 2. Sumber Kebenaran

Urutan acuan desain:

1. UML final: Class, Component, Sequence, ERD, Use Case, Activity.
2. `DESIGN_DECISION_FINAL — TRUSTED-SCRIPT NONCE`.
3. `PRD.md`.
4. `IMPLEMENTATION_CONTRACT.md`.
5. File ini dan `README.md`.

Jika terdapat konflik, sinkronkan dokumen desain terlebih dahulu; jangan membuat
keputusan desain baru saat coding.

## 3. Scope Boundary

### Wajib

- Rule-Based Detection.
- Trusted-Script Nonce.
- CSP Violation Report.
- Storage abstraction.
- Monitoring Dashboard.

### Dilarang

- IP blocking atau rate limiting berbasis IP.
- Machine learning/AI detector.
- Network-level WAF.
- Automatic HTML rewriting untuk nonce.
- Automatic nonce injection ke semua `<script>`.
- Penyimpanan nonce ke database.
- Cookie untuk membawa nonce.
- Penentuan trust berdasarkan isi HTML final.

`client_ip` hanya boleh dicatat sebagai informasi audit.

## 4. Rule-Based Detection

Detection berada pada `patterns.py` dan `detector.py`. Core detection tidak boleh
mengimpor Flask, SQLAlchemy, Storage, Middleware, atau Dashboard.

Kontrak utama:

```python
@dataclass(frozen=True)
class DetectionResult:
    status: str
    matched_rule: Optional[str]
    payload: str
    field: Optional[str] = None

def scan(payload: str, patterns=DEFAULT_XSS_PATTERNS) -> DetectionResult: ...
def scan_mapping(data, patterns=DEFAULT_XSS_PATTERNS) -> list[DetectionResult]: ...
```

`scan_mapping()` hanya mengembalikan hasil `DETECTED`. Hasil `SAFE` tidak dicatat
sebagai noise log.

Dataset penelitian terdiri dari 30 payload: Inline Script Injection (10), Event
Handler Injection (10), Cookie Access (5), dan DOM Manipulation (5).

## 5. Trusted-Script Nonce

### 5.1 Prinsip

```text
HTTP Request
    ↓
XSSGuardMiddleware
    ↓
scan_mapping() / detection logging
    ↓
generate_nonce()
    ↓
environ["xssguard.nonce"]
    ↓
Aplikasi Host
    ↓
trusted inline script menggunakan nonce
    ↓
response body
    ↓
build_csp_header(nonce)
    ↓
CSP header + response body
```

### 5.2 Invariant nonce

- Tepat satu nonce untuk satu request.
- Gunakan CSPRNG (`secrets`).
- Nonce dibuat sebelum host application dipanggil.
- Primitive resmi: `environ["xssguard.nonce"]`.
- Nilai yang sama digunakan pada `script-src` CSP.
- Nonce bukan input pengguna.
- Nonce tidak disimpan di Storage/database.
- Nonce tidak dikirim sebagai cookie.
- Middleware tidak membaca/menulis ulang response HTML.

### 5.3 Trust boundary

Keputusan apakah script trusted berada pada Aplikasi Host/developer. XSSGuard
hanya menyediakan nonce.

Flask:

```jinja2
<script nonce="{{ xssguard_nonce }}">
    console.log("Trusted script");
</script>
```

Raw WSGI:

```python
nonce = environ["xssguard.nonce"]
html = f'<script nonce="{nonce}">...</script>'
```

Jangan menggunakan `inject_nonce_into_scripts()` atau mekanisme sejenis.

## 6. Middleware

`XSSGuardMiddleware.__call__()` wajib mengikuti urutan:

1. Baca request body bila tersedia.
2. Replay `wsgi.input` agar host tetap dapat membacanya.
3. Jalankan `detector.scan_mapping()`.
4. Catat setiap `DETECTED` ke Storage.
5. Panggil `nonce.generate_nonce()` tepat satu kali.
6. Set `environ["xssguard.nonce"]`.
7. Panggil host application melalui `custom_start_response`.
8. `custom_start_response` menambahkan CSP menggunakan nonce yang sama.
9. Teruskan `app_iter` tanpa memodifikasi response body.

Tidak boleh ada HTML rewriting setelah host mengembalikan response.

## 7. CSP Header

`build_csp_header(nonce)` wajib memasukkan `'nonce-{nonce}'` ke `script-src`.

Default policy:

```text
default-src 'self';
script-src 'self' 'nonce-{nonce}';
object-src 'none';
base-uri 'self';
```

## 8. CSP Violation Report

`CspReportRoute.handler_csp_report()` wajib:

1. menerima `POST /csp-report`;
2. membaca raw body;
3. memanggil `report.parse_csp_report(raw_body)`;
4. jika hasil bukan `None`, memanggil `store.log_csp_report(...)`;
5. jika hasil `None`, melewati tanpa mencatat;
6. selalu mengembalikan `204 No Content`.

Parser menangani `{"csp-report": {...}}` dan object JSON langsung. JSON valid
dengan field opsional yang hilang tetap dapat diparsing dengan nilai `None`.

Tidak boleh ada cabang `400 Bad Request` karena parsing report gagal.

## 9. Storage dan ERD

`BaseStore` hanya menyediakan:

```text
log_detection()
log_csp_report()
recent_detections()
recent_csp_reports()
```

Entity persistensi:

```text
DetectionRecord
- id
- payload
- status
- matched_rule
- source
- client_ip
- created_at

CspReportRecord
- id
- document_uri
- violated_directive
- blocked_uri
- client_ip
- created_at
```

Tidak ada relationship langsung antara kedua entity. Tidak ada entity/tabel/
atribut nonce dan tidak ada tabel IP blocking.

## 10. Dashboard

Dashboard hanya menggunakan `IStorage`:

```text
Admin
  ↓
Dashboard
  ↓
recent_detections()
recent_csp_reports()
  ↓
render dashboard
```

`dashboard.py` tidak boleh mengimpor `detector.py`, `nonce.py`, `report.py`, atau
`XSSGuardMiddleware`.

## 11. Component Alignment

```text
detector → IDetector
nonce → INonce
report → IReport
Storage → IStorage

XSSGuardMiddleware → IDetector, INonce, IStorage
CspReportRoute → IReport, IStorage
dashboard → IStorage

XSSGuardMiddleware → provides IHostIntegration
Aplikasi Host → uses IHostIntegration

XSSGuard → XSSGuardMiddleware
XSSGuard → CspReportRoute
```

Jangan menambah dependency silang yang tidak ada pada Component Diagram.

## 12. Activity/Sequence Alignment

Request:

```text
request → scan → log detection jika DETECTED → generate nonce
→ set environ → call host → host render trusted script
→ receive response → build CSP header → return response
```

CSP report:

```text
Browser → POST /csp-report → parse → valid?
→ Ya: log_csp_report() / Tidak: lewati → 204
```

Dashboard:

```text
Admin → /xssguard/ → recent_detections()
→ recent_csp_reports() → render dashboard
```

## 13. Definition of Done

Perubahan hanya dianggap selesai jika:

- sesuai `IMPLEMENTATION_CONTRACT.md`;
- PRD dan seluruh UML tetap sinkron;
- nonce tersedia sebelum host dipanggil;
- nonce CSP dan nonce host identik;
- middleware tidak mengubah response body;
- CSP report selalu berakhir `204`;
- ERD tidak menyimpan nonce;
- dashboard hanya bergantung pada Storage;
- tidak ada IP blocking;
- pengujian relevan lulus.
