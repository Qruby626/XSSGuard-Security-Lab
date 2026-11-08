# XSSGuard

XSSGuard adalah package Python framework-agnostic untuk mitigasi Stored XSS melalui:

1. **Rule-Based XSS Detection**.
2. **Trusted-Script Nonce**.
3. **CSP Violation Report**.

Desain mengikuti UML final dan menggunakan WSGI middleware sebagai titik integrasi.

## Requirements

- Python >= 3.9
- Tidak ada dependensi wajib untuk core library

### Optional Dependencies

| Extra | Package | Keterangan |
|-------|---------|------------|
| `flask` | Flask >= 2.0 | Diperlukan untuk `XSSGuard` Flask extension dan Dashboard |
| `dev` | pytest >= 7.0 | Diperlukan untuk menjalankan pengujian |

## Installation

### Dari source (development)

```bash
git clone https://github.com/Qruby626/XSSGuard-Security-Lab.git
cd XSSGuard-Security-Lab
pip install -e .
```

### Dengan dukungan Flask

```bash
pip install -e ".[flask]"
```

### Dengan dependensi pengembangan

```bash
pip install -e ".[flask,dev]"
```

## 1. Arsitektur

```text
xssguard/
├── patterns.py       # DEFAULT_XSS_PATTERNS
├── detector.py       # scan(), scan_mapping()
├── nonce.py          # generate_nonce(), build_csp_header()
├── report.py         # parse_csp_report()
├── storage.py        # BaseStore, MemoryStore, Records
├── middleware.py     # XSSGuardMiddleware
├── flask_ext.py      # XSSGuard, Flask integration
└── dashboard.py      # create_dashboard_blueprint()
```

## 2. Trusted-Script Nonce

XSSGuard **tidak** melakukan automatic nonce injection.

Alur runtime:

```text
Request
  ↓
XSSGuardMiddleware
  ↓
generate_nonce()
  ↓
environ["xssguard.nonce"]
  ↓
Host Application
  ↓
Trusted inline script memakai nonce
  ↓
Response body
  ↓
build_csp_header(nonce)
  ↓
Response + CSP header
```

Nonce dibuat satu kali per-request menggunakan CSPRNG. Nilai yang sama digunakan
oleh host dan directive `script-src`.

### Flask

`XSSGuard` menyediakan context variable `xssguard_nonce` yang bersumber dari
`request.environ["xssguard.nonce"]`.

```html
<script nonce="{{ xssguard_nonce }}">
    console.log("Trusted script");
</script>
```

### Raw WSGI

```python
nonce = environ["xssguard.nonce"]
html = f'<script nonce="{nonce}">...</script>'
```

Keputusan trust berada pada Aplikasi Host/developer. Middleware tidak mencari,
menilai, atau memodifikasi tag `<script>` pada response.

## 3. Rule-Based Detection

Request dipindai menggunakan pola regex:

```python
results = scan_mapping(data)
```

Hanya hasil `DETECTED` yang dicatat ke Storage. Hasil `SAFE` tidak menjadi log.

## 4. CSP Violation Report

Endpoint:

```text
POST /csp-report
```

Alur:

```text
Browser
  ↓
CSP violation
  ↓
POST /csp-report
  ↓
CspReportRoute
  ↓
parse_csp_report()
  ↓
JSON valid?
 ├── Ya → log_csp_report()
 └── Tidak → lewati
  ↓
204 No Content
```

Endpoint selalu mengembalikan `204 No Content`. Report invalid tidak dicatat.

## 5. Storage

`BaseStore` menyediakan tepat empat operasi:

```python
log_detection()
log_csp_report()
recent_detections()
recent_csp_reports()
```

Record:

```text
DetectionRecord
├── payload
├── status
├── matched_rule
├── source
├── client_ip
└── created_at

CspReportRecord
├── document_uri
├── violated_directive
├── blocked_uri
├── client_ip
└── created_at
```

Nonce tidak dipersistenkan. Tidak ada relationship langsung antara dua record.

## 6. Flask Quick Start

```python
from flask import Flask, render_template
from xssguard.flask_ext import XSSGuard
from xssguard.storage import MemoryStore
from xssguard.dashboard import create_dashboard_blueprint

app = Flask(__name__)
store = MemoryStore()

guard = XSSGuard(app=app, store=store)

app.register_blueprint(
    create_dashboard_blueprint(store),
    url_prefix="/xssguard",
)

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
```

Template host:

```html
<!doctype html>
<html>
<body>
    <h1>XSSGuard</h1>
    <script nonce="{{ xssguard_nonce }}">
        console.log("Trusted inline script");
    </script>
</body>
</html>
```

## 7. Raw WSGI Quick Start

```python
from xssguard.middleware import XSSGuardMiddleware
from xssguard.storage import MemoryStore

def host_app(environ, start_response):
    nonce = environ["xssguard.nonce"]
    body = (
        f'<script nonce="{nonce}">'
        'console.log("Trusted script");'
        '</script>'
    ).encode()

    start_response(
        "200 OK",
        [("Content-Type", "text/html; charset=utf-8")],
    )
    return [body]

app = XSSGuardMiddleware(host_app, store=MemoryStore())
```

## 8. Dashboard

Dashboard membaca data melalui Storage:

```python
store.recent_detections()
store.recent_csp_reports()
```

Dashboard tidak mengimpor detector, nonce, report, atau middleware.

## 9. Testing

```powershell
python -m pytest -q
```

Pengujian utama:

- detection cocok → `DETECTED`;
- detection aman → `SAFE`;
- nonce dibuat per-request;
- nonce tersedia sebelum host dipanggil;
- nonce CSP sama dengan nonce host;
- trusted script menggunakan nonce;
- body tidak diubah middleware;
- CSP report valid disimpan;
- CSP report invalid dilewati;
- endpoint selalu 204.

Browser E2E minimal menguji trusted script dengan nonce benar, script tanpa nonce,
script dengan nonce salah, stored payload tanpa nonce, dan pengiriman CSP report.

## 10. Dataset Penelitian

| Kategori | Jumlah |
|---|---:|
| Inline Script Injection | 10 |
| Event Handler Injection | 10 |
| Cookie Access | 5 |
| DOM Manipulation | 5 |
| **Total** | **30** |

Detection Rate:

```text
DR = Submission Terdeteksi / Total Submission Diuji × 100%
```

Target penelitian: ≥ 80%.

## 11. Scope Boundaries

XSSGuard tidak menyediakan:

- IP blocking;
- rate limiting berbasis IP;
- ML/AI detection;
- network-level WAF;
- HTML sanitizer;
- automatic nonce injection;
- penyimpanan nonce.

Middleware mendeteksi dan mencatat request, kemudian meneruskannya. Enforcement
CSP terjadi pada browser.

## 12. Dokumen Desain

Dokumen yang harus tetap sinkron:

```text
rule.md
IMPLEMENTATION_CONTRACT.md
PRD.md
README.md
DESIGN_DECISION_FINAL — TRUSTED-SCRIPT NONCE

UML:
- Class Diagram
- Component Diagram
- Sequence Diagram
- Activity Diagram
- ERD
- Use Case Diagram
```

### Final rule

> XSSGuard menghasilkan satu nonce CSPRNG per-request, mengekspos nonce melalui
> `environ["xssguard.nonce"]` sebelum aplikasi host dipanggil, dan menggunakan
> nonce yang sama pada CSP `script-src`. Aplikasi host menerapkan nonce secara
> eksplisit hanya pada trusted inline script. Middleware tidak melakukan HTML
> rewriting atau automatic nonce injection.
