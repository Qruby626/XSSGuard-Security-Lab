# Implementation Contract — XSSGuard

**Status:** Design Specification Alignment — Proposed
**Sumber:** Enam dokumen UML (`Rancangan_*_Revisi.docx`), `PRD.md`, `.agents/rules/rule.md`
**Fungsi dokumen ini:** menerjemahkan diagram dan requirement menjadi signature,
tipe data, dan invariant yang bisa langsung diimplementasikan dan diuji — tidak
ada lagi keputusan desain yang perlu diambil saat coding. Kalau ada kebutuhan
yang tidak tercakup di sini, itu tanda perlu kembali ke UML/PRD dulu, bukan
mengarang keputusan baru di tengah coding.

---

## 0. Tindakan Pembersihan Sebelum Mulai

Kode yang sudah ada (`xssguard/`) berisi beberapa elemen sisa dari rancangan awal
yang **tidak sesuai lagi** dengan UML, PRD, dan `rule.md` versi final. Sebelum
menambah fitur baru, bersihkan dulu:

| Berkas | Hapus | Alasan |
|---|---|---|
| `storage.py` | `blocked_ips()`, `block_ip()` dari `BaseStore` (Protocol) dan `MemoryStore`; atribut `_blocked_ips` | Hapus seluruh mekanisme keputusan/pencatatan daftar IP yang diblokir |
| `middleware.py` | Parameter `block_after_n_detections`, atribut `_detection_counts` dari `XSSGuardMiddleware` | Hapus seluruh mekanisme pemblokiran atau penghitungan deteksi per-IP |
| `flask_ext.py` | Parameter `block_after_n_detections` dari `XSSGuard.__init__()` | Hapus konfigurasi yang dapat memicu pemblokiran IP |

Setelah pembersihan ini, kontrak di bawah adalah bentuk akhir yang berlaku.

---

## 1. Kontrak Modul Core

Core **tidak boleh** `import flask`, `import sqlalchemy`, atau mengakses
objek request/response milik framework apa pun. Semua fungsi menerima dan
mengembalikan tipe data Python biasa.

### 1.1 `patterns.py`

```python
DEFAULT_XSS_PATTERNS: list[str]
```

Daftar pola regex (string, bukan `re.Pattern` yang sudah di-compile) yang
dipakai sebagai default oleh `detector.py`.

### 1.2 `detector.py`

```python
@dataclass(frozen=True)
class DetectionResult:
    status: str                      # "DETECTED" atau "SAFE"
    matched_rule: Optional[str]      # pola regex yang cocok; None kalau SAFE
    payload: str                     # nilai mentah yang diperiksa
    field: Optional[str] = None      # path field dalam data (mis. "comment.0.text")

def scan(payload: str, patterns: Sequence[str] = DEFAULT_XSS_PATTERNS) -> DetectionResult: ...

def scan_mapping(
    data: Mapping[str, Any],
    patterns: Sequence[str] = DEFAULT_XSS_PATTERNS,
) -> list[DetectionResult]: ...
```

**Invariant wajib:**
- `scan_mapping()` **hanya** mengembalikan elemen dengan `status == "DETECTED"`.
  Hasil `"SAFE"` disaring sebelum dikembalikan — pemanggil tidak pernah menerima
  list berisi status `"SAFE"`.
- `scan()` tidak melempar exception untuk payload kosong/`None`-safe — kembalikan
  `DetectionResult(status="SAFE", matched_rule=None, payload=payload)`.

### 1.3 `nonce.py`

```python
def generate_nonce(n_bytes: int = 16) -> str: ...

def build_csp_header(
    nonce: str,
    *,
    extra_script_src: str = "",
    policy_template: Optional[str] = None,
) -> str: ...
```

**Invariant wajib:**
- `generate_nonce()` memakai `secrets` (CSPRNG), bukan `random`.
- Nonce di-encode base64url-safe agar valid sebagai atribut HTML dan token CSP.
- `build_csp_header()` selalu menyisipkan `'nonce-{nonce}'` ke directive
  `script-src`.
- Policy default tetap menggunakan `default-src 'self'; script-src 'self'
  'nonce-{nonce}'; object-src 'none';`.
- Nilai nonce yang dipakai pada header CSP harus sama dengan nonce yang diekspos
  kepada host application untuk request yang sama.

### 1.4 `report.py`

```python
@dataclass(frozen=True)
class CspReportData:
    document_uri: Optional[str]
    violated_directive: Optional[str]
    blocked_uri: Optional[str]
    original_policy: Optional[str]
    raw: dict

def parse_csp_report(raw_body: bytes) -> Optional[CspReportData]: ...
```

**Invariant wajib:**
- Kembalikan `None` (bukan raise exception) kalau `raw_body` bukan JSON valid
  atau bukan bentuk objek/dict.
- Browser membungkus payload asli di bawah key `"csp-report"` — `parse_csp_report`
  harus menangani bentuk `{"csp-report": {...}}` maupun objek langsung.
- **Tidak ada validasi "required fields yang menolak."** Field yang hilang cukup
  bernilai `None` di `CspReportData`, bukan alasan mengembalikan `None` untuk
  keseluruhan hasil (itu hanya terjadi kalau JSON gagal diparse sama sekali).

---

## 2. Kontrak Modul Storage

### 2.1 Dataclass (`storage.py`)

```python
@dataclass
class DetectionRecord:
    payload: str                              # format "{field}={value}"
    status: str                               # selalu "DETECTED" pada praktiknya
    matched_rule: Optional[str]
    source: str                               # environ["PATH_INFO"]
    client_ip: Optional[str]                    # hanya untuk pencatatan/audit; bukan untuk blocking
    created_at: datetime = field(default_factory=_now)   # UTC

@dataclass
class CspReportRecord:
    document_uri: Optional[str]
    violated_directive: Optional[str]
    blocked_uri: Optional[str]
    client_ip: Optional[str]                    # hanya untuk pencatatan/audit; bukan untuk blocking
    created_at: datetime = field(default_factory=_now)   # UTC
```

Field `id` **tidak** ada di dataclass — itu murni tambahan skema tabel (lihat §5),
relevan hanya untuk implementasi `BaseStore` berbasis basis data sungguhan.

### 2.2 `BaseStore` (Protocol)

```python
class BaseStore(Protocol):
    def log_detection(self, record: DetectionRecord) -> None: ...
    def log_csp_report(self, record: CspReportRecord) -> None: ...
    def recent_detections(self, limit: int = 50) -> list[DetectionRecord]: ...
    def recent_csp_reports(self, limit: int = 50) -> list[CspReportRecord]: ...
```

Implementasi `BaseStore` mana pun (`MemoryStore` atau lainnya) **wajib** hanya
punya empat method ini. Menambah method baru ke Protocol ini mengharuskan revisi
Class Diagram dan Component Diagram (interface `IStorage`) di sesi yang sama.

### 2.3 `MemoryStore`

```python
class MemoryStore:
    def __init__(self) -> None:
        self._lock: Lock
        self._detections: list[DetectionRecord]
        self._csp_reports: list[CspReportRecord]
    # mengimplementasikan keempat method BaseStore di atas
```

**Invariant wajib:**
- Semua akses ke `_detections`/`_csp_reports` dilindungi `self._lock` (thread-safety
  untuk WSGI server multi-thread).
- `recent_detections()`/`recent_csp_reports()` mengembalikan entri **terbaru
  dulu** (urutan descending berdasarkan `created_at`), maksimal `limit` item.

---

## 3. Kontrak Modul Extension

### 3.1 `middleware.py`

```python
class XSSGuardMiddleware:
    def __init__(
        self,
        app: WSGIApplication,
        *,
        patterns: Optional[Sequence[str]] = None,
        store: Optional[BaseStore] = None,
    ) -> None: ...

    def __call__(self, environ: dict, start_response: StartResponse) -> Iterable[bytes]: ...
```

**Alur wajib di dalam `__call__()`** (urutan ini mengikat — lihat Sequence
Diagram 1):

1. Baca body request (kalau ada `CONTENT_LENGTH` > 0), replay kembali ke
   `environ["wsgi.input"]` supaya aplikasi host tetap bisa membacanya.
2. Panggil `detector.scan_mapping(data, self.patterns)`.
3. Untuk tiap `DetectionResult`, panggil `self.store.log_detection(DetectionRecord(
   payload=f"{result.field}={result.payload}", status=result.status,
   matched_rule=result.matched_rule, source=environ.get("PATH_INFO", ""),
   client_ip=environ.get("REMOTE_ADDR")))`.
4. Panggil `nonce.generate_nonce()` tepat satu kali untuk request tersebut.
5. Tetapkan `environ["xssguard.nonce"] = nonce` **sebelum**
   `self.app(...)` dipanggil, sehingga host application dapat menggunakan nonce
   tersebut saat menghasilkan response.
6. Panggil `self.app(environ, custom_start_response)` — `custom_start_response`
   adalah closure yang menyisipkan header CSP melalui
   `nonce.build_csp_header(nonce)` sebelum meneruskan ke `start_response` asli.
7. Teruskan `app_iter` dari host application **tanpa memodifikasi response body**.
   Middleware tidak membaca seluruh body untuk mencari tag `<script>`, tidak
   menyisipkan atribut `nonce`, dan tidak mengubah `Content-Length` hanya karena
   mekanisme nonce.
8. Untuk trusted inline script, aplikasi host bertanggung jawab menerapkan nonce
   secara eksplisit menggunakan nilai yang diekspos XSSGuard.

**Invariant wajib:**
- `environ["xssguard.nonce"]` tersedia bagi host application sebelum host
  application menghasilkan response.
- Nonce pada `environ["xssguard.nonce"]` sama persis dengan nonce pada directive
  `script-src` di CSP response request tersebut.
- Middleware tidak melakukan HTML rewriting atau automatic nonce injection.
- Response body diteruskan apa adanya, baik HTML maupun non-HTML.
- Tidak ada pemeriksaan, penghitungan, atau keputusan pemblokiran berdasarkan IP
  di dalam middleware. `client_ip` hanya dicatat sebagai informasi sumber request
  bila tersedia (lihat §0).

### 3.2 Kontrak Integrasi Trusted-Script Nonce

Primitive lintas framework yang wajib disediakan middleware adalah:

```python
environ["xssguard.nonce"]
```

Semantik:

1. Nilai dibuat sekali per request menggunakan `generate_nonce()`.
2. Nilai tersedia sebelum host application dipanggil.
3. Nilai hanya berasal dari XSSGuard, bukan dari input pengguna.
4. Nilai yang sama digunakan untuk `build_csp_header()`.
5. Middleware tidak menentukan apakah suatu script trusted atau untrusted.
6. Middleware tidak memberikan nonce secara otomatis kepada script pada response.
7. Keputusan untuk menempatkan nonce pada trusted inline script berada pada
   aplikasi host/developer.

Contoh raw WSGI:

```python
nonce = environ["xssguard.nonce"]
html = f'<script nonce="{nonce}">...</script>'
```

Contoh Flask:

```jinja2
<script nonce="{{ xssguard_nonce }}">
    console.log("Trusted script");
</script>
```

Primitive ini tidak disimpan ke `BaseStore` atau database.

### 3.3 `flask_ext.py`

```python
class XSSGuard:
    def __init__(
        self,
        app: Optional[Flask] = None,
        *,
        patterns: Optional[Sequence[str]] = None,
        store: Optional[BaseStore] = None,
    ) -> None: ...

    def init_app(self, app: Flask) -> None: ...

def register_csp_report_route(
    app: Flask,
    store: BaseStore,
    path: str = "/csp-report",
) -> None: ...
```

**Invariant wajib:**
- `init_app()` membungkus `app.wsgi_app` dengan `XSSGuardMiddleware(app.wsgi_app,
  patterns=self.patterns, store=self.store)`.
- `init_app()` mendaftarkan Flask `context_processor` yang menyediakan context
  variable `xssguard_nonce` kepada template.
- Nilai `xssguard_nonce` bersumber dari `request.environ["xssguard.nonce"]`.
- Integrasi nonce Flask **tidak** menggunakan hook `before_request` atau
  `after_request`.
- `store` default ke `MemoryStore()` baru kalau tidak diberikan pemanggil.
- Handler yang didaftarkan `register_csp_report_route()`:
  1. Panggil `report.parse_csp_report(request.get_data())`.
  2. Kalau hasilnya bukan `None`, panggil `store.log_csp_report(CspReportRecord(
     document_uri=..., violated_directive=..., blocked_uri=...,
     client_ip=request.remote_addr))`.
  3. Kalau hasilnya `None`, lewati tanpa mencatat apa pun.
  4. **Selalu** `return Response(status=204)` — di kedua kondisi di atas.
     **Tidak ada cabang status lain (termasuk 400) dalam kondisi apa pun.**

**Kontrak penggunaan template Flask:**
- Trusted inline script menggunakan `xssguard_nonce`, misalnya:
  `<script nonce="{{ xssguard_nonce }}">...</script>`.
- XSSGuard tidak melakukan rewriting otomatis terhadap tag `<script>` yang
  dihasilkan template.

---

## 4. Kontrak CspReportRoute

UML mendefinisikan komponen `CspReportRoute` dengan operasi:

```python
handler_csp_report()
```

Alur wajib:

```text
Browser
  ↓ POST /csp-report
CspReportRoute.handler_csp_report()
  ↓
report.parse_csp_report(raw_body)
  ↓
valid?
 ├─ Ya → store.log_csp_report(...)
 └─ Tidak → lewati tanpa dicatat
  ↓
204 No Content
```

Handler tidak membuat nonce, tidak memvalidasi nonce, dan tidak melakukan blocking.
Endpoint selalu mengembalikan `204 No Content`.

---

## 4. Kontrak Modul Dashboard

### 4.1 `dashboard.py`

```python
def create_dashboard_blueprint(
    store: BaseStore,
    name: str = "xssguard_dashboard",
) -> Blueprint: ...
```

**Invariant wajib (paling ketat di seluruh proyek):**
- Berkas ini **tidak boleh** `import` apa pun dari `detector.py`, `nonce.py`,
  atau `report.py`. Satu-satunya dependency selain Flask adalah `BaseStore`.
- Route di dalam blueprint memanggil `store.recent_detections()` dan
  `store.recent_csp_reports()`, lalu me-render satu halaman ringkasan
  (`render_template_string` atau setara).
- Kalau ada kebutuhan menampilkan data baru di dashboard yang berarti
  `dashboard.py` perlu mengimpor modul lain — itu tanda kebutuhan tersebut
  salah ditempatkan; datanya harus lewat `BaseStore` dulu (tambah field/record
  baru di §2), bukan lewat import langsung.

---

## 5. Kontrak Data — Skema Persistensi (dari ERD)

Berlaku untuk implementasi `BaseStore` berbasis basis data sungguhan (di luar
`MemoryStore`, yang cukup memakai list di memori):

**Tabel `detection_records`**

| Kolom | Tipe | Constraint |
|---|---|---|
| `id` | `BIGINT` | PK, AUTO_INCREMENT |
| `payload` | `TEXT` | NOT NULL |
| `status` | `VARCHAR(20)` | NOT NULL |
| `matched_rule` | `VARCHAR(255)` | NULL |
| `source` | `VARCHAR(255)` | NOT NULL |
| `client_ip` | `VARCHAR(45)` | NULL |
| `created_at` | `DATETIME` | NOT NULL |

**Tabel `csp_report_records`**

| Kolom | Tipe | Constraint |
|---|---|---|
| `id` | `BIGINT` | PK, AUTO_INCREMENT |
| `document_uri` | `VARCHAR(500)` | NULL |
| `violated_directive` | `VARCHAR(100)` | NULL |
| `blocked_uri` | `VARCHAR(500)` | NULL |
| `client_ip` | `VARCHAR(45)` | NULL |
| `created_at` | `DATETIME` | NOT NULL |

**Tidak ada foreign key antara kedua tabel ini dan tidak ada tabel/struktur
khusus untuk IP yang diblokir.** `client_ip` pada kedua record hanya merupakan
data audit/sumber request, bukan mekanisme pemblokiran. Jika implementasi masa
depan menambahkan mekanisme blocking, itu bukan perubahan coding biasa dan harus
didahului revisi scope/PRD serta UML yang relevan.

---

## 6. Invariant Lintas-Modul (tidak boleh dilanggar oleh perubahan apa pun)

1. `detector.py`, `nonce.py`, `report.py` tidak saling mengimpor, dan tidak
   mengimpor `storage.py`/`middleware.py`/`flask_ext.py`/`dashboard.py`.
2. `dashboard.py` hanya mengimpor `storage.py` (lihat §4).
3. Satu-satunya milik `XSSGuardMiddleware`/`XSSGuard` yang boleh menyentuh
   `detector`/`nonce`/`report`/`BaseStore` sekaligus.
4. Endpoint CSP report selalu `204`, tidak pernah `400`.
5. `scan_mapping()` tidak pernah mengembalikan hasil berstatus `"SAFE"`.
6. Tidak ada method/atribut yang berkaitan dengan pemblokiran IP di `BaseStore`,
   `MemoryStore`, `XSSGuardMiddleware`, maupun `XSSGuard`.
7. Tidak ada dependency wajib baru di `pyproject.toml` untuk modul di luar
   `flask_ext.py`/`dashboard.py`.
8. `XSSGuardMiddleware` mengekspos nonce melalui `environ["xssguard.nonce"]`
   sebelum host application dipanggil, dan tidak melakukan automatic HTML
   nonce injection.

---

## 7. Definition of Done (dipetakan ke PRD §5)

| Requirement PRD | Kontrak yang harus dipenuhi | Cara verifikasi |
|---|---|---|
| FR-1 Rule-Based Detection | §1.2 — `scan()`/`scan_mapping()` | `tests/test_detector.py`; DR ≥ 80% pada dataset 30 payload |
| FR-2 CSP Nonce Dinamis | §1.3, §3.1, §3.2 | Nonce per-request tersedia via `environ["xssguard.nonce"]`, cocok dengan `script-src`, trusted script menerapkannya secara eksplisit, dan body tidak diubah middleware |
| FR-3 CSP Violation Report | §1.4, §3.3 | Parser/endpoint diuji; endpoint selalu 204; functional browser E2E dapat membuktikan violation dan pengiriman report |
| FR-4 Portabilitas | §3.1 (WSGI murni) | `examples/flask_demo.py` dan `examples/raw_wsgi_demo.py` jalan tanpa modifikasi kode inti |
| FR-5 Dashboard | §4 | `dashboard.py` tidak mengimpor Core; halaman menampilkan data dari `BaseStore` |

---

## 8. Referensi

- `PRD.md` — tujuan, non-goals, kriteria penerimaan
- `.agents/rules/rule.md` — aturan proses dan larangan
- `Rancangan_Class_Diagram_XSSGuard_Revisi.docx`
- `Rancangan_Component_Diagram_XSSGuard_revisi.docx`
- `Rancangan_Sequence_Diagram_XSSGuard_Revisi.docx`
- `Rancangan_ERD_XSSGuard_Revisi.docx`
- `Rancangan_UseCase_Diagram_XSSGuard_revisi.docx`
- `Rancangan_Activity_Diagram_XSSGuard_Revisi.docx`
