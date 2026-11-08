# DESIGN DECISION FINAL — TRUSTED-SCRIPT NONCE XSSGuard v1.0

| Field | Nilai |
|---|---|
| Versi | 1.0 |
| Tanggal | 14 September 2026 |
| Menggantikan | `IMPLEMENTATION_CONTRACT.md` §3.1 langkah 6 (auto-inject nonce ke semua `<script>`) |
| Pemicu | Bukti E2E browser: script hasil injeksi XSS mendapat nonce valid dan tereksekusi meski CSP aktif |

---

## 1. Ringkasan Keputusan

XSSGuard mengubah model integrasi CSP nonce dari **automatic nonce injection** — yaitu memberi nonce kepada semua `<script>` yang belum memiliki nonce — menjadi **Trusted-Script Nonce**.

Pada desain baru, XSSGuard menghasilkan nonce CSPRNG per-request dan mengekspos nonce tersebut kepada aplikasi host melalui API integrasi resmi. Aplikasi host bertanggung jawab menerapkan nonce tersebut **hanya pada script yang dipercaya**.

Middleware **berhenti membaca dan menulis ulang body HTML**. Middleware hanya:

1. Membuat nonce per-request.
2. Mengekspos nonce ke aplikasi host **sebelum** host application dipanggil.
3. Menyisipkan nonce ke header `Content-Security-Policy`.
4. Meneruskan response body tanpa modifikasi.

Keputusan ini diambil karena pengujian browser E2E membuktikan bahwa automatic nonce injection dapat memberikan nonce valid kepada script attacker sehingga CSP tidak lagi menjadi enforcement boundary yang efektif.

---

## 2. Masalah yang Melatarbelakangi

```text
Attacker payload → tersimpan di database (Stored XSS)
        ↓
Dirender ulang di response HTML sebagai <script>
        ↓
Middleware lama memindai SEMUA <script> di body
        ↓
Attacker script ikut mendapat nonce valid
        ↓
CSP menerima nonce → browser mengeksekusi payload
```

Akar masalah: middleware tidak dapat mengetahui asal-usul atau tingkat kepercayaan sebuah `<script>` hanya dari HTML final. Karena itu, keputusan trust tidak boleh dibuat dengan cara otomatis memberikan nonce kepada seluruh elemen `<script>`.

Kepercayaan harus berasal dari sumber yang lebih dipercaya daripada string HTML, yaitu **kode/template aplikasi host yang dikendalikan developer**.

---

## 3. Trust Boundary Baru

```text
TRUSTED                                      UNTRUSTED
────────────────────────────────────────────────────────────
Developer aplikasi host                      User input
Kode/template aplikasi host                  Request HTTP
Nonce yang diekspos XSSGuard                  Data tersimpan yang berasal dari user
dan digunakan oleh aplikasi host             Attacker payload
```

Aturan utama:

> XSSGuard menghasilkan nonce per-request menggunakan CSPRNG dan mengekspos nonce tersebut kepada aplikasi host melalui API integrasi resmi. Aplikasi host menerapkan nonce tersebut secara eksplisit hanya pada script yang dipercaya.

Nonce bersifat unik per-request dan tidak berasal dari user input. Script yang diinjeksi attacker tidak memperoleh nonce melalui mekanisme resmi XSSGuard.

Kepercayaan ditentukan secara **struktural berdasarkan sumber kode/template yang dipercaya**, bukan berdasarkan penilaian apakah isi sebuah `<script>` terlihat aman.

> **Catatan penting:** XSSGuard tidak dapat menjamin bahwa nonce tidak pernah bocor jika aplikasi host memiliki vulnerability lain yang mengekspos nonce. Klaim keamanan dibatasi pada mekanisme normal integrasi XSSGuard.

---

## 4. Primitive Nonce API dan Integrasi Framework

### 4.1 Primitive API — WSGI

`xssguard/nonce.py` **tidak berubah secara konseptual**:

- `generate_nonce()` tetap menghasilkan nonce CSPRNG.
- `build_csp_header()` tetap menghasilkan CSP yang memuat nonce pada `script-src`.

`xssguard/middleware.py` berubah menjadi:

1. Membuat satu nonce untuk setiap request.
2. Sebelum memanggil host application, menetapkan:

```python
environ["xssguard.nonce"] = nonce
```

3. Menggunakan nonce yang sama untuk membangun CSP header.
4. Tidak memodifikasi response body.

`environ["xssguard.nonce"]` menjadi **primitive API resmi lintas framework**.

Aturan:

- satu nonce untuk satu request;
- nonce dibuat sebelum `self.app(environ, start_response)`;
- nonce tidak disimpan ke Storage;
- nonce tidak berasal dari user input;
- nonce tidak dikirim sebagai cookie;
- middleware tidak melakukan HTML rewriting.

### 4.2 Flask API

Flask extension menyediakan nonce kepada template melalui template context variable:

```text
xssguard_nonce
```

Sumber nilainya tetap:

```python
request.environ["xssguard.nonce"]
```

Mekanisme integrasi yang direkomendasikan adalah Flask `context_processor`, misalnya:

```python
@app.context_processor
def inject_xssguard_nonce():
    return {
        "xssguard_nonce": flask.request.environ.get("xssguard.nonce")
    }
```

Template trusted kemudian dapat menggunakan:

```html
<script nonce="{{ xssguard_nonce }}">
    console.log("Trusted script");
</script>
```

**Batas keputusan:** `context_processor` merupakan mekanisme integrasi Flask yang disepakati pada level desain. Implementasi detail dan nama operation/kelas yang diperlukan tetap harus dituangkan secara konsisten ke `IMPLEMENTATION_CONTRACT.md` dan UML sebelum coding.

`before_request` dan `after_request` **tidak digunakan** untuk mekanisme ini.

### 4.3 Raw WSGI

Aplikasi WSGI mentah mengambil nonce langsung dari:

```python
nonce = environ["xssguard.nonce"]
```

dan menggunakan nilai tersebut ketika membangun script yang dipercaya.

Dengan demikian, primitive API tetap satu:

```text
environ["xssguard.nonce"]
```

sedangkan cara konsumsi dapat berbeda sesuai framework.

---

## 5. CSP Policy — Keputusan Final

XSSGuard mempertahankan policy default:

```text
default-src 'self'; script-src 'self' 'nonce-{nonce}'; object-src 'none';
```

Keputusan ini berarti:

1. **Inline script yang tidak memiliki nonce yang sesuai** tidak diizinkan oleh `script-src`.
2. Inline script trusted dapat dijalankan jika menggunakan nonce yang sama dengan nonce pada CSP response.
3. `'self'` tetap mengizinkan script eksternal yang berasal dari origin aplikasi sesuai kebijakan CSP.
4. Middleware tidak memodifikasi body HTML untuk menambahkan nonce.

Karena `'self'` tetap ada, klaim keamanan **tidak** boleh ditulis sebagai:

> “Semua script hanya dapat dieksekusi jika memiliki nonce.”

Klaim yang digunakan:

> **“Script inline yang tidak memiliki nonce yang sesuai akan ditolak oleh kebijakan CSP, sedangkan script dari source yang secara eksplisit diizinkan oleh policy, seperti `'self'`, tetap dapat dieksekusi sesuai policy.”**

Nonce pada trusted inline script harus berasal dari nonce request yang sama:

```text
CSP Header:
script-src 'self' 'nonce-ABC'

Trusted:
<script nonce="ABC">...</script>

Attacker:
<script>alert(1)</script>
```

Hasil yang diharapkan:

```text
Trusted script  → ALLOW
Attacker script → BLOCK
```

---

## 6. Alur Flask

```text
Request masuk
     ↓
XSSGuardMiddleware.__call__()
     ↓
generate_nonce()
     ↓
environ["xssguard.nonce"] = nonce
     ↓
self.app(environ, start_response)
     ↓
Flask app berjalan
     ↓
context_processor membaca request.environ["xssguard.nonce"]
     ↓
Template menerima xssguard_nonce
     ↓
Trusted template:
<script nonce="{{ xssguard_nonce }}">...</script>
     ↓
Flask menghasilkan HTML yang sudah memiliki nonce
     ↓
Middleware TIDAK menyentuh body
     ↓
Middleware menambahkan CSP header dengan nonce yang sama
     ↓
Browser menerapkan CSP
```

Dengan policy:

```text
script-src 'self' 'nonce-{nonce}'
```

maka:

```text
trusted inline script + nonce cocok → ALLOW
inline script tanpa nonce            → BLOCK
inline script dengan nonce salah     → BLOCK
same-origin external script          → ALLOW sesuai policy
```

---

## 7. Alur Raw WSGI

```text
Request masuk
     ↓
XSSGuardMiddleware.__call__()
     ↓
generate_nonce()
     ↓
environ["xssguard.nonce"] = nonce
     ↓
self.app(environ, start_response)
     ↓
App WSGI mentah mengambil:
nonce = environ["xssguard.nonce"]
     ↓
App membuat trusted script:
<script nonce="{nonce}">...</script>
     ↓
App mengembalikan body
     ↓
Middleware TIDAK menyentuh body
     ↓
Middleware menambahkan CSP header dengan nonce yang sama
     ↓
Browser menerapkan CSP
```

Baik Flask maupun raw WSGI menggunakan satu sumber kebenaran:

```text
environ["xssguard.nonce"]
```

---

## 8. Penanganan Stored XSS

Stored XSS mempunyai karakteristik bahwa payload dapat diterima dan disimpan pada satu request, kemudian dirender pada response request lain.

```text
Hari 1:
POST payload attacker
        ↓
payload tersimpan

Hari 2:
GET /comments
        ↓
payload dirender kembali
        ↓
<script>alert()</script>
        ↓
script berasal dari data, bukan trusted template
        ↓
tidak memiliki nonce request yang sah
        ↓
CSP menolak eksekusi inline script
        ↓
browser dapat menghasilkan CSP Violation Report
```

Trusted-Script Nonce **tidak melakukan deteksi ulang terhadap response HTML**. Mekanisme ini juga tidak menggantikan output encoding, sanitization, atau secure templating.

Pembagian tanggung jawab tetap:

```text
Rule-Based Detection
        ↓
deteksi dan pencatatan indikasi pada input/request

CSP Trusted-Script Nonce
        ↓
browser-side enforcement terhadap script inline
        ↓
yang tidak memiliki nonce sesuai policy
```

Dengan demikian, Rule-Based Detection dan CSP Nonce merupakan dua mekanisme independen dengan tanggung jawab berbeda.

> **Batas klaim:** Trusted-Script Nonce tidak berarti seluruh bentuk Stored XSS atau seluruh jenis XSS otomatis terselesaikan. Efektivitas CSP bergantung pada kebijakan CSP dan cara aplikasi host merender konten.

---

## 9. Evaluasi CSP dan Blocking

### 9.1 Functional Browser E2E — Wajib

Evaluasi CSP dilakukan menggunakan browser yang diinstrumentasi, misalnya Selenium atau Playwright.

Minimal skenario:

| Skenario | Expected |
|---|---|
| Trusted inline script + nonce valid | Execute |
| Inline script tanpa nonce | Block |
| Inline script dengan nonce salah | Block |
| Stored XSS yang dirender sebagai inline script tanpa nonce | Block |
| CSP violation terjadi | Browser dapat menghasilkan report |
| `/csp-report` menerima report valid | HTTP 204 dan record tercatat |

Indikator utama blocking adalah **payload tidak berhasil mengeksekusi JavaScript pada browser**.

CSP Violation Report digunakan sebagai **bukti pendukung bahwa browser mendeteksi pelanggaran policy**, bukan sebagai satu-satunya bukti bahwa JavaScript pasti tidak dieksekusi.

### 9.2 Blocking Rate (BR) — Metrik Tambahan

BR **bukan acceptance criterion utama**.

Apabila pembimbing atau metodologi penelitian membutuhkan metrik kuantitatif tambahan, BR dapat dihitung dari hasil browser E2E:

```text
BR =
jumlah payload yang terbukti tidak mengeksekusi JavaScript
--------------------------------------------------------- × 100%
                  total payload diuji
```

Metodologi BR harus mendefinisikan secara eksplisit:

- browser/environment yang digunakan;
- payload yang diuji;
- kondisi eksekusi;
- indikator keberhasilan/gagal eksekusi;
- cara mengisolasi trusted script aplikasi dari payload attacker.

CSP Violation Report dapat dicatat sebagai evidence pendukung.

Target BR tidak ditetapkan sebagai acceptance criterion dalam Design Decision ini sebelum metodologi E2E disepakati.

---

## 10. Dampak terhadap Dokumen, UML, dan Kode Proyek

| Artefak | Keputusan |
|---|---|
| `IMPLEMENTATION_CONTRACT.md` | **Revisi wajib**: ganti auto-injection dengan primitive `environ["xssguard.nonce"]`, non-modifikasi body, dan kontrak integrasi Flask |
| `PRD.md` §1 | **Revisi wajib**: hapus klaim bahwa nonce dapat diterapkan tanpa perubahan template host |
| `PRD.md` FR-2 | **Revisi wajib**: definisikan trusted-script nonce dan tanggung jawab aplikasi host |
| `PRD.md` §8 | **Revisi wajib**: evaluasi CSP melalui functional browser E2E; BR tidak menjadi acceptance criterion utama |
| Use Case Diagram | **Review**; pertahankan jika tidak ada perubahan aktor/use case yang substantif |
| Sequence Diagram | **Revisi wajib**: tambah ekspos nonce sebelum host app dipanggil dan hapus langkah HTML rewriting |
| Activity Diagram | **Revisi wajib**: hapus aktivitas auto-injection dan ganti dengan ekspos nonce + konsumsi oleh host |
| Component Diagram | **Review/Revisi**: modelkan dependency integrasi nonce antara middleware dan host application secara konsisten |
| Class Diagram | **Review/Revisi**: representasikan kontrak integrasi nonce yang benar; tidak wajib menambah `get_nonce(environ)` jika primitive `environ` sudah cukup |
| ERD | **Tetap** kecuali ditemukan dampak lain; nonce tidak disimpan ke database |
| `xssguard/middleware.py` | **Revisi**: hapus HTML rewriting dan expose nonce |
| `xssguard/flask_ext.py` | **Revisi**: integrasi `xssguard_nonce` |
| `xssguard/nonce.py` | **Tetap** secara mekanisme inti |
| `xssguard/report.py` | **Tetap** |
| `xssguard/storage.py` | **Tetap** |
| `examples/flask_demo.py` | **Revisi** agar trusted script memakai `xssguard_nonce` |
| `examples/raw_wsgi_demo.py` | **Revisi** agar trusted script memakai `environ["xssguard.nonce"]` |
| `tests/test_middleware.py` | **Revisi**: hapus asumsi auto-injection dan uji nonce exposure/body preservation |
| `tests/test_flask_ext.py` | **Revisi**: uji `xssguard_nonce` pada template |
| Browser E2E tests | **Tambahan** untuk membuktikan enforcement CSP |
| Naskah skripsi Bab I–III | **Review**: hapus klaim “otomatis tanpa edit template” dan sesuaikan batas klaim keamanan |

Perubahan dokumen dan UML dilakukan **sebelum coding**, karena perubahan ini mengubah kontrak dan alur integrasi CSP.

---

## 11. Yang Tidak Berubah

- Tiga mekanisme inti XSSGuard tetap:
  1. Rule-Based Detection
  2. CSP Nonce
  3. CSP Violation Report
- Rule-Based Detection tetap bertanggung jawab terhadap deteksi input/request dan pencatatan indikasi.
- `detector.py` dan `scan_mapping()` tidak berubah karena keputusan Trusted-Script Nonce tidak memerlukan perubahan pada mekanisme deteksi.
- `report.py` dan `storage.py` tetap menangani parsing/pencatatan CSP Violation Report.
- Tidak ada IP blocking.
- `client_ip` tetap hanya untuk audit/logging.
- XSSGuard tidak menjadi WAF.
- XSSGuard tidak melakukan sanitization HTML.
- XSSGuard tidak melakukan request blocking.
- Nonce tidak disimpan ke database.
- Core tetap framework-agnostic; Flask hanya menjadi lapisan integrasi.
- CSP Violation Report endpoint tetap mengembalikan HTTP 204.

Perubahan utama hanya berada pada **cara CSP nonce diintegrasikan dengan aplikasi host**.

---

## 12. Alternatif yang Ditolak

| Alternatif | Alasan ditolak |
|---|---|
| Nonce ke semua `<script>` | Terbukti tidak aman melalui browser E2E karena attacker script dapat memperoleh nonce valid |
| Skip nonce jika request DETECTED | Tidak menyelesaikan Stored XSS karena deteksi request dan rendering response dapat terjadi pada request berbeda |
| Middleware melakukan sanitization HTML | Menambah mekanisme baru di luar tiga mekanisme inti yang telah ditetapkan |
| Menghilangkan nonce dan hanya mengandalkan `'self'` | Tidak memberikan enforcement terhadap inline script attacker |
| Menentukan trust berdasarkan marker/atribut yang berasal dari HTML user-controlled | Marker dapat ikut diinjeksi attacker dan tidak membentuk trust boundary yang aman |

---

## 13. Batasan dan Klaim Keamanan

Trusted-Script Nonce diposisikan sebagai mekanisme **defense-in-depth** dan browser-side enforcement.

XSSGuard tidak mengklaim bahwa:

- seluruh jenis XSS dapat dideteksi;
- seluruh Stored XSS otomatis dihilangkan;
- CSP menggantikan output encoding atau sanitization;
- nonce tidak mungkin bocor melalui vulnerability aplikasi lain;
- semua JavaScript harus selalu memiliki nonce, karena policy tetap mengizinkan source tertentu seperti `'self'`.

Klaim yang digunakan:

> **XSSGuard menghasilkan nonce CSP yang unik per-request dan menyediakan nonce tersebut kepada aplikasi host. Aplikasi host menerapkan nonce secara eksplisit pada trusted inline script, sedangkan middleware tidak lagi memberikan nonce secara otomatis kepada seluruh script pada response. Dengan policy CSP yang sesuai, inline script tanpa nonce yang valid dapat ditolak oleh browser dan pelanggarannya dapat dilaporkan melalui CSP Violation Report.**

---

## 14. Status Keputusan

### Keputusan desain

**TRUSTED-SCRIPT NONCE — DIPILIH**

### Empat keputusan yang dikunci

1. **Primitive API**

```python
environ["xssguard.nonce"]
```

2. **Flask API**

```jinja2
{{ xssguard_nonce }}
```

melalui integrasi Flask `context_processor`, dengan sumber:

```python
request.environ["xssguard.nonce"]
```

3. **CSP Policy**

```text
default-src 'self'; script-src 'self' 'nonce-{nonce}'; object-src 'none';
```

4. **Evaluasi CSP**

> **Functional Browser E2E wajib; BR hanya metrik tambahan dan bukan acceptance criterion utama.**

Keempat keputusan ini menjadi dasar untuk sinkronisasi berikutnya terhadap:

```text
Design Decision
      ↓
PRD
      ↓
IMPLEMENTATION_CONTRACT.md
      ↓
6 UML
      ↓
Implementation
      ↓
Testing
```

**Coding belum dilakukan berdasarkan dokumen ini sampai PRD, Contract, dan UML selesai diselaraskan.**

---

## 15. Sign-off

| Peran | Nama | Tanggal | Status |
|---|---|---|---|
| Peneliti | Malvin (NPM 301220020) | 14 Sept 2026 | Proposed |
| Pembimbing | | | Menunggu |
