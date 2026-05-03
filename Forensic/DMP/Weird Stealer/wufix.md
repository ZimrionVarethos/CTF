# WriteUp — WeordStealer (Forensic)

**Event:** FindIT CTF Qualifikasi  
**Category:** Forensics  
**Flag:** `FindITCTF{#kita usahakan wfh gaji usd itu!!}`

---

## Overview

File yang diberikan: `stealer.DMP` (76MB). Deskripsi soal bilang *"I just found this weird stealer in the wild"* — kita dikasih memory dump dari proses stealer yang sedang/sudah berjalan.

Alur solve:

```
stealer.DMP
  ├─[1] bulk_extractor   → C2 URL, AES keys, ZIP artifacts
  ├─[2] parse MDMP       → base VA stealer.exe, VA→file offset map
  ├─[3] reconstruct PE   → carve/stealer_extracted.exe
  ├─[4] analisis binary  → Go + Garble, konfirmasi enkripsi
  ├─[5] heap scan        → flag.txt path, POST /checksum body
  └─[6] AES-256-GCM      → FLAG
```

---

## Langkah 1 — Recon Awal: bulk_extractor

Sebelum apapun, kita scan DMP secara kasar. Tool `bulk_extractor` bekerja tanpa perlu memahami format file — dia cukup scan seluruh byte stream dan ekstrak pattern yang menarik: URL, domain, ZIP header, AES key candidate, dll.

```bash
sudo apt install bulk-extractor
bulk_extractor -o output_hasil stealer.DMP
ls -lh output_hasil/
```

**Hasil penting dari `output_hasil/url.txt`:**

```
http://172.20.180.135:1337/upload4
http://172.20.180.135:1337/upload
http://172.20.180.135:1337/checksum
```

Port `1337` + endpoint `/upload` dan `/checksum` — pola klasik C2 info-stealer. Stealer mengupload data curian ke endpoint tersebut dan memverifikasi integritasnya lewat `/checksum`.

**Dari `output_hasil/aes_keys.txt`:**

```
15131395  84 8e 69 c1 78 3a 4c a1 b2 7d 85 cb ef a7 85 cb 0a 5e 3f c4 9d 35 76 76 69 85 e9 91 89 ef 76 45  AES256
15131907  28 e6 3c a3 0e a9 d8 6d 27 be 24 20 0e 58 cc 08 a4 d8 bd 9c 8d 14 b1 e8 3c 53 64 04 b9 f5 e7 4c  AES256
```

Ada dua kandidat AES-256 key di raw dump. Bulk_extractor deteksi ini lewat pattern entropy tinggi + key schedule analysis.

**Dari `output_hasil/zip.txt`:**

```
14974203  PK  (local file header)
```

Ada ZIP embedded di memory. Isinya: `Crypto\Keys\...`, `SYSTEM.hive`, `SECURITY.hive` — bahan curian DPAPI + registry hive.

---

## Intermezzo: Kenapa Kita Perlu Parse MDMP Sendiri?

bulk_extractor kasih petunjuk berharga, tapi kita belum punya **executable stealer-nya**. Kita tahu stealer berjalan dan meninggalkan jejak di memory — artinya PE binary-nya pasti ada di dump.

Masalahnya: **DMP bukan flat memory dump**. File ini berformat **Windows MiniDump (MDMP)**, dan sifatnya cukup spesifik:

```
┌─────────────────────────────────────────────────┐
│  MDMP Header (magic "MDMP", versi, stream count) │
├─────────────────────────────────────────────────┤
│  Stream Directory                                 │
│  ├── Stream 0: ModuleListStream (type=4)         │
│  │     → setiap .exe/.dll yang di-load:          │
│  │       nama file, base VA, ukuran              │
│  ├── Stream 1: Memory64ListStream (type=9)       │
│  │     → setiap region memori:                   │
│  │       VA (virtual address), ukuran, ...       │
│  └── ... (ThreadList, SystemInfo, Exception, ...) │
├─────────────────────────────────────────────────┤
│  Memory Data Block                               │
│  (bytes dari semua region, dikemas rapat-rapat)  │
└─────────────────────────────────────────────────┘
```

**Sifat penting MDMP yang harus dipahami:**

1. **Memori disimpan dalam "ranges"** — bukan flat dari 0x0 sampai 0xFFFFFFFF. Yang disimpan hanya region yang aktif dipakai proses.

2. **VA ≠ file offset** — alamat `0x7ff697eb0000` di memory proses BUKAN berarti ada di posisi itu di file DMP. Posisi aktual di file bergantung pada urutan ranges di Memory64ListStream.

3. **Mapping VA → file offset** harus dibangun manual:
   ```
   Range ke-0: VA=X0, size=S0 → file_offset = base_data_offset
   Range ke-1: VA=X1, size=S1 → file_offset = base_data_offset + S0
   Range ke-2: VA=X2, size=S2 → file_offset = base_data_offset + S0 + S1
   ...
   ```

4. **PE tersebar di beberapa range** — Windows load PE section per section, jadi `.text`, `.data`, `.rdata` bisa ada di range berbeda.

Karena itu kita tidak bisa langsung `dd if=stealer.DMP bs=1 skip=X count=Y` dan dapat PE yang valid. Kita harus reconstruct page by page lewat VA mapping.

---

## Langkah 2 — Parse MDMP: Temukan stealer.exe Base VA

Script ini parse header MDMP, list semua module yang di-load, dan build VA→file offset mapping.

```python
#!/usr/bin/env python3
# parse_mdmp.py
# Jalankan dari direktori yang sama dengan stealer.DMP
import struct

DMP_FILE = 'stealer.DMP'
data = open(DMP_FILE, 'rb').read()

# Verifikasi magic
assert data[:4] == b'MDMP', f"Bukan MDMP! Magic: {data[:4]}"
print(f"[+] MDMP confirmed, ukuran: {len(data):,} bytes")

# MDMP Header
# offset 0: Signature (4 bytes) = "MDMP"
# offset 4: Version (4 bytes)
# offset 8: NumberOfStreams (4 bytes)
# offset 12: StreamDirectoryRva (4 bytes) → offset ke stream directory
stream_count   = struct.unpack('<I', data[8:12])[0]
stream_dir_rva = struct.unpack('<I', data[12:16])[0]
print(f"[+] Jumlah stream: {stream_count}")
print(f"[+] Stream directory di offset: {hex(stream_dir_rva)}")

# Parse tiap stream
# Setiap entry di stream directory = 12 bytes:
#   Type (4 bytes), DataSize (4 bytes), Rva (4 bytes)
print("\n[*] Stream directory:")
for i in range(stream_count):
    off   = stream_dir_rva + i * 12
    stype = struct.unpack('<I', data[off:off+4])[0]
    ssize = struct.unpack('<I', data[off+4:off+8])[0]
    srva  = struct.unpack('<I', data[off+8:off+12])[0]

    label = {
        3: 'ThreadListStream',
        4: 'ModuleListStream',
        6: 'ExceptionStream',
        7: 'SystemInfoStream',
        9: 'Memory64ListStream',
        15: 'MiscInfoStream',
    }.get(stype, f'type={stype}')

    print(f"  [{i:2d}] {label}: size={ssize}, rva={hex(srva)}")

    # === ModuleListStream: list PE modules ===
    if stype == 4:
        mod_count = struct.unpack('<I', data[srva:srva+4])[0]
        print(f"       → {mod_count} modules:")
        pos = srva + 4
        for j in range(mod_count):
            base_va  = struct.unpack('<Q', data[pos:pos+8])[0]
            mod_size = struct.unpack('<I', data[pos+8:pos+12])[0]
            # MINIDUMP_MODULE = 108 bytes
            # ModuleNameRva (RVA ke MINIDUMP_STRING) di offset +20
            name_rva = struct.unpack('<I', data[pos+20:pos+24])[0]
            if name_rva + 4 <= len(data):
                name_len = struct.unpack('<I', data[name_rva:name_rva+4])[0]
                name     = data[name_rva+4:name_rva+4+name_len].decode('utf-16-le', errors='replace')
            else:
                name = '(invalid rva)'
            print(f"         [{j:2d}] base={hex(base_va)}, size={hex(mod_size)}, {name}")
            pos += 108

    # === Memory64ListStream: VA → file offset mapping ===
    if stype == 9:
        # Structure: NumberOfMemoryRanges (8 bytes) + BaseRva (8 bytes)
        # lalu array of (StartOfMemoryRange, DataSize) masing-masing 16 bytes
        num_ranges   = struct.unpack('<Q', data[srva:srva+8])[0]
        base_data_rva = struct.unpack('<Q', data[srva+8:srva+16])[0]
        print(f"       → {num_ranges} memory ranges, data mulai di offset {hex(base_data_rva)}")

        ranges = []
        current_file_off = base_data_rva
        for k in range(num_ranges):
            entry_off = srva + 16 + k * 16
            va  = struct.unpack('<Q', data[entry_off:entry_off+8])[0]
            sz  = struct.unpack('<Q', data[entry_off+8:entry_off+16])[0]
            ranges.append((va, sz, current_file_off))
            current_file_off += sz

        print(f"       → Total data: {(current_file_off - base_data_rva):,} bytes")
        print(f"       → Contoh ranges:")
        for (va, sz, foff) in ranges[:5]:
            print(f"           VA={hex(va)}, size={hex(sz)}, file_off={hex(foff)}")
```

```bash
python3 parse_mdmp.py
```

Output yang relevan:
```
[+] MDMP confirmed, ukuran: 79,691,776 bytes
[+] Jumlah stream: 15
[+] Stream directory di offset: 0x20

[*] Stream directory:
  [ 0] ModuleListStream: ...
         [0] base=0x7ff697eb0000, size=0x2dc2000, C:\Users\SERV\Desktop\stealer.exe
         [1] base=0x7ffb12340000, ...ntdll.dll
         ...
  [ 8] Memory64ListStream: ...
         → 149 memory ranges, data mulai di offset 0x...
```

**Yang kita perlukan:**
- `stealer.exe` ada di base VA `0x7ff697eb0000`, ukuran `0x2dc2000`
- Memory64ListStream punya 149 ranges dengan mapping VA → file offset

---

## Langkah 3 — Reconstruct PE dari MDMP

Setelah tahu base VA stealer.exe dan punya mapping VA→file offset, kita bisa reconstruct PE-nya. Script ini lengkap dan standalone — bisa langsung dijalankan.

```python
#!/usr/bin/env python3
# extract_pe.py
# Output: carve/stealer_extracted.exe
import struct, os

DMP_FILE     = 'stealer.DMP'
STEALER_BASE = 0x7ff697eb0000
STEALER_SIZE = 0x2dc2000
OUT_FILE     = 'carve/stealer_extracted.exe'

print(f"[*] Membaca {DMP_FILE}...")
data = open(DMP_FILE, 'rb').read()
assert data[:4] == b'MDMP', "Bukan file MDMP!"

# ─── Step A: Build VA → file offset mapping dari Memory64ListStream ───
stream_count   = struct.unpack('<I', data[8:12])[0]
stream_dir_rva = struct.unpack('<I', data[12:16])[0]

ranges = []
for i in range(stream_count):
    off   = stream_dir_rva + i * 12
    stype = struct.unpack('<I', data[off:off+4])[0]
    srva  = struct.unpack('<I', data[off+8:off+12])[0]

    if stype == 9:  # Memory64ListStream
        num_ranges    = struct.unpack('<Q', data[srva:srva+8])[0]
        base_data_rva = struct.unpack('<Q', data[srva+8:srva+16])[0]
        current_file_off = base_data_rva
        for k in range(num_ranges):
            entry_off = srva + 16 + k * 16
            va  = struct.unpack('<Q', data[entry_off:entry_off+8])[0]
            sz  = struct.unpack('<Q', data[entry_off+8:entry_off+16])[0]
            ranges.append((va, sz, current_file_off))
            current_file_off += sz
        break

print(f"[+] Loaded {len(ranges)} memory ranges")

# ─── Step B: Helper read_va — baca data dari VA seolah memory flat ───
def read_va(va, size):
    """
    Baca `size` bytes mulai dari Virtual Address `va`.
    Mencari range yang cover VA tersebut, lalu baca dari file DMP.
    Kalau VA tidak ter-cover (unmapped page), isi dengan 0x00.
    """
    result = bytearray(size)
    pos    = 0
    while pos < size:
        found = False
        for (va_start, sz, file_off) in ranges:
            if va_start <= (va + pos) < (va_start + sz):
                chunk_start = (va + pos) - va_start
                to_read     = min(size - pos, sz - chunk_start)
                result[pos:pos+to_read] = data[file_off+chunk_start : file_off+chunk_start+to_read]
                pos  += to_read
                found = True
                break
        if not found:
            pos += 1  # unmapped page, biarkan 0x00
    return bytes(result)

# ─── Step C: Baca dan validasi PE header ───
print(f"[*] Membaca PE header di VA {hex(STEALER_BASE)}...")
pe_header = read_va(STEALER_BASE, 0x1000)

assert pe_header[:2] == b'MZ', "MZ signature tidak ditemukan!"
e_lfanew = struct.unpack('<I', pe_header[0x3C:0x40])[0]
assert pe_header[e_lfanew:e_lfanew+4] == b'PE\x00\x00', "PE signature tidak valid!"
print(f"[+] MZ valid, PE header di offset {hex(e_lfanew)}")

machine      = struct.unpack('<H', pe_header[e_lfanew+4 : e_lfanew+6])[0]
num_sections = struct.unpack('<H', pe_header[e_lfanew+6 : e_lfanew+8])[0]
opt_hdr_size = struct.unpack('<H', pe_header[e_lfanew+20: e_lfanew+22])[0]
print(f"[+] Machine: {hex(machine)} ({'x86-64' if machine == 0x8664 else 'unknown'})")
print(f"[+] Jumlah sections: {num_sections}")

# ─── Step D: Parse section table ───
section_table_off = e_lfanew + 24 + opt_hdr_size
sections = []
print("\n[*] Sections:")
for i in range(num_sections):
    sec_off = section_table_off + i * 40
    name    = pe_header[sec_off:sec_off+8].rstrip(b'\x00').decode('ascii', errors='replace')
    vsize   = struct.unpack('<I', pe_header[sec_off+8 : sec_off+12])[0]
    vrva    = struct.unpack('<I', pe_header[sec_off+12: sec_off+16])[0]
    rawsize = struct.unpack('<I', pe_header[sec_off+16: sec_off+20])[0]
    rawoff  = struct.unpack('<I', pe_header[sec_off+20: sec_off+24])[0]
    sections.append((name, vrva, vsize, rawoff, rawsize))
    print(f"  [{i}] {name:8s}: VA={hex(STEALER_BASE+vrva)}, vsize={hex(vsize)}, rawoff={hex(rawoff)}")

# ─── Step E: Reconstruct PE file ───
# Total size = sampai section terakhir
total_size = max(rawoff + rawsize for (_, _, _, rawoff, rawsize) in sections)
total_size = ((total_size + 0xFFF) // 0x1000) * 0x1000  # align 4KB
print(f"\n[*] Estimated PE size: {hex(total_size)} bytes ({total_size:,} bytes)")

pe_file = bytearray(total_size)

# Copy PE header (0x1000 pertama)
pe_file[:0x1000] = pe_header

# Copy tiap section dari virtual memory ke raw offset
for (name, vrva, vsize, rawoff, rawsize) in sections:
    print(f"[*] Extracting section {name}...")
    sec_data  = read_va(STEALER_BASE + vrva, vsize)
    copy_size = min(vsize, rawsize)
    if rawoff + copy_size <= total_size:
        pe_file[rawoff:rawoff+copy_size] = sec_data[:copy_size]

# ─── Step F: Simpan ───
os.makedirs('carve', exist_ok=True)
with open(OUT_FILE, 'wb') as f:
    f.write(pe_file)

print(f"\n[+] Saved: {OUT_FILE} ({len(pe_file):,} bytes)")
print(f"[!] Verifikasi: file {OUT_FILE}")
print(f"[!] Verifikasi: sha256sum {OUT_FILE}")
```

```bash
python3 extract_pe.py

# Verifikasi
file carve/stealer_extracted.exe
# → PE32+ executable (GUI) x86-64, for MS Windows

sha256sum carve/stealer_extracted.exe
# → c6774d4ac1b4132f20f91581d2fbadb3a03f72738b562bd5840273d87b20b9d7
```

---

## Langkah 4 — Analisis Binary: Go + Garble

```bash
# Cek apakah Go binary — ada build info magic
strings carve/stealer_extracted.exe | grep "buildinf"
# → \xff Go buildinf:   (magic header Go build info)

# Versi Go sengaja di-strip oleh garble
strings carve/stealer_extracted.exe | grep -i "version"
# → go version: unknown  ← garble strip versi

# Cek fungsi-fungsi yang bisa diidentifikasi
strings carve/stealer_extracted.exe | grep "main\."
# → main.(*b1KyQJV7boj).Replace  ← satu-satunya fungsi main.*, nama ter-obfuscate

# Package names yang di-randomize oleh garble
strings carve/stealer_extracted.exe | grep "runtime\."
# → runtime.main, runtime.goexit, dll (stdlib tidak di-obfuscate)

# Lihat string paths yang ter-obfuscate
strings carve/stealer_extracted.exe | grep -E "\.go$" | head -20
# → nama file .go yang sudah di-rename oleh garble
```

**Kesimpulan:** Binary Go yang di-compile dengan [Garble](https://github.com/burrowers/garble):
- Package/function names di-randomize → analisis statik susah
- String literals di-enkripsi saat compile → C2 URL tidak tampak di strings
- Tapi di memory (heap), semua string sudah di-decrypt saat runtime → kita scan heap

---

## Langkah 5 — Heap Scan: Temukan Artifacts Runtime

Karena binary ter-obfuscate, pendekatan terbaik adalah scan memory heap dari DMP — di situ semua string sudah dalam bentuk plaintext (sudah di-decrypt oleh runtime Go).

Script ini scan semua memory range yang **bukan** PE region stealer, lalu cari pattern menarik.

```python
#!/usr/bin/env python3
# heap_scan.py
# Scan heap memory untuk artifacts: flag path, HTTP POST body, dll
import struct

DMP_FILE     = 'stealer.DMP'
STEALER_BASE = 0x7ff697eb0000
STEALER_END  = STEALER_BASE + 0x2dc2000  # base + size

print(f"[*] Loading {DMP_FILE}...")
data = open(DMP_FILE, 'rb').read()
assert data[:4] == b'MDMP'

# ─── Build ranges ───
stream_count   = struct.unpack('<I', data[8:12])[0]
stream_dir_rva = struct.unpack('<I', data[12:16])[0]
ranges = []
for i in range(stream_count):
    off   = stream_dir_rva + i * 12
    stype = struct.unpack('<I', data[off:off+4])[0]
    srva  = struct.unpack('<I', data[off+8:off+12])[0]
    if stype == 9:
        num_ranges    = struct.unpack('<Q', data[srva:srva+8])[0]
        base_data_rva = struct.unpack('<Q', data[srva+8:srva+16])[0]
        cur = base_data_rva
        for k in range(num_ranges):
            e  = srva + 16 + k * 16
            va = struct.unpack('<Q', data[e:e+8])[0]
            sz = struct.unpack('<Q', data[e+8:e+16])[0]
            ranges.append((va, sz, cur))
            cur += sz
        break

print(f"[+] {len(ranges)} ranges loaded")
print(f"[*] Scanning heap (skip PE range {hex(STEALER_BASE)}-{hex(STEALER_END)})...")
print("=" * 70)

# Pattern yang kita cari
PATTERNS = {
    'FLAG_PATH'   : b'flag.txt',
    'HTTP_POST'   : b'POST /',
    'C2_CHECKSUM' : b'/checksum',
    'C2_UPLOAD'   : b'/upload',
    'CONTENT_LEN' : b'Content-Length',
    'HIVE_SYSTEM' : b'SYSTEM.hive',
    'CRYPTO_KEY'  : b'Crypto\\Keys',
}

hits = {}
for (va_start, sz, file_off) in ranges:
    # Skip PE range
    if STEALER_BASE <= va_start < STEALER_END:
        continue
    if sz < 32:
        continue

    chunk = data[file_off:file_off+sz]

    for label, pattern in PATTERNS.items():
        pos = 0
        while True:
            found = chunk.find(pattern, pos)
            if found == -1:
                break
            abs_va = va_start + found
            ctx    = chunk[max(0, found-30) : found+100]
            ctx_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)

            if label not in hits:
                hits[label] = []
            hits[label].append((abs_va, ctx_str, file_off + found))

            pos = found + 1

# Print hasil per label
for label, results in hits.items():
    print(f"\n[{label}] — {len(results)} hit(s)")
    for (va, ctx, foff) in results[:3]:  # max 3 per label
        print(f"  VA={hex(va)} | file_off={hex(foff)}")
        print(f"  Context: {ctx}")
```

```bash
python3 heap_scan.py
```

Output kunci:
```
[FLAG_PATH] — 1 hit(s)
  VA=0x18b5c64fe098 | file_off=0xe4f098
  Context: ...C:\Users\SERV\Documents\flag.txt...

[HTTP_POST] — 2 hit(s)
  VA=0x18b5c6578006 | file_off=0xe58006
  Context: POST /upload HTTP/1.1..Content-Length: 2128303...

[C2_CHECKSUM] — 1 hit(s)
  VA=0x18b5c660xxxx | file_off=0xe6xxxx
  Context: POST /checksum HTTP/1.1..Content-Length: 72...
```

**Analisis temuan:**
- `flag.txt` ada di `C:\Users\SERV\Documents\` → stealer target file ini
- `POST /upload` dengan `Content-Length: 2128303` → upload utama (ZIP berisi SYSTEM.hive, SECURITY.hive, dll)
- `POST /checksum` dengan `Content-Length: 72` → **body 72 bytes ini sangat menarik**

72 bytes = 12 (nonce) + 44 (ciphertext) + 16 (tag) → **persis struktur AES-256-GCM!**

---

## Langkah 6 — Ekstrak Ciphertext dari POST /checksum

Script ini cari POST /checksum di heap lalu ekstrak body 72 bytes-nya.

```python
#!/usr/bin/env python3
# extract_ciphertext.py
# Output: hex ciphertext dari POST /checksum body
import struct

DMP_FILE = 'stealer.DMP'
data = open(DMP_FILE, 'rb').read()
assert data[:4] == b'MDMP'

# ─── Build ranges ───
stream_count   = struct.unpack('<I', data[8:12])[0]
stream_dir_rva = struct.unpack('<I', data[12:16])[0]
ranges = []
for i in range(stream_count):
    off   = stream_dir_rva + i * 12
    stype = struct.unpack('<I', data[off:off+4])[0]
    srva  = struct.unpack('<I', data[off+8:off+12])[0]
    if stype == 9:
        num_ranges    = struct.unpack('<Q', data[srva:srva+8])[0]
        base_data_rva = struct.unpack('<Q', data[srva+8:srva+16])[0]
        cur = base_data_rva
        for k in range(num_ranges):
            e  = srva + 16 + k * 16
            va = struct.unpack('<Q', data[e:e+8])[0]
            sz = struct.unpack('<Q', data[e+8:e+16])[0]
            ranges.append((va, sz, cur))
            cur += sz
        break

# ─── Cari POST /checksum ───
TARGET = b'POST /checksum'
for (va_start, sz, file_off) in ranges:
    chunk = data[file_off:file_off+sz]
    idx = chunk.find(TARGET)
    if idx == -1:
        continue

    abs_va = va_start + idx
    print(f"[+] Found 'POST /checksum' di VA {hex(abs_va)} (file offset {hex(file_off+idx)})")

    # Ambil 512 bytes dari situ untuk parse HTTP
    http_data = chunk[idx:idx+512]
    print(f"[*] Raw HTTP (first 200 chars):")
    print(''.join(chr(b) if 32 <= b < 127 else '.' for b in http_data[:200]))
    print()

    # Cari akhir headers (blank line = \r\n\r\n)
    header_end = http_data.find(b'\r\n\r\n')
    if header_end == -1:
        header_end = http_data.find(b'\n\n')
        body_offset = header_end + 2
    else:
        body_offset = header_end + 4

    if header_end == -1:
        print("[-] Tidak menemukan akhir header!")
        continue

    # Body = 72 bytes setelah headers
    body = http_data[body_offset:body_offset+72]
    print(f"[+] Body ({len(body)} bytes): {body.hex()}")
    print()

    if len(body) >= 72:
        print("[*] AES-256-GCM breakdown:")
        print(f"    Nonce      (12 bytes): {body[:12].hex()}")
        print(f"    Ciphertext (44 bytes): {body[12:56].hex()}")
        print(f"    GCM Tag    (16 bytes): {body[56:72].hex()}")
    break
else:
    print("[-] POST /checksum tidak ditemukan di heap!")
    print("[!] Cek heap_scan.py output untuk VA yang benar")
```

```bash
python3 extract_ciphertext.py
```

---

## Langkah 7 — Decrypt: AES-256-GCM → FLAG

Semua bahan terkumpul:
- **AES-256 Key** (dari `aes_keys.txt`): `848e69c1783a4ca1b27d85cbefa785cb0a5e3fc49d3576766985e99189ef7645`
- **Body 72 bytes** (dari POST /checksum): nonce + ciphertext + tag
- **Mode**: AES-256-GCM (deterministik dari ukuran 12-byte nonce)

```bash
pip3 install pycryptodome
```

```python
#!/usr/bin/env python3
# decrypt_flag.py
from Crypto.Cipher import AES

# ─── Key dari bulk_extractor aes_keys.txt (offset 15131395) ───
key = bytes.fromhex(
    '848e69c1783a4ca1b27d85cbefa785cb'
    '0a5e3fc49d3576766985e99189ef7645'
)

# ─── Body 72 bytes dari POST /checksum (hasil extract_ciphertext.py) ───
body = bytes.fromhex(
    '9165a0312c206893d55d06cd'   # nonce 12 bytes
    '838077d9c80c2bb7bb1911fc'   # ↓ ciphertext 44 bytes
    'd9e11853d5f8622719d2fa73'   #
    '03dbe53bf41ad3b66d5da120'   #
    'd2edc96b071d4b2f'           # ↑ akhir ciphertext
    '9a75548ad5d0b56713d6d8ac'   # ↓ GCM tag 16 bytes
    '1cf9d013'                   # ↑ akhir tag
)

# Verifikasi ukuran
assert len(body) == 72, f"Body harus 72 bytes, dapat {len(body)}"

# ─── Pecah komponen ───
nonce      = body[:12]    # 12 bytes
ciphertext = body[12:56]  # 44 bytes
tag        = body[56:72]  # 16 bytes

print("=" * 60)
print(f"Key   : {key.hex()}")
print(f"Nonce : {nonce.hex()} ({len(nonce)} bytes)")
print(f"CT    : {ciphertext.hex()} ({len(ciphertext)} bytes)")
print(f"Tag   : {tag.hex()} ({len(tag)} bytes)")
print("=" * 60)

# ─── Decrypt ───
cipher    = AES.new(key, AES.MODE_GCM, nonce=nonce)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)

print(f"\n[+] FLAG: {plaintext.decode()}")
```

```bash
python3 decrypt_flag.py
```

Output:
```
============================================================
Key   : 848e69c1783a4ca1b27d85cbefa785cb0a5e3fc49d3576766985e99189ef7645
Nonce : 9165a0312c206893d55d06cd (12 bytes)
CT    : 838077d9c80c2bb7bb1911fcd9e11853d5f8622719d2fa7303dbe53bf41ad3b66d5da120d2edc96b071d4b2f (44 bytes)
Tag   : 9a75548ad5d0b56713d6d8ac1cf9d013 (16 bytes)
============================================================

[+] FLAG: FindITCTF{#kita usahakan wfh gaji usd itu!!}
```

---

## Screenshot Requirements

Untuk dokumentasi/bukti:

| # | Screenshot apa | Command |
|---|---------------|---------|
| 1 | bulk_extractor output url.txt | `cat output_hasil/url.txt` |
| 2 | bulk_extractor output aes_keys.txt | `cat output_hasil/aes_keys.txt` |
| 3 | parse_mdmp.py output (ModuleListStream, stealer.exe base VA) | `python3 parse_mdmp.py 2>&1 \| head -40` |
| 4 | extract_pe.py selesai + `file carve/stealer_extracted.exe` | run script lalu `file carve/stealer_extracted.exe` |
| 5 | sha256sum stealer_extracted.exe | `sha256sum carve/stealer_extracted.exe` |
| 6 | heap_scan.py menemukan flag.txt path dan POST /checksum | `python3 heap_scan.py 2>&1` |
| 7 | extract_ciphertext.py — body 72 bytes + AES-GCM breakdown | `python3 extract_ciphertext.py` |
| 8 | decrypt_flag.py — FLAG | `python3 decrypt_flag.py` |

---

## Ringkasan Teknis

| Artifact | Detail |
|----------|--------|
| Input | `stealer.DMP` — Windows MiniDump, 76MB, 15 streams, 149 memory ranges |
| Format MDMP | `ModuleListStream` (module list) + `Memory64ListStream` (VA→file offset map) |
| C2 Server | `172.20.180.135:1337` — `/upload`, `/upload4`, `/checksum` |
| Stealer binary | `C:\Users\SERV\Desktop\stealer.exe`, PE32+ x86-64, 13.4MB |
| Bahasa | Go dengan Garble obfuscation (package/function names di-randomize) |
| SHA256 | `c6774d4ac1b4132f20f91581d2fbadb3a03f72738b562bd5840273d87b20b9d7` |
| Target stealer | `C:\Users\SERV\Documents\flag.txt` + DPAPI Crypto keys + registry hives |
| Enkripsi | AES-256-GCM: nonce 12b + ciphertext 44b + tag 16b = 72b total |
| AES Key | `848e69c1783a4ca1b27d85cbefa785cb0a5e3fc49d3576766985e99189ef7645` |
| **FLAG** | **`FindITCTF{#kita usahakan wfh gaji usd itu!!}`** |

---

## Tools

```
bulk_extractor  — recon kasar, ekstrak URL/AES key/ZIP dari raw bytes
xxd / strings   — inspeksi manual
Python3 struct  — parse MDMP format, reconstruct PE, scan heap
pycryptodome    — AES-256-GCM decrypt
file, sha256sum — verifikasi binary
```
