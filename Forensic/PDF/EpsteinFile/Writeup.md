# EpsteinFile - PragyanCTF2026

## Challenge Overview
You are provided with a PDF file related to an ongoing investigation. The document appears complete, but not everything is as it seems.

Analyze the file carefully and recover the hidden flag!!!
## Solution Steps

### 1. Ekstraksi Teks dari PDF
Sebuah challenge forensics yang melibatkan analisis file PDF dengan teks tersembunyi dan enkripsi berlapis.

Langkah pertama, saya mencurigai adanya teks yang disamarkan di balik balok-balok hitam pada PDF. Untuk memverifikasi hal ini, saya mengekstrak semua teks dari PDF:
```bash
pdftotext contacts.pdf - | wc -l
```

Output menunjukkan ada 2900 baris teks. Kemudian saya mencari area yang mencurigakan di sekitar baris 2865:
```bash
pdftotext contacts.pdf - | sed -n '2865,2875p'
```

**Output:**
```
*Redacted to
protect potential
victim information
XOR_KEY
JEFFREY
*Redactions for personal
contact information
```

Bingo! Ditemukan XOR key: `JEFFREY`

### 2. Mencari Ciphertext
Karena sudah mendapat key, langkah selanjutnya adalah mencari ciphertext. Saya menggunakan `strings` dengan grep untuk mencari kata kunci terkait:
```bash
strings contacts.pdf | grep -Ei -C 3 "XOR|secret|hidden|cipher|key"
```

**Output:**
```
/Hidden (3e373f283d312d25222332362c3d2e292322)
```

Ditemukan ciphertext dalam hex: `3e373f283d312d25222332362c3d2e292322`

### 3. Dekripsi XOR
Membuat script Python sederhana untuk melakukan XOR decryption:
```python
from binascii import unhexlify

cipher_bytes = bytes.fromhex("3e373f283d312d25222332362c3d2e292322")
key = b"JEFFREY"

result = bytes([b ^ key[i % len(key)] for i, b in enumerate(cipher_bytes)])
print(result.decode())
```

**Output:**
```
trynottogetdiddled
```

Hasilnya bukan flag, melainkan sebuah password!

### 4. Mencari File Tersembunyi di Akhir PDF
Saya teringat bahwa file sering disembunyikan setelah marker `%%EOF` pada PDF. Melakukan verifikasi dengan `xxd`:
```bash
xxd contacts.pdf | tail
```

Terlihat ada data setelah `%%EOF`. Mencari offset yang tepat:
```bash
grep -abU "%%EOF" contacts.pdf
```

**Output:** `13984070:%%EOF`

Mengekstrak data tersembunyi setelah EOF:
```bash
dd if=contacts.pdf of=hidden.bin bs=1 skip=13984076
```

**Output:**
```
109+0 records in
109+0 records out
109 bytes copied, 0.00171039 s, 63.7 kB/s
```

Memeriksa tipe file:
```bash
file hidden.bin
```

**Output:**
```
hidden.bin: PGP symmetric key encrypted data - AES with 256-bit key salted & iterated - SHA512
```

### 5. Dekripsi PGP dengan Password
Menggunakan GPG untuk mendekripsi file dengan password yang sudah didapat (`trynottogetdiddled`):
```bash
gpg --decrypt hidden.bin
```

Saat diminta passphrase, masukkan: `trynottogetdiddled`

**Output:**
```
cpgs{96a2_a5_j9l_u8_0h6p6q8}
```

### 6. Decode ROT13 dan ROT5
String yang didapat masih ter-encode dengan ROT13 (untuk huruf) dan ROT5 (untuk angka).

Decode ROT13 untuk huruf:
```bash
echo "cpgs{96a2_a5_j9l_u8_0h6p6q8}" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

**Output:**
```
pctf{96n2_n5_w9y_h8_0u6c6d8}
```

Kemudian secara manual decode ROT5 untuk angka:
- 9→4, 6→1, 2→7, 5→0, 8→3, 0→5, 6→1, 6→1, 8→3

## Flag
```
pctf{41n7_n0_w4y_h3_5u1c1d3}
```

## Tools Used
- `pdftotext` - Ekstraksi teks dari PDF
- `strings` - Mencari string dalam binary
- `xxd` - Hex dump
- `dd` - Data dump/extraction
- `gpg` - Dekripsi PGP
- Python - XOR decryption
- `tr` - ROT13 translation

## Key Techniques
1. PDF text extraction untuk menemukan hidden text
2. XOR cipher decryption
3. File carving setelah EOF marker
4. PGP symmetric encryption
5. ROT13/ROT5 cipher
