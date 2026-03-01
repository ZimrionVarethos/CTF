# 🚩 FULL WRITEUP: THE CHIZURU MALWARE REVERSE ENGINEERING

## PHASE 1: INITIAL DISCOVERY (THE ENTRY POINT)

Semuanya dimulai dari file `challenge.zip` yang berisi sebuah file biner misterius.

1. **Identifikasi File:** Kita punya file bernama `cmatrix`. Pas kita cek pakai perintah `file cmatrix`, ternyata itu adalah **PyInstaller executable**.
2. **Extraction (PyInstxtractor):** Kita bongkar biner Python itu untuk melihat source code aslinya.

```bash
python3 pyinstxtractor.py cmatrix
```

3. **Hasil Extract:** Di dalam folder hasil extract, kita nemu harta karun:
   - `utama.bin`: Script utama yang sudah di-compile.
   - `libutama.so` (atau `libutama.bin`): Shared library pendukung.
   - **Link Tersembunyi:** Di salah satu metadata atau script hasil decompile, kita nemu URL GitHub Gist yang mencurigakan (milik user `blacowhait`).

---

## PHASE 2: ENVIRONMENT RECONSTRUCTION (DOCKER)

Karena menjalankan malware di mesin asli itu bunuh diri, kita bangun "Laboratorium" di Docker.

1. **Build Lab:** Kita pakai Ubuntu karena library-nya paling cocok.

```bash
docker run -it --rm -v $(pwd):/malware -w /malware ubuntu:latest /bin/bash
```

2. **Fix Dependency (The Python 3.8 Nightmare):** Malware ini manja, dia minta Python 3.8 yang sudah *deprecated*.

```bash
add-apt-repository ppa:deadsnakes/ppa -y && apt update
apt install -y python3.8 python3.8-distutils libpython3.8 xxd openssl curl

# Install PIP & Library Kripto
curl https://bootstrap.pypa.io/pip/3.8/get-pip.py -o get-pip.py
python3.8 get-pip.py
python3.8 -m pip install pycryptodome
```

---

## PHASE 3: COMMAND SNIFFING (THE SHELL HIJACKING)

Ini langkah paling cerdas yang kita lakuin. Daripada nebak-nebak apa yang dilakuin `utama.bin`, kita **"sadap"** perintah shell-nya.

1. **Kenapa?** Karena pas kita run, muncul error `/bin/sh: 1: Bad substitution`. Ini artinya malware lagi nyoba kirim perintah Bash yang kompleks lewat Python.
2. **Hijacking `/bin/sh`:**

```bash
mv /bin/sh /bin/sh.orig
cat << 'EOF' > /bin/sh
#!/bin/bash
echo "[!] MALWARE EXECUTED: $@" >> /malware/log_perintah.txt
exec /bin/bash "$@"
EOF
chmod +x /bin/sh
```

3. **Execution:** Kita jalanin malware-nya.

```bash
export LD_LIBRARY_PATH=.
./utama.bin
```

---

## PHASE 4: REVEALING THE SECRET RECIPE

Setelah malware jalan (dan gagal karena folder `/home/uzer` gak ada), dia ninggalin jejak di `log_perintah.txt`.

1. **Isi Log:** Kita nemu perintah `openssl` yang sangat spesifik:
   - **Key Source:** `/tmp/init.txt.pem` (File 3408 bytes dari GitHub)
   - **Rumus Key:** `head -c 256 | rev | tail -c 64`
   - **Rumus IV:** `tail -c 128 | rev | head -c 32`

2. **Ekstraksi Kunci:**

```bash
export MY_KEY=$(head -c 256 /tmp/init.txt.pem | rev | tail -c 64)
export MY_IV=$(tail -c 128 /tmp/init.txt.pem | rev | head -c 32)
```

---

## PHASE 5: DATA RECOVERY (SYSDIG & REVERSAL)

File asli sudah dihapus (`rm -f`). Kita harus ambil dari rekaman sistem (`.scap`).

1. **Sysdig Dump:** Kita cari *write event* ke file `.enc`.

```bash
sysdig -r challenge.scap "evt.type=write and fd.name contains flag.txt.enc" -x
```

2. **The "Hex Reversal" Trick:** Malware ini iseng. Sebelum dienkripsi, dia membalik urutan Hex-nya. Jadi, urutan dekripsi kita adalah:

   **File Encrypt → Hex → Reverse → Binary → OpenSSL Decrypt**

3. **Final Decryption Command:**

```bash
xxd -p flag.txt.enc.000000 | rev | xxd -r -p | \
openssl enc -aes-256-ctr -d -K $MY_KEY -iv $MY_IV
```

---

## PHASE 6: THE FLAG

Setelah semua drama library, shell hijacking, dan rumus matematika gila itu, munculah flag-nya:

```
INTECHFEST{actually_i_wanna_add_pyArmor_but_its_broken_8217da}
```

---

## 💡 Key Takeaways

| Teknik | Kegunaan |
|---|---|
| **PyInstxtractor** | Buat bongkar biner Python |
| **Binary Hijacking** | Ganti `/bin/sh` buat intip perintah internal malware |
| **Crypto Reversal** | Selalu cek apakah data di-`rev` sebelum atau sesudah enkripsi |
| **Sysdig** | Sahabat terbaik kalau file sudah di-`rm` |
