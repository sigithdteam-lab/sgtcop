sgtcopv2.py (Smart Security Monitor v2.0)

1. Tujuan Utama

monitor keamanan khusus untuk server berbasis Linux (terutama dengan PHP, Exim, dan lingkungan hosting). Fungsinya:

· Mendeteksi spam pada antrian email dan log Exim.
· Memindai file PHP untuk mencari WebShell, backdoor, dan kode berbahaya.
· Belajar secara otomatis dari temuan untuk meningkatkan deteksi di masa depan.
· Menggunakan Machine Learning (Random Forest) untuk klasifikasi file mencurigakan.
· Mengintegrasikan VirusTotal API untuk verifikasi hash file.
· Memperbarui basis data tanda tangan (signature) dari server pusat.

---

2. Instalasi dan Ketergantungan

2.1. Persiapan Environment

· Pastikan Python 3.6+ terinstal.
· Buat direktori yang diperlukan (secara otomatis dibuat jika belum ada):
  ```bash
  mkdir -p /var/log/security_monitor /var/lib/security_monitor /root/security_backups
  ```

2.2. Install Library Python

```bash
pip3 install requests joblib scikit-learn numpy
```

Catatan: Jika library tidak terinstal, fitur terkait akan dinonaktifkan (fallback) dan script tetap berjalan.

2.3. API Key VirusTotal (Opsional)

Setel environment variable untuk mengaktifkan integrasi VirusTotal:

```bash
export VIRUSTOTAL_API_KEY="your_api_key_here"
```

Atau tambahkan ke ~/.bashrc agar permanen.

---

3. Konfigurasi (Variabel CONFIG di dalam script)

Anda bisa mengubah parameter di awal script sesuai kebutuhan server:

Parameter Deskripsi
scan_dirs Direktori yang akan dipindai (contoh: /home, /var/www).
log_dir Lokasi log harian.
learning_file File JSON untuk menyimpan data pembelajaran (pola, fungsi berbahaya, dll).
report_file File laporan akhir.
backup_dir Tempat backup sebelum upgrade.
max_file_size_webshell Maksimal ukuran file PHP yang dipindai (default 2 MB).
blocked_*_files File daftar domain, IP, dan negara yang diblokir untuk spam.
signature_url URL untuk update signature dari remote server.
virustotal_api_key Bisa diisi langsung atau dari environment variable.
ml_model_path Lokasi penyimpanan model ML yang sudah dilatih.

---

4. Cara Menjalankan

4.1. Mode Interaktif / Kontinu (Default)

```bash
python3 sgtcop.py
```

Script akan menjalankan satu siklus scan, lalu menunggu 3600 detik (1 jam) sebelum mengulang.

4.2. Mode Sekali Jalan (--once)

```bash
python3 sgtcop.py --once
```

Menjalankan scan satu kali dan keluar.

4.3. Mode Upgrade Otomatis (--upgrade)

```bash
python3 sgtcop.py --upgrade
```

Melakukan scan, belajar dari temuan, lalu memperbarui learning_data.json dengan pola baru. Tidak ada perubahan pada kode script itu sendiri (hanya data pembelajaran).

4.4. Update Signature Database (--update-signatures)

```bash
python3 sgtcop.py --update-signatures
```

Mengunduh signature terbaru dari signature_url dan menggabungkannya ke learning_data.json. Membutuhkan requests dan koneksi internet.

4.5. Latih Model Machine Learning (--train-ml)

```bash
python3 sgtcop.py --train-ml
```

Melakukan scan untuk mengumpulkan sampel file (positif/negatif), lalu melatih model Random Forest dan menyimpannya ke ml_model_path. Gunakan setelah beberapa kali scan agar ada data yang cukup.

4.6. Tampilkan Bantuan (--help)

```bash
python3 sgtcop.py --help
```

Menampilkan ringkasan opsi.

---

5. Fungsi Utama (Alur Proses)

5.1. Pemindaian Spam (Spam Scanning)

· Antrian Email: /var/spool/mail, /var/spool/postfix/*.
· Log Exim: /var/log/exim_mainlog – mencari kata kunci seperti spam, rejected, blocked.
· File PHP yang memanggil mail() dan mengandung pola spam (Viagra, Casino, dll).
· Deteksi spam berdasarkan:
  · Domain pengirim/ penerima yang ada di daftar blokir.
  · IP sumber yang masuk blokir.
  · Pola di subjek/body email.
  · Aturan Exim (SPF, DKIM, dll).

5.2. Pemindaian File PHP (WebShell & Malware)

· Hanya file dengan ekstensi .php, .phtml, .php5, .inc, .module, dll.
· Pemeriksaan:
  · Pola regex berbahaya (eval(, system(, base64_decode, dll).
  · Fungsi berbahaya (exec, shell_exec, curl_exec, dll).
  · Nama file mencurigakan (c99, r57, shell, cmd, dll).
  · Konten terenkripsi/obfuscated (gzinflate, str_rot13, dll).
  · Machine Learning: Ekstrak 8 fitur (panjang, entropi, jumlah fungsi berbahaya, dll) dan prediksi probabilitas (threshold > 0.7).
  · VirusTotal: Jika file dicurigai, hitung hash MD5 dan tanyakan ke VirusTotal (jika API key ada).
· Hasil dikategorikan Critical (sangat berbahaya) atau Suspicious.

5.3. Pembelajaran (Self-Learning)

· Pola/fungsi/nama baru yang ditemukan saat scan akan ditambahkan ke learning_data.json.
· Domain/IP spam yang sering muncul juga ditambahkan ke daftar blokir internal.
· Metode: script akan memperbarui dangerous_patterns, dangerous_functions, suspicious_names, critical_patterns, dan spam_patterns.

5.4. Upgrade (Auto-Upgrade)

· Hanya memperbarui data pembelajaran, bukan kode program.
· Membuat backup file pembelajaran sebelum perubahan.
· Menyimpan log upgrade di backup_dir.

5.5. Pelaporan

· Hasil scan disimpan dalam file teks di /root/security_report.txt.
· Laporan mencakup:
  · Ringkasan spam (jumlah, sumber teratas).
  · Daftar file critical dan suspicious (dengan hash, ukuran, probabilitas ML, link VirusTotal jika ada).
  · Deteksi versi PHP dan masalah konfigurasi (disable_functions, allow_url_fopen, dll).
  · Pola baru yang dipelajari.
  · Status fitur tambahan (ML, VT, update signature).

---

6. Fitur 
- Self-Learning Pembelajaran dinamis dari temuan scan – pola baru otomatis ditambahkan ke knowledge base.
- Machine Learning (Random Forest) Klasifikasi file dengan 8 fitur numerik. Model disimpan dan dapat dilatih ulang.
- VirusTotal Integration Verifikasi hash file dengan VirusTotal API untuk validasi eksternal.
- Signature Update Update basis data tanda tangan dari server pusat (jika URL dikonfigurasi).
- Spam Detection Multi-Source Email queue, log Exim, file PHP, dan aturan Exim.
- PHP Configuration Audit Memeriksa pengaturan php.ini untuk keamanan (disable_functions, allow_url_fopen, dll).
- Blocklist Management Membaca/menambahkan domain, IP, dan negara yang diblokir untuk spam.
- Reporting Laporan lengkap dan terstruktur untuk admin.
- Continuous Monitoring Mode daemon dengan interval 1 jam (bisa disesuaikan).
- Fallback Mechanism Jika library tidak terinstal, fitur terkait dinonaktifkan tanpa mengganggu proses utama.

---

7. Contoh Skenario Penggunaan

Skenario 1: Scan Sekali untuk Investigasi

```bash
python3 sgtcop.py --once
```

Cocok untuk pemeriksaan awal atau troubleshooting.

Skenario 2: Monitoring Berkelanjutan

```bash
nohup python3 sgtcop.py > /dev/null 2>&1 &
```

Menjalankan di background, akan terus memindai setiap jam.

Skenario 3: Update Pola Setelah Menemukan WebShell Baru

```bash
python3 sgtcop.py --once      # scan untuk mengumpulkan temuan
python3 sgtcop.py --upgrade   # belajar dari temuan
```

Skenario 4: Integrasi VirusTotal dan ML

1. Setel VIRUSTOTAL_API_KEY.
2. Jalankan scan beberapa kali agar terkumpul sampel.
3. Jalankan --train-ml untuk melatih model.
4. Model akan otomatis digunakan pada scan berikutnya.

---

8. Lokasi File Penting

File/Direktori Kegunaan
/var/log/security_monitor/security_YYYYMMDD.log Log harian aktivitas.
/var/lib/security_monitor/learning_data.json Basis data pengetahuan (pola, fungsi, nama mencurigakan).
/var/lib/security_monitor/ml_model.pkl Model ML yang disimpan (joblib).
/root/security_report.txt Laporan hasil scan terakhir.
/root/security_backups/ Backup file pembelajaran dan upgrade log.
/etc/blocked_incoming_email_domains Daftar domain yang diblokir (format: satu per baris).
/etc/blocked_incoming_email_country_ips Daftar IP/ranges yang diblokir.
/etc/blocked_incoming_email_countries Daftar kode negara (ISO) yang diblokir.

---

9. Catatan Penting

· Hak akses: Jalankan sebagai root atau user dengan akses baca ke direktori sistem (Exim, mail spool, PHP).
· Kinerja: Scan direktori besar bisa memakan waktu, gunakan --once untuk sekali jalan.
· Keamanan: Script tidak mengubah file sistem (hanya membaca dan menulis log/backup), kecuali upgrade data pembelajaran yang hanya memodifikasi learning_data.json.
· Kustomisasi: Anda dapat menambah/ mengurangi SKIP_DIRS atau SCAN_EXTS di bagian atas script.

---

Dengan panduan ini, Anda dapat memanfaatkan sgtcop.py sebagai alat bantu keamanan yang adaptif dan terintegrasi untuk server Anda.
