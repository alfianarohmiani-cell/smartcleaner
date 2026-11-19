# Smart Scan File Dobel (PC)

```
SMART SCAN FILE DOBEL - versi PC

CARA 1 - jadi .exe lewat GitHub (tanpa install apa pun di PC)
1. Buat repo baru di GitHub, upload SEMUA isi zip ini (termasuk folder .github).
2. Buka tab "Actions" > tunggu "Build SmartScan.exe" selesai (sekitar 2-3 menit, centang hijau).
3. Klik build tersebut > bagian "Artifacts" > unduh "SmartScan-Windows".
4. Ekstrak, jalankan SmartScan.exe. Kalau muncul peringatan SmartScreen: "More info" > "Run anyway".

CARA 2 - kalau di PC sudah ada Python
   pip install send2trash pillow
   python smartscan.py

CARA PAKAI
- Centang drive (misal D:\) atau "Tambah folder", lalu klik "Mulai Scan".
- Tab "Isi sama persis": file yang isinya identik 100%. Sudah otomatis ditandai mana yang disimpan.
- Klik kolom Status / tekan Spasi untuk ganti SIMPAN / HAPUS. Klik dua kali untuk membuka file.
- Klik "Pindahkan ke Recycle Bin". File masih bisa dikembalikan dari Recycle Bin.
- Tab "Nama mirip": file seperti "foto (1).jpg" yang isinya beda. Cek manual dulu.

Tips: scan drive D:/E: (data) lebih berguna daripada C:. Folder Windows, Program Files,
AppData, dan file OneDrive yang belum diunduh otomatis dilewati.
```
