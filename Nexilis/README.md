# Nexilis standalone patch dan Frida

Terakhir diverifikasi: 16 Oktober 2026.

## Status

APK hasil patch dapat berjalan mandiri tanpa Frida, membuka halaman login PLN
Mobile, menerima input, dan mempertahankan PID yang sama selama pengujian 60
detik. Setelah itu Frida 16.5.2 berhasil melakukan spawn dengan `-f`; toast dan
dialog `Frida injected` muncul serta skrip mengirim event `frida-injected`.

Artifact default:

```text
build/pln-nexilis-standalone.apk
```

## Cara menjalankan

Build, uninstall versi lama, install, lalu spawn Frida:

```sh
./run.sh
```

Build APK saja:

```sh
./run.sh --build-only
```

Jalankan Frida pada APK yang sudah terpasang:

```sh
./run.sh --frida-only
```

Script memilih perangkat ADB pertama yang berstatus `device`. Gunakan
`ANDROID_SERIAL=<serial>` untuk memilih perangkat tertentu. Input APK dan output
dapat diganti dengan environment variable `INPUT_APK` dan `OUTPUT_APK`.

## Patch yang diterapkan

### Gate Java

- `DexLoaderBridge.getModernStealthThreatMask(Context)` mengembalikan `0`.
- `DexLoaderBridge.watchmanVerify()` mengembalikan `true`.
- Keputusan posture `e0.a(JSONObject)` mengembalikan `true`.
- Pemeriksaan ulang protected runtime `v0.a(...)` dibuat `return-void`.
- Pemeriksaan status server lokal dibuat mengizinkan boot.
- Session token, registration state, dan key-delivery memakai state provisioning
  emulator yang telah diverifikasi.

### Payload mandiri

- `nexilis_install.bin` dibundel sebagai asset lalu diekstrak ke private files
  directory saat boot.
- `nexilis_native_components.snpc` dibundel dan dibaca dari private files
  directory.
- SHA-256 APK sumber dan kedua payload diverifikasi sebelum perubahan.
- Dekripsi tetap dilakukan oleh implementasi native asli `DexLoaderBridge`;
  JavaScript tidak berisi decoder pengganti.

### Gate native

Hasil analisis r2 mengonfirmasi dua fungsi ARM64 pada `libprotector.so`. Script
mengubah entry keduanya menjadi `mov w0, #1; ret`:

```text
virtual 0x22e6e0 / file 0x22d6e0  native loader gate
virtual 0x224260 / file 0x223260  watchdog policy action
```

Script memeriksa delapan byte asli sebelum menulis patch dan berhenti jika binary
berbeda.

### Indikator Frida

`emulator/frida-injected.js` memasang hook lifecycle `Activity`, menunggu
protected `com.app.plnmobile.MainActivity` aktif, mempertahankan referensi Activity
dengan `Java.retain`, lalu menampilkan toast dan `AlertDialog`.

## Bukti runtime

- Empat protected DEX berhasil didekripsi ke direct buffer.
- Halaman `Masukkan nomor HP` tampil dari APK hasil script.
- PID standalone yang sama bertahan selama 60 detik dan keyboard numerik tampil.
- Build final lulus `apksigner verify`.
- Mode `--frida-only` menghasilkan event `frida-injected`.

Pesan `NATIVE_WATCHDOG_EVENT ... reason=frida_*` masih dapat muncul sebagai log.
Native policy action sudah dibuat log-only sehingga event tersebut tidak menutup
aplikasi.
