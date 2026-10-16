# Appdome standalone patch dan Frida

Terakhir diverifikasi: 14 Oktober 2026.

## Status

APK hasil rekonstruksi dapat membuka halaman login, menerima tap pada field nomor
HP, menampilkan keyboard, dan mempertahankan sesi Frida aktif. Alur permission
juga berhasil dilewati hingga home.

Implementasi final berada di:

```text
run.sh
emulator/repackage-and-inject.sh
emulator/frida-injected.js
```

Catatan eksperimen dan bukti debugging lengkap tetap tersedia di
`emulator/README.md`.

## Cara menjalankan

Build, uninstall versi lama, install, lalu spawn Frida:

```sh
./run.sh /path/to/appdome.apk
```

APK hasil build ditulis ke:

```text
emulator/build/pln-frida-ready.apk
```

Jalankan Frida saja pada APK yang sudah terpasang:

```sh
./run.sh --frida-only
```

Gunakan `ANDROID_SERIAL=<serial>` bila target bukan serial default script.

## Patch yang diterapkan

- Bootstrap Appdome `libloader.so` dilewati dengan mengganti application menjadi
  `android.app.Application`.
- Atribut Appdome `appComponentFactory` dihapus dari manifest.
- `com.app.plnmobile.MainActivity` direkonstruksi sebagai subclass langsung
  `io.flutter.embedding.android.FlutterActivity`.
- DEX runtime yang dipulihkan dimasukkan sebagai `classes6.dex` dan dipotong
  sesuai `file_size` header.
- Initializer `aFbZQ2.d2vKC4(Context)` pada runtime DEX dibuat langsung
  `return-void`; JNI initializer itu sebelumnya bergantung pada `libloader.so`.
- Registrasi `MobileScannerPlugin` yang class-nya tidak tersedia dilewati agar
  registrasi plugin berikutnya, termasuk `SharedPreferencesPlugin`, tetap jalan.
- Flutter Impeller dimatikan melalui metadata manifest untuk menghindari freeze
  Vulkan pada renderer emulator.

## Dampak dan batasan

Patch menghapus ketergantungan startup pada loader Appdome, bukan menyamarkan
artefak Frida. UI utama dan plugin yang tersedia tetap berjalan. Fitur scanner
belum tersedia karena class `MobileScannerPlugin` tidak ada pada APK rekonstruksi.
