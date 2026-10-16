# Handoff debugging Frida / Appdome

Terakhir diperbarui: 14 Oktober 2026, 20:12 WIB; mencakup APK hasil apktool
yang menerima Frida attach stabil dan perbaikan freeze renderer emulator.

**Status: TARGET FRIDA ATTACH TERCAPAI PADA APK PATCH; PARITAS FITUR BELUM SELESAI.**
Main PID terverifikasi hidup dengan session Frida dan skrip aktif selama 30 detik.
Field nomor HP dapat diklik dan keyboard tampil. Plugin `mobile_scanner` belum
tersedia pada APK rekonstruksi, sehingga fitur scanner belum dapat dianggap normal.

## Hasil apktool terbaru — Frida attach berhasil

Artifact:

```text
emulator/build/pln-frida-ready.apk
SHA-256 3a7a3e8896288d603833a77b78113d4e92dbde9cad8026cbdc4e312b9e541aab
```

Perubahan kandidat ini:

- Bootstrap `libloader.so` tidak dijalankan: manifest memakai
  `android.app.Application` dan tidak memakai Appdome `appComponentFactory`.
- `com.app.plnmobile.MainActivity` direkonstruksi sebagai subclass langsung
  `io.flutter.embedding.android.FlutterActivity`.
- DEX runtime Appdome yang pernah didump dimasukkan statis sebagai
  `classes6.dex` setelah dipotong ke `file_size` header (`196036` byte).
- Hanya initializer `aFbZQ2.d2vKC4(Context)` di DEX runtime yang dibuat
  `return-void`, karena JNI-nya sebelumnya didaftarkan oleh `libloader`.
- Registrasi `MobileScannerPlugin` dilewati karena class plugin tersebut tidak
  ada. `NoClassDefFoundError` sebelumnya menghentikan seluruh registrant sebelum
  `SharedPreferencesPlugin`, lalu UI menampilkan `PlatformException` yang
  menyesatkan sebagai kegagalan koneksi.
- Impeller dimatikan melalui metadata application. Trace freeze menunjukkan
  thread raster menunggu `vkAllocateCommandBuffers` pada driver Vulkan emulator,
  sedangkan main thread tertahan di `FlutterJNI.nativeSurfaceDestroyed`.

Hasil runtime terverifikasi:

- PID `25983` hidup dan window fokus adalah
  `com.app.plnmobile/.MainActivity`.
- Skrip Frida aktif bertahan 30 detik;
  `session.is_detached == false` dan PID tetap hidup.
- Tidak ada watchdog Appdome yang membunuh `frida-server` pada kandidat ini.
- Layar login tampil tanpa dialog `SharedPreferences`, field nomor HP menerima
  tap, dan keyboard tampil.
- Alur permission berhasil melewati halaman `Perizinan Akses` hingga home.
  Siklus Back → relaunch serta tap navigasi berhasil tanpa launch/destroy timeout.
- Registrasi scanner sengaja dilewati; fitur scanner belum dapat dianggap bekerja.

APK ini sedang terpasang di emulator. Attach manual:

```sh
/Users/rahmatafriyanton/.pyenv/versions/frida-16.5.2/bin/frida \
  -U -p "$(adb -s emulator-5554 shell pidof com.app.plnmobile)"
```

Install ulang menghapus data APK lama karena signature debug berbeda:

```sh
adb -s emulator-5554 uninstall com.app.plnmobile
adb -s emulator-5554 install emulator/build/pln-frida-ready.apk
```

## Permintaan user dan titik lanjut

User meminta memperbaiki `run.py` dan JavaScript agar aplikasi yang sudah terinstall
di emulator tidak freeze, layar bisa diklik, dan tidak perlu force exit. User
secara eksplisit meminta environment `pyenv shell frida-16.5.2`.

User menegaskan proses utama mati karena Frida. Pengujian attach tanpa skrip
mendukung observasi tersebut. User kemudian restart emulator untuk masalah DNS;
setelah user mengatakan “sudah”, DNS sudah diverifikasi normal, tetapi crash Frida
masih terjadi. User kemudian meminta fokus pada goal dan mengoreksi pendekatan: “ga usah di samarkan, bersihkan aja hasil deteksinya”.
Jangan mengganti nama thread/artefak sebagai pengganti sanitasi hasil cek.
Permintaan terakhir adalah memasukkan temuan penting beserta action plan ke README ini.

Goal Frida attach dan UI interaktif sudah tercapai melalui APK rekonstruksi di
bagian atas. Bagian eksperimen berikut bersifat historis untuk APK original;
runner lama pada APK original tetap belum stabil.

## Percobaan tabel callback hasil deteksi

Crash buffer kemudian memberi evidence khusus PID `15318`, TID `15442`:
SIGSEGV/SEGV_MAPERR, fault `0x3c5a6dbc9f`; PC `libloader+0x150f74`, caller
`+0x325164`. Disassembly PC adalah `ldp w15,w16,[x21,#8]`; register
`x21=0x3c5a6dbc97`, sehingga alamat baca cocok persis dengan fault. Simpanan
log relevan tersedia di `evidence/2026-10-14-pid15318-crash.log`.
Ini menunjukkan fault baca pointer di loader, bukan bukti pasti mekanisme anti-tamper.

Kontrol `/tmp/appdome-table-unchanged-control.py` mengalokasikan CModule yang sama,
mengubah/memulihkan proteksi halaman, tetapi menulis kembali relative pointer original
(tidak redirect). PID `16777` hidup sekitar 18 detik sebelum keluar, dengan counter shim
0 sebagaimana diharapkan, dibanding 4–5 detik pada kontrol redirect. Perbedaan ini
mengarahkan pemeriksaan ke perubahan target callback/validasi datanya; belum membuktikan
penyebab tunggal dan tetap bukan aplikasi stabil. Jangan menafsirkan log generik
`result-forwarder-installed` sebagai bukti callback dialihkan pada kontrol unchanged.


Uji pembanding lanjutan: `/tmp/appdome-forwarder-control.py` menghapus penulisan
`payload[177]` sehingga CModule hanya menghitung dan memanggil original. PID `15714`
tetap keluar sekitar 5 detik, dengan counter 5 lalu 8. Jadi kegagalan sanitizer
sebelumnya tidak mengisolasi semantik byte hasil. Kontrol kedua memakai ARM64
`ldr x16, original; br x16` sebagai tail-branch, tanpa frame C atau perubahan hasil,
untuk mempertahankan LR/stack pemanggil. Run PID `16078` timeout saat attach (belum
menguji thunk); retry terminal berikutnya PID `16336` berhasil memasang pointer
namun main keluar sekitar 4 detik. Scratch: `/tmp/appdome-tailbranch-control.py`.
Mengganti frame C dengan tail-branch saja tidak memulihkan kestabilan. Pemeriksaan
integritas tabel tetap hipotesis, bukan fakta yang sudah dibuktikan.


User mengonfirmasi hanya memiliki APK; Fusion Set/ThreatScope tidak tersedia.
Dispatcher `0x98468` membaca tabel relative-offset 16 byte per entri pada
`0x6fe418` sampai `0x6ff318`. Offset pertama menuju ID event, offset kedua relatif
terhadap alamat slot callback. Runtime PID `14934` mengonfirmasi pemetaan subscriber
historis; halaman tabel `r--`. Callback dipanggil dengan payload sebagai argumen x0.

Kandidat `/tmp/appdome-result-forwarder.py` mengubah hanya entri callback event 136
untuk `0x3d68ac` (slot decimal `7335568`) menuju CModule yang menulis `payload[177]=1`
lalu memanggil callback asli. Tidak memasang inline Interceptor pada dispatcher.
Proteksi halaman dipulihkan ke `r--` setelah menulis relative pointer. PID `15318`
mencatat counter 6 lalu 9 pemanggilan, tetapi main tetap keluar sekitar 5 detik.
**Kandidat gagal dan tidak diintegrasikan ke skrip utama.** Belum dibuktikan apakah
kegagalan berasal dari pemeriksaan integritas data, pemicu lain, atau semantik hasil.
Jangan mengulangi perubahan entri yang sama dengan klaim bahwa tanpa inline hook
pasti lolos deteksi. Scratch observasi tabel: `/tmp/appdome-subscriptions.py`.

## Pembaruan 17:33 WIB dan trace terminasi berikutnya

Pemeriksaan timeout berikutnya: tracing raw syscall dengan opsi userstacktrace dan
sym-userobj pada PID `17523` tidak menghasilkan user stack; attach sudah timeout
sebelum skrip terpasang. `/tmp/appdome-exit-userstack-run.txt` dan trace pasangannya
bukan bukti caller exit aplikasi. Tidak ada proses eksperimen yang masih ditunggu.

Batas attach diuji 12 detik pada scratch `/tmp/appdome-attach-timing.py` (bukan
perubahan default runner). PID `18113` gagal segera dengan ServerNotRunningError;
PID `18458` gagal dari Frida sendiri pada 5,661 detik dengan
ProcessNotRespondingError “unexpectedly timed out trying to sync up with agent”.
Jadi menaikkan batas Python saja belum memperbaiki sinkronisasi agent. Run runner
PID `18273` juga timeout 5 detik meski server dan app masih tercatat saat diagnostic.

Server kini menyimpan stdout/stderr ke `/data/local/tmp/appdome-frida-server.log`,
ditimpa pada launch baru. Runner membaca maksimal 30 baris saat error, sebelum
cleanup; sebelumnya log dibuang. Pada kegagalan PID `18273`, log kosong: tidak ada
pesan server yang menjelaskan timeout. Belum ada bukti penyebabnya server crash.


Readiness server kini mensyaratkan RPC `enumerate_processes()` berhasil, dengan
batas total sekitar 5 detik dan pembatalan per RPC. Keberadaan ADB/Frida device saja
tidak lagi cukup. Startup server dipindahkan ke blok try/finally runner agar kegagalan
startup juga masuk cleanup. Sepuluh tes regresi lulus, termasuk device tersedia tetapi
server RPC belum siap. Uji langsung PID `17250` berhasil handshake lalu timeout pada
attach 5 detik; ini membuktikan readiness saja belum memperbaiki attach/app. Cleanup
selesai, bukan keberhasilan runtime. Bagian historis tentang get_device-only sudah usang.


Pemeriksaan caller lanjutan: observer `libc.exit` dan `libc._exit` pada PID `14035`
tidak mencatat hit sebelum main keluar sekitar 18 detik. Ini konsisten dengan jalur
syscall langsung, tetapi belum membuktikan asal caller. Observer wrapper native
`libloader+0x2ebc94` dengan attach delay 0,5 detik pada PID `14511` juga tidak mendapat
hit dan main keluar sekitar 4 detik. Jangan menyimpulkan wrapper ini tidak dipakai:
instrumentasi dapat mengubah perilaku/timing deteksi. Kedua observer hanya mengamati,
bukan mengganti return value atau menahan exit. Scratch: `/tmp/appdome-exit-caller.py`
dan `/tmp/appdome-native-exit-caller.py`; keduanya selesai dan cleanup dijalankan.

Regresi lifecycle terbaru berjumlah sembilan tes dan lulus. Tes baru memastikan
main hidup di-detach sebelum server dihentikan, sedangkan session dari main yang
sudah hilang tidak di-detach. Belum ada bukti perbaikan runtime aplikasi.


Run interaktif PID `12728` keluar sekitar 21 detik: log Java mengirim SIGKILL
pukul 17:33:17.718 dan 17:33:21.180, kemudian Zygote mencatat exit clean (0)
pukul 17:33:32.826. Klik manual user teramati pada `/dev/input/event0`, tetapi
snapshot dispatcher sudah fokus launcher; belum membuktikan aplikasi menerima klik.
`wm size` saat pemeriksaan berikutnya menunjukkan **1080x2400**; jangan mengandalkan
resolusi 462x1006 dari run lama tanpa pemeriksaan ulang.

Trace raw syscall selanjutnya pada PID `13527` mengonfirmasi TID `13660` (ada dalam
snapshot `/proc/13527/task`) menjalankan `exit_group(0)` sebelum main hilang:
`NR 94 (0, 76770f8670, 40, 2, 0, 30)`. Argumen pertama adalah exit status;
register berikutnya bukan argumen resmi exit_group. Filter guard saat ini memeriksa
slot args[1] terhadap 9, sehingga pola ini lolos. Jangan langsung memblokir seluruh
exit_group: eksperimen sebelumnya sudah menunjukkan risiko freeze setelah exit ditahan.
Langkah berikutnya ialah mencari caller/produser hasil deteksi pada thread ini.

Scratch `/tmp/appdome-exit-trace.py`, `/tmp/appdome-exit-trace.txt`, dan
`/tmp/appdome-exit-run.txt` memuat trace tersebut. Instance tracing khusus sudah dihapus.
Host scratch abort saat detach setelah cleanup mematikan server, dengan assertion
`_frida_device_release_session_co: session_id != null`. Runner utama kini mencoba
detach sebelum cleanup hanya bila main PID masih ada; bila PID hilang, tidak mencoba
detach session lama. Perubahan lifecycle ini belum membuktikan UI/aplikasi stabil.

## Status runtime terbaru — 17:22 WIB

`run.py` sekarang menyediakan:

```sh
/Users/rahmatafriyanton/.pyenv/versions/frida-16.5.2/bin/python run.py --interactive
```

Mode ini melakukan launch normal dan attach segera tanpa jeda `0,8` detik.
JavaScript hanya memasang termination guard native, lalu mengirim
`appdome-ready`; mode ini **tidak** menjalankan `Java.perform`,
`disableEnforcementDecision()`, `monitorUi()`, hook
`Activity.dispatchTouchEvent`, atau heartbeat main thread. Runner tetap
memeriksa session dan PID, tetapi sengaja tidak memakai heartbeat pada mode
interaktif. Perilaku default dan `--verify-only` tetap memakai instrumentasi UI.

Delapan tes `test_run.py` lulus, `node --check frida-force-clean.js` lulus, dan
IDE tidak melaporkan lint error. Ini hanya memverifikasi lifecycle runner dan
konfigurasi skrip, bukan keberhasilan runtime aplikasi.

Hasil runtime mode interaktif:

- Beberapa run dengan attach tertunda hidup sekitar 23–24 detik lalu main PID
  keluar.
- Spawn-suspended tidak cocok: PID spawn menjadi bootstrap, kemudian activity
  berpindah ke PID lain yang tidak ter-hook.
- Attach langsung tanpa Java menghasilkan satu run PID `7198` yang bertahan
  `106,664` detik. Saat gagal, diagnostic melihat server PID `7818` dan app PID
  pengganti `7835`; PID awal/session tidak lagi valid, sehingga run tetap
  dinyatakan gagal.
- Replay konfigurasi yang sama pada PID `8242` hanya bertahan `22,651` detik.
  Hasil 106 detik belum reproducible dan masih timing-dependent.
- Satu percobaan attach gagal bahkan sebelum script load karena `frida-server`
  ditutup selama jeda attach.

Resolusi emulator saat ini `462x1006`. Koordinat lama `970,2180` berada di luar
layar dan tidak boleh dipakai sebagai bukti interaksi. ADB tap pada `230,912`
berhasil menutup modal “Sistem Dalam Pemeliharaan”, lalu tap `414,952`
memunculkan loading tab Akun. Namun user melaporkan sentuhan manual tetap tidak
berfungsi; perubahan layar lewat ADB **bukan bukti bahwa goal klik manual sudah
tercapai**.

Status akhir: mode interaktif sudah menghilangkan seluruh hook Java/UI, tetapi
aplikasi belum terbukti menerima sentuhan manual secara stabil dan PID masih
keluar secara nondeterministik. Langkah berikutnya harus membedakan event input
kernel, dispatch Android, dan respons Flutter pada run yang sama, sekaligus
merekam penyebab exit PID awal. Jangan menambah hook main-thread sebelum sumber
freeze diketahui.

## Temuan terbaru — baca sebelum mencoba perubahan lain

Pembaruan lanjutan pada runner: `frida_call()` memakai `frida.Cancellable` dan timer
untuk attach/create/load (5 detik per operasi), serta detach (2 detik). Setup yang
gagal mencoba detach tanpa menutupi exception asli. Enam tes regresi lulus, termasuk
pembatalan RPC yang tertahan dan detach setelah script load gagal. Ini memperbaiki
lifecycle host, belum menyelesaikan crash aplikasi; force-stop cleanup dan strategi
native/freeze lama masih perlu diganti setelah kandidat terbukti.

Percobaan dispatcher berikutnya, PID `15966`, berhasil attach/load dan mencatat
event `136` (`0x88`) lalu `137` (`0x89`) pada pointer objek yang sama. Snapshot 160 byte
keduanya identik dalam log. Event `138` tidak tertangkap; kemudian main-dead. Belum
ada heartbeat UI pada run ini. Isi struktur dan penyebab kematian belum dipastikan.
`/tmp/appdome-event-diag.py` sudah memakai operasi Frida berbatas waktu dan finally
cleanup; hasil ini menggantikan status “belum pernah terpasang” untuk eksperimen
tersebut, tetapi tidak mengubah fakta attach timeout pada run PID `15378` sebelumnya.


**Belum ada sanitizer yang terbukti berhasil.** Eksperimen terbaru dilakukan dengan
Frida 16.5.2, biasanya tanpa patch RET native dan tanpa pembekuan child. File produksi
`run.py` dan `frida-force-clean.js` sekarang memuat termination guard dan mode
`--interactive` yang dijelaskan di atas, tetapi keduanya belum merupakan solusi final.
Jangan menyamakan log `appdome-ready` atau beberapa heartbeat dengan keberhasilan.

### Hasil deteksi yang benar-benar terlihat

Hook observasi pada
`tkIz24.lgH6M2.yiWzn5.qHIoU1(String, String, boolean, boolean, String, String)`
menangkap pesan berikut pada PID `14282`:

- Ancaman umum: judul `Security Threat Detected by App`, Support REF `7215`.
- Frida: judul `Frida Detected by App`, Support REF `7228`.
- Root: judul `Rooted Device Detected by App`, Support REF `6901`.
- Magisk: judul `Magisk Detected by App`, Support REF `6908`.
- Frida lagi: judul yang sama, Support REF `6905-1`.
- ADB: judul `ADB Detected by App`, Support REF `6906`.

Argumen ketiga/keempat yang tertangkap adalah `true, false`. Argumen pertama berisi
pesan akan menutup aplikasi; kedua adalah judul; kelima string kosong; keenam kode
support yang sebagian berubah antar-run. Ini bukti pesan yang dikirim aplikasi,
**bukan pemetaan resmi semua policy Appdome atau bukti lokasi detektor aslinya**.
Jangan menganggap dua REF Frida berasal dari satu cek yang sama.

PID `14664`: meneruskan panggilan asli dengan argumen ketiga diubah menjadi `false`,
tanpa native patch, freeze child, atau hook decision lama, **tetap berakhir main-dead**
setelah sekitar empat heartbeat. Pengubahan flag pada lapisan pesan saja tidak cukup.
Makna lengkap dua boolean belum dibuktikan; jangan menyebut ini sanitizer final.

Refleksi menunjukkan class `buNKX9` mempunyai `shouldFinishActivities`,
`currentActivitiesCount`, dan `activitiesCountLock`. Class `yiWzn5` memiliki field
`UserIndicationPopup_private_static_isExitingAfterToast`,
`UserIndicationPopup_private_static_isWaitingForToastCallback`, `toastStack`,
`persistentMessage`, dan `waitedMessage` (tiga nama terakhir juga memakai prefix
`UserIndicationPopup_private_static_`). Ini konsisten dengan lapisan UI/enforcement;
belum membuktikan sumber hasil deteksi berada di class tersebut.

### Bukti terminasi native menyasar thread Frida

Trace kernel `/tmp/appdome-kernel-trace.txt`, run main PID `10691`, berisi:

```text
sender TID 10921: sig=9 code=0  comm=Thread-21 pid=10924 grp=1
sender TID 10919: sig=9 code=-6 comm=gmain     pid=10891 grp=0
```

Pada format event `signal_generate`, PID setelah `comm` adalah target, sedangkan
PID di kolom TASK-PID adalah pengirim. `code=-6` konsisten dengan pengiriman
thread-directed (`SI_TKILL`). **Filter target hanya main PID akan melewatkan SIGKILL
ke TID `gmain`; sinyal fatal ke thread juga dapat mematikan seluruh proses.**
Jangan memakai keberadaan child/orphan atau session Frida yang belum detached sebagai
bukti main masih hidup. Trace ini belum memetakan caller native ke offset tertentu.

Trace dibuat dalam instance terpisah:
`/sys/kernel/debug/tracing/instances/appdome_goal_diag`, event
`events/signal/signal_generate`, filter `sig == 9 || sig == 31`.
Opsi `userstacktrace` sudah dicoba tetapi output saat itu tidak memuat user stack.
Instance dinonaktifkan/dihapus setelah run. Direktori `events/syscalls` tidak ada,
tetapi **`events/raw_syscalls/sys_enter` dan `sys_exit` ada**, diverifikasi pada sesi
terbaru. Keberadaannya belum berarti syscall arguments sudah berhasil didekode.

### Jalur JNI/native yang sudah tertangkap

PID `15025`: hook observasi JNI `CallStaticVoidMethodV` (slot 142 tabel JNIEnv,
ARM64) dengan filter `jmethodID == qHIoU1.handle` menangkap backtrace berikut.
Slot 141/142/143 diamati; hit yang tercatat berasal dari slot 142.

```text
libloader.so + 0x17fb60
libloader.so + 0x1f8614
libloader.so + 0x1f7c90
libloader.so + 0x98510
libloader.so + 0x3f3e5c
libloader.so + 0x3f4a64
libloader.so + 0x325168
libc.so!__pthread_start
libc.so!__start_thread
```

Ini alamat frame/return pada backtrace, **bukan otomatis entry fungsi**. Gunakan base
module dari run baru; jangan menyalin alamat absolut ASLR atau `jmethodID` lama.
Disassembly di sekitar `0x3f3e44`–`0x3f3e64` menunjukkan tiga panggilan ke
`0x98468` dengan `w0 = 0x88`, `0x89`, `0x8a`, dan `x1 = x19` yang sama.
Makna tiga event dan struktur `x19` belum diketahui. Jangan menamainya sebagai
“report / popup / kill” tanpa bukti runtime.

Eksperimen selanjutnya yang hendak mengamati argumen `0x98468`, PID `15378`,
gagal **saat attach**, dengan
`frida.ProcessNotRespondingError: unexpectedly timed out trying to sync up with agent`.
Script belum terpasang; tidak ada dump event dari percobaan tersebut. Ini bukan bukti
bahwa hook `0x98468` menyebabkan crash. Scratch itu juga tidak mempunyai finally yang
andal untuk kegagalan attach; periksa dan bersihkan sisa run sebelum mengulang.

### Jalur pembacaan artefak: hasil negatif juga penting

- Observer libc `open/openat/fopen/readlink/readlinkat`, PID `12520`, hanya melihat
  `/proc/self/exe`, `/proc/<tid>/timerslack_ns`, dan `/proc/self/statm` dalam log
  terbatas. Tidak menemukan sumber pembacaan artefak Frida. Ini tidak membuktikan
  aplikasi tidak membaca proc; jalurnya bisa direct syscall atau terjadi sebelum hook.
- `libloader.so` punya wrapper syscall sendiri: `getdents64` `0x2eba8c`,
  `openat` `0x2ebaa4`, `close` `0x2ebabc`, `lseek` `0x2ebb04`,
  `read` `0x2ebb34`, raw `read` `0x2ebb50`, `readlinkat` `0x2ebba4`.
  Offset hanya untuk hash library yang tercantum di bagian environment.
- Observer gabungan wrapper tersebut, PID `12934`, hanya mencatat
  `readlinkat /proc/self/fd/88 -> 11`, tanpa readiness Java; Zygote mengonfirmasi
  SIGSEGV pada `13:09:18.253`. Host menunggu walaupun main sudah mati dan perlu cleanup.
  Penyebab crash belum terisolasi; jangan menganggap semua wrapper aman untuk hook.
- Observer hanya native `openat`, PID `13252`, mencapai readiness lalu main-dead,
  tanpa log pembacaan proc yang relevan.
- Kandidat fungsi `0x447834` dipanggil statis dari fungsi yang memuat callsite
  `tgkill` `0x253a04`. Observer PID `13605` tidak menangkap input/return kandidat
  sebelum main mati. **Belum terbukti fungsi ini detektor Frida.**
- Percobaan mengganti nama thread tidak menghasilkan log keberhasilan rename.
  User telah meminta tidak menyamarkan artefak; jangan meneruskan pendekatan ini.

### Action plan berdasarkan temuan terbaru

1. **Buat harness eksperimen yang bounded terlebih dulu.** Tangani timeout attach,
   create/load script, dan detach; catat PID utama/child, waktu, serta exit dari
   logcat/kernel secara terpisah. Bungkus setup/cleanup dengan `finally` atau gunakan
   proses host terpisah dengan batas waktu. Jangan biarkan `script.load()` yang macet
   membuat semua pengamatan berhenti. Jangan force-stop sampai evidence exit tersimpan.
2. **Lanjutkan dari jalur JNI yang telah terbukti.** Korelasikan setiap pesan/REF dengan
   backtrace dan waktu. Amati `0x98468` satu titik per eksperimen untuk event
   `0x88/0x89/0x8a`; validasi prologue, tipe/pointer, dan batas memori sebelum membaca.
   Bandingkan struktur/flag untuk pesan Frida dan event lain, lalu telusuri produsernya.
   Backtrace hanya menunjukkan jalur pengiriman; cari hasil cek sebelum enforcement.
3. **Pisahkan dua jalur terminasi.** Catat `Process.killProcess` Java dan signal kernel
   termasuk target TID `gmain`. Sanitasi yang hanya menahan toast/Java exit sudah gagal.
   Korelasikan kedua jalur dengan REF dan caller; jangan mengganti semua kill/tgkill/exit
   dengan RET atau menganggap SIGSYS aman.
4. **Jika bukti menunjuk pemeriksaan proc, amati sebelum memfilter.** Gunakan wrapper
   atau raw-syscall tracing secara terarah untuk mengidentifikasi path, FD, thread,
   caller, isi, dan return length yang benar. Callback native yang menghindari kerja
   JavaScript pada jalur panas/fork adalah kandidat untuk diuji, belum solusi teruji.
   Periksa raw wrapper pendek dan instruksi yang direlokasi sebelum memasang Interceptor.
5. **Sanitasi hanya hasil yang sudah dipahami.** Jika berupa status/flag, buktikan enum,
   bitmask, dan konvensi return; ubah hanya hasil deteksi yang dituju. Jika berupa
   buffer proc, pertahankan struktur, ukuran, EOF/error, FD reuse, dan pembacaan bertahap.
   Jangan mengosongkan seluruh buffer atau menulis string melebihi panjang valid.
   Jangan mengganti nama thread/berkas atau memalsukan semua hasil tanpa korelasi.
6. **Uji semua pemicu yang terlihat.** Frida punya setidaknya dua REF berbeda;
   root/Magisk/ADB/ancaman umum juga muncul, dan baseline tanpa Frida sudah mati.
   Catat pemicu yang masih aktif setelah satu kandidat berubah; jangan menyatakan
   Frida sebagai satu-satunya penyebab. Konfigurasi fusion/ThreatScope belum tersedia.
7. **Integrasikan setelah kandidat terbukti.** Ganti strategi broad RET dan blanket
   SIGSTOP yang masih ada di skrip utama; benahi readiness server dan lifecycle cleanup.
   Jalankan regresi verifier, kemudian minimal dua run emulator dengan PID/session
   tetap benar, heartbeat main thread, dan perubahan UI nyata (keyboard saat field
   diketuk, kembali tanpa submit). Amati sekurangnya 60 detik dan ulangi interaksi.
   Goal baru selesai bila aplikasi tidak crash/freeze dan tidak butuh force exit.

### Scratch terbaru dan cara memakainya

Semua berada di `/tmp`, dapat hilang, bukan implementasi final. Baca sebelum menjalankan;
kebanyakan mengimpor `emulator/run.py`, sehingga perilakunya berubah jika runner diedit.
Jangan jalankan seluruh daftar sekaligus atau memakai PID lama.

- `appdome-kernel-signals-diag.py`: signal trace semua target untuk SIGKILL/SIGSYS.
- `appdome-proc-read-diag.py`: observer libc.
- `appdome-native-read-diag.py`: observer native gabungan yang gagal SIGSEGV.
- `appdome-open-diag.py`: observer native openat saja.
- `appdome-candidate-diag.py`: observer `0x447834` tanpa hit.
- `appdome-java-fields-diag.py`: refleksi class/field yang disebut di atas.
- `appdome-message-diag.py`: pesan/REF hasil deteksi terkonfirmasi.
- `appdome-result-diag.py`: percobaan boolean ketiga false, tetap gagal.
- `appdome-jni-diag.py`: backtrace JNI yang berhasil menangkap jalur pesan.
- `appdome-event-diag.py`: kandidat observasi dispatcher, belum teruji karena attach timeout.

Bagian historis berikut dipertahankan untuk konteks; action plan terbaru di atas
mengambil prioritas bila daftar langkah lama mengulang eksperimen yang sudah gagal.

## Pembaruan setelah handoff awal: DNS sehat, baseline dan jalur Java

Bagian ini lebih baru daripada daftar eksperimen awal di bawah.

- **Baseline setelah DNS sehat, tanpa server/attach Frida:** PID `7009` hidup
  pada detik 1–6, tidak ada lagi pada detik 7. Log pukul `12:53:24.968`
  mencatat `Process: Sending signal. PID: 7009 SIG: 9`; Zygote kemudian
  mencatat exit karena signal 9. Pemeriksaan `ps` setelah run tidak menemukan
  `fs64`, `frida-server`, atau proses package. Jadi sekarang telah terbukti
  build juga melakukan terminasi tanpa Frida pada environment emulator ini.
  Jangan menyimpulkan seluruh terminasi hanya disebabkan Frida.
- **Attach tanpa native patch/freeze, logger Java pada Process.killProcess:**
  PID `7646` memiliki empat heartbeat main-thread sebelum terminasi. Stack Java:
  `android.os.Process.killProcess` →
  `tkIz24.mamTp0.kJFy54.buNKX9.qLeOG3` →
  `tkIz24.mamTp0.kJFy54.buNKX9.oIjyT9` →
  `tkIz24.bpfPU2.p1nAp7.oIjyT9` →
  `tkIz24.lgH6M2.yiWzn5$3.run` → Android Handler/Looper.
  Mengembalikan dari hook `killProcess` untuk PID sendiri belum mencegah
  kematian. Pemicu terminasi berikutnya belum tertangkap.
- **Hook Java lama saja, tanpa native patch/freeze, DNS sehat:** PID `8125`
  memiliki empat heartbeat, kemudian `enforcement-skipped: false`, lalu mati.
  Jadi callback tersebut saja bukan solusi, sekalipun UI sempat responsif.
- **Hook Java lama + freeze child, seluruh native patch dinonaktifkan:**
  PID `8664` tetap mati; child `8816` dibekukan. Ini juga bukan solusi.
- **Hook dispatcher Java yang lebih atas:** `tkIz24.bpfPU2.p1nAp7.oIjyT9`
  memiliki overload `()`, `(android.content.Context)`, dan
  `(android.content.Context, java.lang.Boolean)`, semuanya return void.
  Mengganti ketiganya pada eksperimen PID `9208` belum berhasil; empat heartbeat
  tercatat, lalu main mati tanpa log callback dispatcher-skipped.
- JADX `--single-class tkIz24.mamTp0.kJFy54.buNKX9` terhadap APK gagal menemukan
  class tersebut. Asset `assets/KYdUbMzmQTG/WeKTWWTGWm.dex` tidak terbaca.
  Menonaktifkan checksum dengan `-P dex-input.verify-checksum=no` juga gagal
  (buffer position di luar ukuran). Jangan mengulang dua command itu dengan
  input identik dan mengharapkan source class langsung tersedia.

Scratch tambahan: `/tmp/appdome-java-exit-diag.py`,
`/tmp/appdome-java-only-freeze.js`, `/tmp/appdome-dispatch-diag.py`, serta
`/tmp/appdome-postdns-baseline.png`. Semua eksperimen telah selesai dan cleanup
runner dijalankan; baseline tanpa Frida tidak memakai cleanup force-stop.

Pertanyaan telah diajukan kepada user mengenai konfigurasi Appdome untuk
emulator/root/Frida atau nama event ThreatScope. Saat pembaruan ini ditulis
belum ada jawaban. Jangan mengarang nama policy/event dari pola crash saja.

## Environment yang telah diverifikasi

- Workspace: `/Users/rahmatafriyanton/Documents/LiveDemo/PLN/POC/AppDome`.
- Emulator: `emulator-5554`, Android 10, `arm64-v8a`, root tersedia melalui Magisk `su`.
- Package: `com.app.plnmobile`.
- Activity: `com.app.plnmobile/.MainActivity`.
- APK lokal: `../9rC2vJ5pB7.apk`. Aplikasi sudah terinstall; investigasi tidak
  memerlukan install ulang, clear data, atau login dengan akun nyata.
- Frida Python terverifikasi versi `16.5.2`.
- Python setelah memilih environment:
  `/Users/rahmatafriyanton/.pyenv/versions/frida-16.5.2/bin/python`.
- Server: `/data/local/tmp/frida-server-16.5.2`.
- Runner menyalinnya ke `/data/local/tmp/fs64`, menjalankan dengan `-P`.
  `-P` berarti **disable preload**, bukan stealth mode.
- `r2`, `jadx`, Node, serta Android NDK tersedia di host.
- SHA-256 `lib/arm64-v8a/libloader.so` dari APK lokal **sama** dengan library
  terinstall, telah diperiksa lewat root:
  `080cd6f86c9473a7699901f3d24b64c42deeda838e33399a28b14a137071bd9e`.

Perintah dari root workspace, di shell zsh:

```sh
eval "$(pyenv init - zsh)"
pyenv shell frida-16.5.2
python -c 'import frida, sys; print(sys.executable); print(frida.__version__)'
```

## File dan perubahan yang sudah dibuat

### `run.py`

- Command subprocess normal diberi timeout 10 detik.
- `install_hooks()` kini mengembalikan `(session, script, health)`, bukan hanya session.
  Referensi script disimpan selama runner berjalan.
- `health` menyimpan waktu heartbeat main thread, jumlah sentuhan yang diakui,
  serta error JavaScript.
- `require_alive()` memeriksa PID utama secara independen dari koneksi Frida,
  lalu error skrip dan heartbeat main thread.
- Mode interaktif tidak lagi menunggu selamanya tanpa pemeriksaan proses.
- `verify()` memeriksa survival, heartbeat, fokus, dan kenaikan counter touch
  setelah `adb input tap 200 580`.
- Cleanup subprocess diberi timeout 5 detik dan tetap mencoba command berikutnya
  jika command sebelumnya timeout.

**Perilaku lama yang masih ada dan harus dievaluasi:**

- `monitor_watchdogs()` masih mengirim `SIGSTOP` ke setiap PID lain bernama package
  yang sama. Identitas “watchdog” belum dibuktikan untuk setiap PID. Ini berisiko
  membekukan proses yang dibutuhkan aplikasi. Jangan menganggap strategi ini benar.
- Launch memakai `am force-stop`, `am start`, lalu menunggu 0,8 detik sebelum attach.
- `cleanup()` masih melakukan `am force-stop` terhadap aplikasi dan mematikan
  server `fs64`, termasuk setelah `--verify-only` atau Ctrl+C.
- Readiness server hanya memakai `frida.get_device()`, belum membuktikan handshake
  server dengan operasi yang benar-benar memakai server.
- Callback detach, propagasi error thread monitor, kegagalan install hook sebelum
  return, dan jalur diagnostic saat ADB disconnect masih perlu dirapikan.
- String `[ready]` berarti hook telah dipasang; belum membuktikan UI sudah responsif.

### `frida-force-clean.js`

- Ditambah pemeriksaan arsitektur arm64 dan instruksi asli sebelum patch native.
  Pemeriksaan semua alamat dilakukan sebelum mulai menulis patch.
- Inisialisasi Java memakai `Java.perform`; error setup dikirim ke Python.
- Ditambah probe main thread setiap 1 detik via `Java.scheduleOnMainThread()`.
  Maksimal satu probe pending agar main thread macet tidak menumpuk antrean probe.
- Ditambah counter setelah `Activity.dispatchTouchEvent()` kembali pada ACTION_UP.
- Hook Java lama masih menonaktifkan method:
  `tkIz24.mamTp0.kJFy54.buNKX9.oIjyT9(android.app.Activity, java.lang.Boolean)`.

**Patch native lama masih ada, bukan perbaikan yang telah terbukti:**

- `exit_group`: offset `0x2ebc94`, instruksi asli `0xd2800bc8`.
- `tgkill`: offset `0x2ebcac`, instruksi asli `0xd2801068`.
- `kill`: offset `0x2ebde4`, instruksi asli `0xd2801028`.
- Instruksi kedua masing-masing `svc #0` / `0xd4000001`.
- Ketiga entry tersebut masih diganti dengan `RET` (`0xd65f03c0`).

Mengganti syscall tersebut dengan RET secara umum tidak aman: tidak menetapkan
return value yang benar, memblokir seluruh jenis sinyal, dan dapat melanggar
kontrak fungsi yang seharusnya tidak kembali. Disassembly menunjukkan caller
`exit_group` di `0x2e5244` diikuti kode fungsi berikutnya di `0x2e5248`, tanpa
epilogue normal untuk kembali dari `_exit`. Ini merupakan risiko konkret, tetapi
**belum terbukti sebagai satu-satunya sumber SIGSEGV** pada pengujian ini.

### Tes lokal

`test_run.py` memiliki empat regression test:

1. PID utama mati walaupun session Frida masih attached dan child tersisa.
2. PID hidup tetapi heartbeat main thread berhenti.
3. Window fokus dan command tap berhasil tetapi touch tidak diakui aplikasi.
4. Cleanup tetap lanjut setelah timeout ADB.

Semua lulus; tes pemilihan device lama di `archive/test_run.py` juga lulus, begitu
juga syntax check JS. Jalankan dari root workspace:

```sh
eval "$(pyenv init - zsh)"
pyenv shell frida-16.5.2
python -m unittest discover -s emulator -p 'test_run.py' -v
python emulator/archive/test_run.py
node --check emulator/frida-force-clean.js
```

Tes ini **bukan bukti** bahwa aplikasi sudah bisa dipakai.

## Temuan runtime yang sudah terbukti

### False PASS pada verifier lama

Sebelum perubahan, `--verify-only` mencetak PASS setelah sekitar 13 detik walaupun
proses utama sudah mati. Window aplikasi masih tertinggal, session Frida belum
detached, dan ada proses lain bernama package yang sama.

Contoh PID utama `24160` dan `25194`: main tidak ada lagi di `/proc`, sementara
child dengan PPID 1 berstatus `T` setelah dibekukan. Android mencatat SIGSEGV;
`dumpsys input` menunjukkan input tidak diproses dan ANR dengan latency sekitar
5 detik. Screenshot login/loading yang terlihat bukan bukti aplikasi hidup.

Hubungan child yang mewarisi koneksi dengan session Frida yang tetap attached
masuk akal, tetapi mekanisme pewarisannya belum diverifikasi. Fakta yang pasti:
`session.is_detached == False` tidak cukup sebagai bukti survival main PID.

### DNS sebelum dan sesudah restart

Sebelum restart:

- Ping `8.8.8.8` berhasil, tetapi `google.com` menghasilkan `unknown host`.
- Network emulator menggunakan DNS `10.0.2.3`.
- Main thread setelah attach teramati menunggu `unix_stream_read_generic`.
- Native stack memuat `libc!fread`, `android_getaddrinfofornetcontext`, dan
  frame `libloader.so`, antara lain offset `0x20de04`, `0x20e4e0`, `0x464788`,
  `0x46b1ac`, `0x46ad64`, `0x46a8bc`.
- Pengamatan getaddrinfo pada eksperimen spawn mencatat `127.0.0.1` dan
  `analytics.appdome.com`. Tidak dibuktikan bahwa seluruh loading UI berasal
  dari DNS, atau bahwa memperbaiki DNS akan memperbaiki crash Frida.

User restart emulator sendiri. Setelah mengatakan “sudah”:

- Boot completed = 1.
- `ping -c 1 -W 2 google.com` berhasil, resolve `142.251.12.101`, sekitar 35 ms.
- Runner tetap gagal karena main PID mati. Jadi **jangan mengulang dugaan bahwa
  DNS adalah solusi penuh crash Frida**.
- Tidak ada perubahan DNS, iptables, private DNS, atau jaringan permanen oleh agent.

## Eksperimen yang sudah dilakukan — jangan ulang tanpa hipotesis baru

Mayoritas eksperimen awal dilakukan sebelum restart/DNS pulih. Jangan menganggap
timing tersebut universal. Eksperimen scratch tidak menjadi implementasi final.

1. **Runner asli dengan freeze + tiga RET native + hook Java.** Main mati dengan
   SIGSEGV; verifier lama memberi PASS palsu. Verifier baru menolak kondisi ini.
2. **Tanpa freeze, patch/hook lama tetap aktif.** PID utama tetap mati sekitar
   4–6 detik. Jadi menghapus SIGSTOP saja belum menyelesaikan masalah.
3. **Tanpa Frida server dan tanpa attach.** Main hidup sampai observasi 12 detik,
   kemudian log menunjukkan exit clean sekitar 20 detik. Jangan menyebut baseline
   ini sukses stabil; pengamatan awal yang hanya 12 detik terlalu pendek.
4. **Frida server saja, tanpa attach, pada launch baru.** Main hidup sekitar
   18 detik lalu tidak ada pada detik 19. Ini berbeda dari kematian cepat setelah attach.
5. **Attach tanpa JavaScript.** Main mati sekitar 4 detik setelah attach;
   `session.is_detached` masih False. Menunjukkan masalah tidak hanya disebabkan
   isi JavaScript lama.
6. **Attach dengan logger exception dan timer JS minimal.** Timer JS bisa berjalan;
   callback main-thread tidak tiba. Pada salah satu run main mati dengan SIGKILL,
   tanpa laporan `Process.setExceptionHandler`. Jangan berharap handler JS menangkap SIGKILL.
7. **Memulai monitor freeze lebih awal.** Tetap main mati; belum memulihkan heartbeat.
8. **Hanya patch wrapper kill; patch exit_group dan tgkill dihapus, freeze masih aktif.**
   Tetap SIGSEGV.
9. **Interceptor wrapper signal, ubah fatal signal menjadi signal 0, tanpa freeze.**
   Main tetap mati; tidak ada laporan callback wrapper yang cukup menjelaskan sumbernya.
10. **Attach child yang sudah ada lebih dahulu, patch callsite native, lalu attach main,
    tanpa freeze.** Tetap main mati. Bukan solusi; belum ada heartbeat UI.
11. **Attach lebih cepat tanpa delay 0,8 detik, hanya Java hook.** Main tetap mati
    sekitar 5 detik. Hook terpasang bukan bukti main-thread responsif.
12. **Spawn + Java hook + logging getaddrinfo.** Main mati sekitar 4 detik;
    terlihat lookup `analytics.appdome.com`.
13. **Setelah DNS pulih, runner file saat ini.** PID `5215` mati; sempat ada
    `enforcement-skipped` dengan flag `false`. Child `5352`, `5495`, `5529`
    dibekukan. `--verify-only` gagal, sebagaimana mestinya.
14. **Spawn + patch native sebelum constructor library.** Hook symbol linker
    `__dl__ZN6soinfo17call_constructorsEv` berhasil memasang patch sebelum constructor.
    Dua varian (dengan/tanpa patch callsite sinyal 31) sama-sama membuat PID awal
    mati dengan SIGSEGV kurang dari sekitar 1 detik. PID `5997` dan `6414`.
    Java-ready tidak tercapai pada run ini. **Bukan solusi yang boleh dipromosikan.**
15. **Seccomp guard terarah pada scratch spawn.** Guard menolak self
    `kill/tgkill(SIGKILL)` dan pola `exit_group` Appdome tanpa patch kode native.
    Run 14:36 melaporkan PID `10316` bertahan selama observasi 25 detik. Replay
    kemudian tetap mencatat main PID keluar; exit code harness `0` hanya berarti
    script selesai, bukan aplikasi stabil.
16. **Integrasi seccomp guard ke runner normal.** Patch RET dan pembekuan watchdog
    dihapus. Beberapa run mencapai sekitar 22–23 detik, tetapi PID utama tetap
    keluar. Java `enforcement-skipped` dapat muncul sebelum exit.
17. **Guard instruction/return-address dan self-check wrapper.** Kandidat
    `exit_group` wrapper berada di `libloader+0x2ebc94`, syscall return PC
    `+0x2ebc9c`. Satu run dengan `exit-group-probe` bertahan 77 detik, tetapi ADB
    tap timeout dan tidak membuktikan UI responsif. Varian exact-PC yang menahan
    exit juga pernah membuat main/Flutter freeze.
18. **Full sustained verification 14:49.** Main masih terdaftar sekitar 49 detik,
    lalu Frida abort dengan assertion session. `FlutterSharedPreferences.xml`
    berubah pukul 14:50, tetapi isinya hanya FCM token; timestamp tersebut bukan
    bukti login/OTP berhasil. Replay konfigurasi historis biasanya mati sekitar
    22–24 detik.
19. **Pemetaan subscriber event.** Runtime mencatat event `137` ke callback
    `0x19c4d4` dan `0x1f8100`, event `136` ke `0x3d68ac` dan `0x460c78`, serta
    event `138` ke `0x3d6d10`. Run bertahan sampai tahap tap setelah 60 detik,
    tetapi perintah input timeout.
20. **Spawn-first / pre-resume guard.** Guard dipasang sebelum protected
    initialization. Pada build ini PID spawn dapat menjadi bootstrap lalu activity
    berpindah ke PID baru yang tidak ter-hook. Verifier tidak boleh menerima PID
    pengganti tersebut sebagai keberhasilan.
21. **Instrumentasi Java ditunda.** Tes lifecycle lokal lulus, tetapi runtime
    tidak menghasilkan kandidat stabil. Menunda hook tidak menghilangkan deteksi
    attach/native.
22. **Trace producer toast Java.** `Toast.show()` ditelusuri ke
    `tkIz24.lgH6M2.yiWzn5.wRt0D8`, `sQadi7`, dan `yiWzn5$2.run`; entry publiknya
    `qHIoU1(String,String,boolean,boolean,String,String)`. Argumen boolean ketiga
    terkonfirmasi `shouldExit=true` untuk Root, Virtualization, Frida, Magisk,
    ADB, dan ancaman filesystem.
23. **Varian sanitasi toast.** Menghapus `qHIoU1` sepenuhnya menghilangkan toast
    tetapi UI freeze sekitar 12 detik. Memanggil original dengan string kosong dan
    boolean false membanjiri antrean toast lalu proses keluar sekitar 23 detik.
    Satu toast kosong dan drop duplikat tetap freeze saat enforcement downstream
    ditahan.
24. **Trace terminasi Java.** Jalur
    `yiWzn5$3.run -> p1nAp7.oIjyT9 -> buNKX9.oIjyT9/qLeOG3 ->
    Process.killProcess(main PID)` terkonfirmasi. No-op hanya pada
    `Process.killProcess(main)` tidak cukup karena watchdog native tetap mengakhiri
    proses sekitar 22–23 detik.
25. **Scan halaman policy.** Modifikasi luas menyebabkan lifecycle freeze.
    Mengubah config byte `+106` menjadi `0` terbukti salah secara semantik; pada
    konfigurasi normal `[+105,+106,+107] == [0,1,0]`, perubahan tersebut membuat
    gate mengembalikan false dan dapat mendorong enforcement.
26. **Analisis IDA hasil deteksi.** `sub_3FE2D4` di `0x3fe2d4` menganggap hasil
    clean/true bila `a2 == 1` untuk konfigurasi normal. `sub_3F380C` menyimpan
    `a2` di payload `+177` dan `a3` di `+178`, lalu menerbitkan event
    `0x88/0x89/0x8a`. Kandidat sanitizer tersempit adalah menulis
    `payload[177] = 1` pada event `0x88`.
27. **Native one-byte result sanitizer.** CModule meng-hook dispatcher
    `libloader+0x98468` dan menulis byte di atas. Hook itu sendiri memicu exit
    cepat sekitar 7 detik, sehingga belum membuktikan nilai hasil salah; inline
    Interceptor terdeteksi sebelum kandidat bisa diverifikasi.
28. **Perbandingan callback dispatcher.** Attach delay memengaruhi hasil.
    Dalam satu run callback native menghitung event `0x88`, `0x89`, dan `0x8a`
    serta heartbeat sempat berjalan, tetapi proses kemudian SIGSEGV pada thread
    aplikasi. Event `0x8a` bukan bukti langsung sebagai perintah kill.
29. **Pemulihan versi historis satu per satu.** Varian pukul 14:47 dan 14:49
    direkonstruksi dari transcript/terminal, termasuk delay `0,8`, guard, probe,
    dan `enforcement-skipped`. Hasil lama 49/77 detik tidak reproducible secara
    konsisten; sebagian replay gagal saat `script.load`, sebagian mati 22–24 detik.
30. **Mode `--interactive` dengan Java enforcement hook tetapi tanpa monitor UI.**
    ADB dapat menutup modal pemeliharaan dan memunculkan loading tab Akun, tetapi
    user tetap melaporkan layar tidak bisa diklik manual. Main PID keluar sekitar
    23–24 detik.
31. **Mode interaktif tanpa seluruh hook Java.** Spawn-suspended membuat PID
    bootstrap keluar sekitar 3 detik dan activity pindah ke proses lain. Launch
    normal + attach segera menghasilkan satu run 106,664 detik, tetapi replay
    identik hanya 22,651 detik. Hasil tetap nondeterministik dan klik manual belum
    terkonfirmasi.
32. **Koreksi koordinat input.** Resolusi emulator berubah menjadi `462x1006`;
    koordinat lama `970,2180` tidak valid. Koordinat ADB yang terlihat bekerja
    adalah sekitar `230,912` untuk modal dan `414,952` untuk tab Akun. ADB input
    tidak boleh dipakai sebagai pengganti bukti sentuhan manual.

Koreksi penting untuk eksperimen terakhir: setelah PID `6414` crash, ActivityManager
menjalankan PID baru `6512` untuk activity yang sama. Ini terverifikasi di log:

```text
12:49:21.358 Zygote: Process 6414 exited due to signal 11 (Segmentation fault)
12:49:21.390 ActivityManager: Start proc 6512:com.app.plnmobile/... for activity ...
12:49:22.032 ActivityTaskManager: Displayed com.app.plnmobile/.MainActivity
```

Eksperimen kemudian menjalankan cleanup dan menutup `6512`. **Bukan bukti bahwa
PID awal adalah bootstrap yang sukses, atau proses baru itu responsif/instrumented.**
Jangan mengubah verifier agar menerima sembarang PID pengganti tanpa memeriksa
session, pemilik activity/window, dan hook di proses baru.

## Catatan native dan batas kesimpulan

Disassembly statis library menunjukkan pemanggil `tgkill`:

- `0x11e334`: argumen signal 0, yaitu pemeriksaan keberadaan thread.
- `0x253a04`: argumen signal 9.
- `0x29ca48`: argumen signal 31.

Pemanggil `kill` dengan argumen 9 terlihat di `0x1e0ac0`, `0x1e0cbc`, `0x1e3200`,
`0x1e35e4`, `0x1e4248`, `0x1e46c0`.

Eksperimen mengganti callsite tersebut dengan `mov w0, #0` belum berhasil.
Jangan menambahkan offset ini ke implementasi final hanya karena tersedia.
Alamat hanya berlaku untuk hash library di atas.

Penjelasan sementara sebelumnya bahwa sinyal 31 adalah “sinyal nonfatal untuk
sinkronisasi” **belum terbukti dan tidak boleh dianggap fakta**. Pada Android arm64,
31 adalah SIGSYS; aplikasi dapat memasang handler sendiri. Fungsi persisnya di
build ini belum dipastikan. Caller dan argument statis tidak membuktikan peran runtime.

Demikian pula, jangan langsung menyimpulkan semua SIGSEGV adalah deteksi Appdome,
atau semua berasal dari RET exit_group. Attach minimal juga gagal; sedangkan
patch dini bisa menambah masalah tersendiri. Perlu stack/crash evidence yang tepat.

## Scratch yang mungkin masih tersedia di host

File berikut berada di `/tmp`, **tidak durable dan bukan sumber kebenaran final**:

- `appdome-run-original.py`, `appdome-frida-original.js`: snapshot sebelum edit.
- `appdome-libloader.so`: library yang diekstrak dari APK; hash tercantum di atas.
- `appdome-linker64`: salinan `/system/bin/linker64`.
- `appdome-before.png`: screenshot lama yang terlihat hidup tetapi main sudah mati.
- `appdome-signal-diag.py`, `appdome-child-diag.py`, `appdome-stack-diag.py`.
- `appdome-early-diag.py`, `appdome-spawn-diag.py`.
- `appdome-early-native.py`, `appdome-early-native.js`: eksperimen terakhir yang gagal.
- `appdome-diag.js`, `appdome-kill-only.js`.

Sebagian script memiliki cleanup yang force-stop aplikasi. Baca sebelum menjalankan;
jangan menjalankan ulang seluruh scratch sebagai test suite. PID dan alamat ASLR
yang tertulis di transcript/scratch tidak boleh dipakai ulang pada launch baru.

## Langkah berikutnya yang berguna

1. Ambil evidence crash terbaru yang membedakan **attach minimal**, hook Java,
   patch native, serta pembekuan child pada kondisi DNS yang sekarang sehat.
   Ulangi hanya variabel yang perlu, dengan waktu, PID/PPID, dan alasan exit tercatat.
2. Identifikasi pemilik activity/window dari Android, bukan hanya `pidof` atau
   nama proses. Catat restart oleh ActivityManager; jangan diam-diam berpindah
   ke proses baru lalu mengklaim session awal berhasil.
3. Ambil native stack/tombstone yang benar-benar milik package dan run terbaru.
   Banyak tombstone lama di emulator milik aplikasi lain; jangan campur sebagai evidence.
4. Hapus/ganti strategi RET pada fungsi non-returning dan blanket SIGSTOP berdasarkan
   hasil analisis, bukan dengan terus menambah no-op/fatal-signal suppression.
5. Setelah kandidat fix bekerja, rapikan lifecycle: readiness server nyata,
   setup/detach/error yang bounded, cleanup tidak menutupi error asli, serta
   definisi keluar dari runner yang sesuai kebutuhan aplikasi tetap berjalan.
6. Verifikasi UI secara nyata: klik field nomor HP hingga keyboard muncul,
   tutup keyboard/kembali tanpa submit/login, dan ulangi interaksi setelah masa
   observasi melewati waktu kematian yang sudah terlihat (sekitar 20 detik).
   Jangan login atau mengirim nomor telepon sebagai bagian tes.

Command read-only dasar untuk pemeriksaan berikutnya:

```sh
adb devices
adb -s emulator-5554 shell getprop sys.boot_completed
adb -s emulator-5554 shell service check activity
adb -s emulator-5554 shell ps -A -o PID,PPID,STAT,NAME
adb -s emulator-5554 shell dumpsys activity activities
adb -s emulator-5554 shell dumpsys input
```

Setelah restart, pernah ada transien `Can't find service: activity` walaupun
`sys.boot_completed` sudah 1; recheck service, bukan langsung menyimpulkan crash app.

## Kriteria selesai

- Environment benar-benar Frida 16.5.2 sesuai permintaan user.
- Aplikasi terinstall berjalan dengan hook yang dimaksud, main PID/session yang
  benar, dan tidak hanya menampilkan stale window atau restart tanpa hook.
- Main thread dan event sentuh responsif, dengan bukti perubahan UI nyata.
- Tidak muncul ANR/crash/exit selama observasi dan beberapa interaksi.
- Tidak memerlukan force exit untuk memulihkan layar setelah menjalankan skrip.
- Tes lokal relevan lulus, dan klaim hasil dibatasi pada skenario runtime yang diuji.

Saat handoff tidak ada proses Python eksperimen/runner yang ditemukan aktif oleh
`pgrep`. Jangan menganggap status emulator, server, atau PID lama masih sama;
periksa ulang sebelum melanjutkan. Goal belum ditandai selesai atau paused.
