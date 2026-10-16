'use strict';

const MESSAGE = 'Appdome — Frida injected';
const TLS_PATTERN =
  'F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9';
let shown = false;
let tlsPatched = false;
let tlsAttempts = 0;
let tlsReplacement = null;

function installFlutterTlsBypass() {
  if (tlsPatched || tlsAttempts++ >= 30) return;

  const flutter = Process.findModuleByName('libflutter.so');
  if (flutter === null) {
    setTimeout(installFlutterTlsBypass, 250);
    return;
  }

  const matches = [];
  const flutterEnd = flutter.base.add(flutter.size);
  for (const range of Process.enumerateRanges('r-x')) {
    if (
      range.base.compare(flutter.base) < 0 ||
      range.base.compare(flutterEnd) >= 0
    ) {
      continue;
    }
    matches.push(...Memory.scanSync(range.base, range.size, TLS_PATTERN));
  }

  if (matches.length !== 1) {
    send({ tag: 'flutter-tls-bypass-failed', matches: matches.length });
    return;
  }

  tlsReplacement = new NativeCallback(function () {
    return 0;
  }, 'int', ['pointer', 'int']);
  Interceptor.replace(matches[0].address, tlsReplacement);
  tlsPatched = true;
  send({
    tag: 'flutter-tls-bypass-active',
    offset: matches[0].address.sub(flutter.base).toString(),
  });
}

function showIndicator() {
  if (shown) return;

  Java.choose('com.app.plnmobile.MainActivity', {
    onMatch(activity) {
      if (shown) return;
      shown = true;
      Java.scheduleOnMainThread(function () {
        const Toast = Java.use('android.widget.Toast');
        const Builder = Java.use('android.app.AlertDialog$Builder');
        const JString = Java.use('java.lang.String');
        const title = JString.$new(MESSAGE);
        const message = JString.$new(
          'Frida berhasil attach ke aplikasi yang diproteksi Appdome. ' +
            'Flutter TLS pinning: ' +
            (tlsPatched ? 'bypass aktif.' : 'hook belum ditemukan.')
        );
        Toast.makeText
          .overload(
            'android.content.Context',
            'java.lang.CharSequence',
            'int'
          )
          .call(Toast, activity, title, Toast.LENGTH_LONG.value)
          .show();
        const dialog = Builder.$new(activity);
        dialog.setTitle(title);
        dialog.setMessage(message);
        dialog.setPositiveButton
          .overload(
            'java.lang.CharSequence',
            'android.content.DialogInterface$OnClickListener'
          )
          .call(dialog, JString.$new('OK'), null);
        dialog.show();
        send({
          tag: 'frida-injected',
          pid: Process.id,
          tlsBypass: tlsPatched,
        });
      });
    },
    onComplete() {},
  });
}

installFlutterTlsBypass();

Java.perform(function () {
  showIndicator();
  const timer = setInterval(function () {
    if (shown) {
      clearInterval(timer);
      return;
    }
    showIndicator();
  }, 250);
});
