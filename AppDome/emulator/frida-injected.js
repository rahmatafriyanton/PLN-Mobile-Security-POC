'use strict';

const MESSAGE = 'Appdome — Frida injected';
let shown = false;

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
          'Frida berhasil attach ke aplikasi yang diproteksi Appdome.'
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
        send({ tag: 'frida-injected', pid: Process.id });
      });
    },
    onComplete() {},
  });
}

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
