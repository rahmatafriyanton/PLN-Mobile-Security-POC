'use strict';

const MESSAGE = 'Nexilis — Frida injected';
let shown = false;

function showIndicator(activity) {
  if (shown) return;
  if (String(activity.getClass().getName()) !== 'com.app.plnmobile.MainActivity') {
    return;
  }
  shown = true;
  const retainedActivity = Java.retain(activity);
  Java.scheduleOnMainThread(function () {
    const Toast = Java.use('android.widget.Toast');
    const Builder = Java.use('android.app.AlertDialog$Builder');
    const JString = Java.use('java.lang.String');
    const title = JString.$new(MESSAGE);
    const message = JString.$new(
      'Frida berhasil attach ke aplikasi yang diproteksi Nexilis.'
    );
    Toast.makeText
      .overload(
        'android.content.Context',
        'java.lang.CharSequence',
        'int'
      )
      .call(Toast, retainedActivity, title, Toast.LENGTH_LONG.value)
      .show();
    const dialog = Builder.$new(retainedActivity);
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
}

Java.perform(function () {
  const Activity = Java.use('android.app.Activity');
  const onResume = Activity.onResume.overload();
  onResume.implementation = function () {
    onResume.call(this);
    showIndicator(this);
  };
});
