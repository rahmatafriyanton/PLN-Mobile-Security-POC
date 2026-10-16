'use strict';
// One-time recovery of the ZTA test registration revoked during this session.
// Does not clear PLN application data. Do not load for ordinary launches.
Java.perform(function () {
  var Splash = Java.use('com.protector.stub.SplashActivity');
  var onCreate = Splash.onCreate.overload('android.os.Bundle');
  onCreate.implementation = function (state) {
    var prefs = this.getSharedPreferences('nexilis_kill', 0);
    if (prefs.getBoolean('install_revoked', false)) {
      Java.use('com.protector.o.z1').b.overload('android.content.Context').call(Java.use('com.protector.o.z1'), this);
      Java.use('com.protector.o.d').b.overload('android.content.Context').call(Java.use('com.protector.o.d'), this);
      prefs.edit().remove('install_revoked').commit();
      console.log('[recovery] revoked test registration cleared; requesting fresh registration');
    }
    return onCreate.call(this, state);
  };
});
