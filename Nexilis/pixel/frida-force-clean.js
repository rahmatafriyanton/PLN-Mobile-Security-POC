'use strict';

// Pixel 5 / Frida 16.5.2 test launcher: ./run-pixel5.sh
// Target APK SHA-256:
// 03e286af4a7e7728b616fcf6587cb096ec2e67472f0a2e04b95d1316eeef5cce
// Native offsets below are specific to this APK's arm64 libprotector.so.
// Keep the Frida session attached while using the application.

Java.perform(function () {
  Java.deoptimizeEverything();
  console.log('[force-clean] ART methods deoptimized');

  // Allow scrcpy mirroring in this instrumented application process.
  var Window = Java.use('android.view.Window');
  var setFlags = Window.setFlags.overload('int', 'int');
  setFlags.implementation = function (flags, mask) {
    return setFlags.call(this, flags & ~0x2000, mask | 0x2000);
  };
  var setAttributes = Window.setAttributes.overload('android.view.WindowManager$LayoutParams');
  setAttributes.implementation = function (attributes) {
    attributes.flags.value = attributes.flags.value & ~0x2000;
    return setAttributes.call(this, attributes);
  };
  var SurfaceView = Java.use('android.view.SurfaceView');
  var setSecure = SurfaceView.setSecure.overload('boolean');
  setSecure.implementation = function (secure) {
    return setSecure.call(this, false);
  };
  console.log('[force-clean] scrcpy capture enabled for this app');

  var JSONObject = Java.use('org.json.JSONObject');
  var Config = Java.use('com.protector.o.l2');

  function normalizeEnvironment(json) {
    var putBoolean = json.put.overload('java.lang.String', 'boolean');
    var putString = json.put.overload('java.lang.String', 'java.lang.Object');

    [
      'native_checks_pass',
      'developer_options_off',
      'adb_off',
      'unknown_sources_off',
      'min_sdk_met',
      'package_ok',
      'signer_ok',
      'play_store_install',
      'no_suspicious_packages',
      'network_validated',
      'is_clean',
    ].forEach(function (key) {
      putBoolean.call(json, key, true);
    });

    [
      'debug_mode',
      'ld_preload_present',
      'accessibility_high_risk',
      'rat_present',
      'rat_a11y_active',
      'screen_share_active',
      'app_cloned',
      'screen_recording_active',
      'overlay_detected',
      'tapjacking_detected',
      'automation_active',
      'uncertified_rom',
      'clock_skew_exceeded',
      'arp_anomaly',
      'dns_hijack',
      'behavioral_anomaly',
      'vpn_active',
      'proxy_configured',
      'captive_portal',
      'dangerous_package_present',
      'rc6_modern_stealth_detected',
    ].forEach(function (key) {
      putBoolean.call(json, key, false);
    });

    putString.call(json, 'failure_reason', Java.use('java.lang.String').$new(''));
    // Keep the evidence mask consistent with the normalized detection flag.
    putString.call(json, 'rc6_modern_stealth_mask', Java.use('java.lang.String').$new('0'));
    // Build.VERSION may retain a value initialized before a device property
    // update. Read the current property instead of that cached Java field.
    var SystemProperties = Java.use('android.os.SystemProperties');
    var currentPatch = String(SystemProperties.get.overload('java.lang.String')
      .call(SystemProperties, 'ro.build.version.security_patch'));
    if (/^\d{4}-\d{2}-\d{2}$/.test(currentPatch)) {
      if (String(json.optString('security_patch', '')) !== currentPatch) {
        console.log('[force-clean] security patch synchronized with current device property: ' + currentPatch);
      }
      putString.call(json, 'security_patch', Java.use('java.lang.String').$new(currentPatch));
    }
    putString.call(json, 'apk_signer_sha256', Config.j());
    putString.call(json, 'apk_signer_sha256GPS', Config.k());
    return json;
  }

  /**
   * Membuat salinan payload untuk log tanpa mencetak token, nonce, certificate
   * chain, atau public key mentah.
   */
  function redactedPayload(payload) {
    var safe = JSONObject.$new(payload.toString());
    [
      'attestation_cert_chain_b64',
      'public_key_der_b64',
      'approval_public_key_der_b64',
      'play_integrity_token',
      'nonce_b64',
    ].forEach(function (key) {
      if (safe.has(key)) {
        var value = String(safe.opt(key));
        safe.put(key, '<redacted length=' + value.length + '>');
      }
    });
    return safe;
  }

  function throwableText(error) {
    var lines = [];
    var current = error;
    for (var depth = 0; current !== null && depth < 8; depth++) {
      try {
        lines.push(
          current.getClass().getName().toString() + ': ' + current.getMessage()
        );
        current = current.getCause();
      } catch (_) {
        lines.push(current.message || current.toString());
        current = null;
      }
    }
    return lines.join('\n');
  }

  var KeyBuilder = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
  var setAuthRequired = KeyBuilder.setUserAuthenticationRequired.overload('boolean');
  setAuthRequired.implementation = function (required) {
    if (required) {
      console.log('[force-clean] Keystore user authentication: disabled');
    }
    return setAuthRequired.call(this, false);
  };

  var Bridge = Java.use('com.protector.stub.DexLoaderBridge');
  // Build-specific native gate for the supplied arm64 APK. Java posture hooks
  // do not affect the native gate used by protected library/DEX loading.
  var nativeLoader = Module.findExportByName('libprotector.so',
    'Java_com_protector_stub_NativeComponentLoaderBridge_loadProtectedLibraryFromMemory');
  var protectorBase = Module.findBaseAddress('libprotector.so');
  if (Process.arch !== 'arm64' || nativeLoader === null || protectorBase === null ||
      !nativeLoader.equals(protectorBase.add(0x22b144))) {
    throw new Error('Unsupported libprotector build: native gate not installed');
  }
  var nativeGate = protectorBase.add(0x22e6e0);
  if (nativeGate.readU32() !== 0xd101c3ff ||
      nativeGate.add(4).readU32() !== 0xa9027bfd) {
    throw new Error('Native gate instruction signature mismatch');
  }
  var nativeGateCallback = new NativeCallback(function (operation) {
    console.log('[force-clean] native gate: ' + operation.readCString());
    return 1;
  }, 'int', ['pointer']);
  Interceptor.replace(nativeGate, nativeGateCallback);
  var nativeAction = protectorBase.add(0x224260);
  if (nativeAction.readU32() !== 0xd10143ff ||
      nativeAction.add(4).readU32() !== 0xa9037bfd) {
    throw new Error('Native watchdog policy instruction signature mismatch');
  }
  var nativeActionCallback = new NativeCallback(function () {
    return 1; // This build's log-only action; keep watchdog observations alive.
  }, 'int', []);
  Interceptor.replace(nativeAction, nativeActionCallback);
  console.log('[force-clean] native loader gate installed');
  Bridge.watchmanVerify.implementation = function () {
    console.log('[force-clean] watchmanVerify: true');
    return true;
  };
  Bridge.getModernStealthThreatMask.overload('android.content.Context').implementation = function () {
    return 0;
  };

  var Splash = Java.use('com.protector.stub.SplashActivity');
  var showBootFailure = Splash['lambda$pullZtaFeatureAccess$1'].overload('java.lang.String');
  showBootFailure.implementation = function (message) {
    console.log('[force-clean] splash failure: ' + message);
    return showBootFailure.call(this, message);
  };
  var dispatchBootFailure = Splash.dispatchBootFailure.overload('java.lang.Throwable');
  dispatchBootFailure.implementation = function (error) {
    console.log('[force-clean] boot failure: ' + throwableText(error));
    return dispatchBootFailure.call(this, error);
  };
  Splash['lambda$pullZtaFeatureAccess$2'].implementation = function () {
    var activity = Java.retain(this);
    Java.scheduleOnMainThread(function () {
      console.log('[force-clean] startup gate: CLEAN');
      activity.continueAfterSecurityGate();
    });
  };

  var Decision = Java.use('com.protector.o.e0');
  var collectEnvironment = Decision.a.overload('android.content.Context');
  collectEnvironment.implementation = function (context) {
    console.log('[force-clean] environment payload normalized');
    return normalizeEnvironment(collectEnvironment.call(this, context));
  };

  var collectPreflightEnvironment = Decision.b.overload('android.content.Context');
  collectPreflightEnvironment.implementation = function (context) {
    console.log('[force-clean] offline preflight payload normalized');
    return normalizeEnvironment(collectPreflightEnvironment.call(this, context));
  };

  var Posture = Java.use('com.protector.o.p0');
  var PostureState = Java.use('com.protector.o.p0$a');
  var SystemClock = Java.use('android.os.SystemClock');
  var passedState = null;
  var postureStates = PostureState.class.getEnumConstants();
  for (var stateIndex = 0; stateIndex < postureStates.length; stateIndex++) {
    if (String(postureStates[stateIndex]) === 'PASSED') {
      passedState = Java.cast(postureStates[stateIndex], PostureState);
      break;
    }
  }
  var cleanPreflight = null;
  var runOfflinePreflight = Posture.a.overload('android.content.Context');
  var canonicalizePreflight = Posture.a.overload('org.json.JSONObject');
  var hashPreflight = Posture.a.overload('[B');
  function buildCleanPreflight(context) {
    var json = normalizeEnvironment(
      collectPreflightEnvironment.call(Decision, context)
    );
    var putBoolean = json.put.overload('java.lang.String', 'boolean');
    var putObject = json.put.overload('java.lang.String', 'java.lang.Object');

    putBoolean.call(json, 'rc4_offline_preflight', true);
    putBoolean.call(json, 'screen_capture_prevention_required', true);
    putBoolean.call(json, 'security_patch_present', true);
    putBoolean.call(json, 'play_integrity_cached_known', true);
    putObject.call(
      json,
      'offline_network_probe_mode',
      Java.use('java.lang.String').$new('local_state_only')
    );
    putObject.call(
      json,
      'offline_preflight_sha256',
      hashPreflight.call(
        Posture,
        canonicalizePreflight.call(Posture, json)
      )
    );

    cleanPreflight = JSONObject.$new(json.toString());
    Posture._b.value = JSONObject.$new(cleanPreflight.toString());
    Posture._c.value = SystemClock.elapsedRealtime();
    Posture._d.value = Java.use('java.lang.String').$new('');
    Posture._a.value.set(passedState);
    console.log('[force-clean] offline preflight: PASSED');
    return JSONObject.$new(cleanPreflight.toString());
  }

  runOfflinePreflight.implementation = function (context) {
    return buildCleanPreflight(context);
  };

  Posture.d.overload().implementation = function () {
    console.log('[force-clean] offline preflight state: PASSED');
  };

  Posture.b.overload('java.lang.String').implementation = function (endpoint) {
    console.log('[force-clean] network enabled after preflight: ' + endpoint);
  };

  var collectCachedEnvironment = Posture.a.overload();
  collectCachedEnvironment.implementation = function () {
    console.log('[force-clean] cached registration payload normalized');
    if (cleanPreflight !== null) {
      return JSONObject.$new(cleanPreflight.toString());
    }
    return normalizeEnvironment(collectCachedEnvironment.call(this));
  };

  Decision.a.overload('org.json.JSONObject').implementation = function () {
    console.log('[force-clean] security decision: CLEAN');
    return true;
  };

  var ProtectorApplication = Java.use('com.protector.stub.ProtectorApplication');
  var ProtectedAttacher = Java.use('com.protector.o.v0');
  ProtectedAttacher.a.overload(
    'java.lang.ClassLoader', 'android.content.Context', 'boolean', 'java.lang.String'
  ).implementation = function (loader, context, required, verifier) {
    console.log('[force-clean] protected runtime reverify: allowed for Frida test');
  };
  var bootOnline = ProtectorApplication.bootOnline.overload(
    'android.content.Context',
    'boolean',
    'com.protector.stub.ProtectorApplication$c'
  );
  ProtectorApplication['lambda$triggerZtaBoot$3'].implementation = function (
    context,
    callback,
    fullAttestation
  ) {
    try {
      buildCleanPreflight(context);
      console.log('[force-clean] boot worker preflight: bypassed');
      if (!Config.q()) {
        console.log('[force-clean] configured boot mode: online');
        return bootOnline.call(this, context, fullAttestation, callback);
      }
      if (Config.p()) {
        console.log('[force-clean] configured boot mode: offline');
        return this.bootOffline(context, callback);
      }
      console.log('[force-clean] configured boot mode: offline certificate');
      return this.bootOfflineWithCert(context, fullAttestation, callback);
    } finally {
      this.bootInProgress.value.set(false);
    }
  };

  // Preserve full attestation: /key requires a fresh Play Integrity token.

  var ZtaClient = Java.use('com.protector.o.h2');
  var postJson = ZtaClient.a.overload(
    'java.lang.String',
    'org.json.JSONObject',
    'java.lang.String',
    'java.lang.String'
  );
  postJson.implementation = function (path, payload, token, userAuth) {
    var isRegister = String(path) === '/api/v1/register';
    if (isRegister) {
      console.log('\n======== REGISTER REQUEST ========');
      console.log('url: ' + Config.J().replace(/\/+$/, '') + path);
      console.log(redactedPayload(payload).toString(2));
      console.log(
        '[analysis] JSON environment dapat diubah lokal; attestation chain, ' +
        'Play Integrity token, nonce, dan key binding diverifikasi server.'
      );
      console.log('==================================\n');
    }

    try {
      return postJson.call(this, path, payload, token, userAuth);
    } catch (error) {
      var detail = throwableText(error);
      console.log('\n======== PROTECTOR API ERROR ========');
      console.log('endpoint: POST ' + path);
      console.log(detail);
      console.log('=====================================\n');
      throw error;
    }
  };

  console.log('[force-clean] hooks installed');
});
