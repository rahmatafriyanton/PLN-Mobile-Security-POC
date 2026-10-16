'use strict';

// Pixel 5 / Frida 16.5.2 presentation screen-sharing variant.
// Target APK SHA-256:
// 03e286af4a7e7728b616fcf6587cb096ec2e67472f0a2e04b95d1316eeef5cce
// Native offsets below are specific to this APK's arm64 libprotector.so.
// Keep the Frida session attached while using the application.

Java.perform(function () {
    Java.deoptimizeEverything();
    console.log('\n[force-clean] =================================================');
    console.log('[force-clean] ART methods deoptimized');
    console.log('[force-clean] =================================================\n');

    var JSONObject = Java.use('org.json.JSONObject');
    var Config = Java.use('com.protector.o.l2');
    var envLogged = false;

    // Prevent secure-window and secure-surface flags from producing a black
    // frame in scrcpy while this presentation script is attached.
    var FLAG_SECURE = 0x2000;
    var Window = Java.use('android.view.Window');
    var addFlags = Window.addFlags.overload('int');
    addFlags.implementation = function (flags) {
        return addFlags.call(this, flags & ~FLAG_SECURE);
    };
    var setFlags = Window.setFlags.overload('int', 'int');
    setFlags.implementation = function (flags, mask) {
        return setFlags.call(this, flags & ~FLAG_SECURE, mask);
    };

    var SurfaceView = Java.use('android.view.SurfaceView');
    var setSecure = SurfaceView.setSecure.overload('boolean');
    setSecure.implementation = function (_) {
        return setSecure.call(this, false);
    };

    var Activity = Java.use('android.app.Activity');
    var activityOnResume = Activity.onResume.overload();
    activityOnResume.implementation = function () {
        this.getWindow().clearFlags(FLAG_SECURE);
        var result = activityOnResume.call(this);
        var activityName = String(this.getClass().getName());
        if (activityName === 'com.app.plnmobile.MainActivity') {
            console.log('[presentation] SCREEN SHARING ENABLED: ' + activityName);
            send({
                tag: 'pixel-application-running',
                activity: activityName,
            });
        }
        return result;
    };

    var protectionMap = {
        'native_checks_pass':           'Native Root/Emulator/Hook Check',
        'developer_options_off':        'Developer Options',
        'adb_off':                      'ADB Debugging',
        'unknown_sources_off':          'Unknown Sources',
        'min_sdk_met':                  'Min SDK Version',
        'package_ok':                   'Package Integrity',
        'signer_ok':                    'APK Signer Verification',
        'play_store_install':           'Play Store Installation',
        'no_suspicious_packages':       'Suspicious Packages (Magisk/Frida)',
        'network_validated':            'Network Validation',
        'is_clean':                     'Overall Clean Status',
        'debug_mode':                   'Debug Mode / Debugger',
        'ld_preload_present':           'LD_PRELOAD Injection',
        'accessibility_high_risk':      'High-Risk Accessibility',
        'rat_present':                  'Remote Access Trojan',
        'rat_a11y_active':              'RAT Accessibility',
        'screen_share_active':          'Screen Sharing',
        'app_cloned':                   'App Cloning',
        'screen_recording_active':      'Screen Recording',
        'overlay_detected':             'Overlay Attack',
        'tapjacking_detected':          'Tapjacking',
        'automation_active':            'UI Automation',
        'uncertified_rom':              'Uncertified ROM',
        'clock_skew_exceeded':          'Clock Skew',
        'arp_anomaly':                  'ARP Spoofing',
        'dns_hijack':                   'DNS Hijacking',
        'behavioral_anomaly':           'Behavioral Anomaly',
        'vpn_active':                   'VPN Active',
        'proxy_configured':             'Proxy',
        'captive_portal':               'Captive Portal',
        'dangerous_package_present':    'Dangerous Package (Root/Frida/Magisk)',
        'rc6_modern_stealth_detected':  'Modern Stealth (RC6)',
    };

    function normalizeEnvironment(json) {
        var putBoolean = json.put.overload('java.lang.String', 'boolean');
        var putString = json.put.overload('java.lang.String', 'java.lang.Object');

        var forcedTrue = [
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
        ];

        var forcedFalse = [
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
        ];

        if (!envLogged) {
            console.log('[force-clean] [ENV] ────────────────────────────────────────');
            console.log('[force-clean] [ENV] Environment Checks (first call)');
            console.log('[force-clean] [ENV] ────────────────────────────────────────');

            forcedTrue.forEach(function (key) {
                var original = json.optBoolean(key, false);
                putBoolean.call(json, key, true);
                var name = protectionMap[key] || key;
                var mark = (original === true) ? '✓' : '✗';
                console.log('[force-clean] [ENV] ' + mark + ' ' + name.padEnd(38) + ' | original: ' + String(original).padEnd(5) + ' → true');
            });

            forcedFalse.forEach(function (key) {
                var original = json.optBoolean(key, false);
                putBoolean.call(json, key, false);
                var name = protectionMap[key] || key;
                var mark = (original === false) ? '✓' : '✗';
                console.log('[force-clean] [ENV] ' + mark + ' ' + name.padEnd(38) + ' | original: ' + String(original).padEnd(5) + ' → false');
            });

            console.log('[force-clean] [ENV] ────────────────────────────────────────');
            envLogged = true;
        } else {
            // tetap force, tapi tidak di-log lagi
            forcedTrue.forEach(function (key) { putBoolean.call(json, key, true); });
            forcedFalse.forEach(function (key) { putBoolean.call(json, key, false); });
        }

        putString.call(json, 'failure_reason', Java.use('java.lang.String').$new(''));
        putString.call(json, 'rc6_modern_stealth_mask', Java.use('java.lang.String').$new('0'));
        putString.call(json, 'apk_signer_sha256', Config.j());
        putString.call(json, 'apk_signer_sha256GPS', Config.k());

        return json;
    }

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
                lines.push(current.getClass().getName().toString() + ': ' + current.getMessage());
                current = current.getCause();
            } catch (_) {
                lines.push(current.message || current.toString());
                current = null;
            }
        }
        return lines.join('\n');
    }

    // ===================== KEYSTORE =====================
    var KeyBuilder = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
    var setAuthRequired = KeyBuilder.setUserAuthenticationRequired.overload('boolean');
    setAuthRequired.implementation = function (required) {
        if (required) {
            console.log('[force-clean] [KEYSTORE] Biometric/User Auth required=true → forced false');
        }
        return setAuthRequired.call(this, false);
    };

    // ===================== NATIVE GATES =====================
    var Bridge = Java.use('com.protector.stub.DexLoaderBridge');
    var nativeLoader = Module.findExportByName('libprotector.so',
        'Java_com_protector_stub_NativeComponentLoaderBridge_loadProtectedLibraryFromMemory');
    var protectorBase = Module.findBaseAddress('libprotector.so');

    if (Process.arch !== 'arm64' || nativeLoader === null || protectorBase === null ||
        !nativeLoader.equals(protectorBase.add(0x22b144))) {
        throw new Error('Unsupported libprotector build: native gate not installed');
    }

    var nativeGate = protectorBase.add(0x22e6e0);
    if (nativeGate.readU32() !== 0xd101c3ff || nativeGate.add(4).readU32() !== 0xa9027bfd) {
        throw new Error('Native gate instruction signature mismatch');
    }

    var nativeGateCallback = new NativeCallback(function (operation) {
        var opName = operation.readCString() || '<unknown>';
        console.log('[force-clean] [NATIVE] Loader Gate | op="' + opName + '" → return 1');
        return 1;
    }, 'int', ['pointer']);
    Interceptor.replace(nativeGate, nativeGateCallback);

    var nativeAction = protectorBase.add(0x224260);
    if (nativeAction.readU32() !== 0xd10143ff || nativeAction.add(4).readU32() !== 0xa9037bfd) {
        throw new Error('Native watchdog policy instruction signature mismatch');
    }

    var nativeActionCallback = new NativeCallback(function () {
        console.log('[force-clean] [NATIVE] Watchdog Policy → return 1 (log-only)');
        return 1;
    }, 'int', []);
    Interceptor.replace(nativeAction, nativeActionCallback);

    console.log('[force-clean] [NATIVE] Native gates installed');

    // ===================== BRIDGE / WATCHMAN =====================
    Bridge.watchmanVerify.implementation = function () {
        console.log('[force-clean] [BRIDGE] Watchman Verify → true');
        return true;
    };

    Bridge.getModernStealthThreatMask.overload('android.content.Context').implementation = function () {
        console.log('[force-clean] [BRIDGE] Modern Stealth Mask → 0');
        return 0;
    };

    // ===================== SPLASH / BOOT GATE =====================
    var Splash = Java.use('com.protector.stub.SplashActivity');

    var showBootFailure = Splash['lambda$pullZtaFeatureAccess$1'].overload('java.lang.String');
    showBootFailure.implementation = function (message) {
        console.log('[force-clean] [SPLASH] Boot failure message: ' + message);
        return showBootFailure.call(this, message);
    };

    var dispatchBootFailure = Splash.dispatchBootFailure.overload('java.lang.Throwable');
    dispatchBootFailure.implementation = function (error) {
        console.log('[force-clean] [SPLASH] Boot failure:\n' + throwableText(error));
        return dispatchBootFailure.call(this, error);
    };

    Splash['lambda$pullZtaFeatureAccess$2'].implementation = function () {
        var activity = Java.retain(this);
        Java.scheduleOnMainThread(function () {
            console.log('[force-clean] [SPLASH] Startup Security Gate → CLEAN');
            activity.continueAfterSecurityGate();
        });
    };

    // ===================== ENVIRONMENT COLLECTORS =====================
    var Decision = Java.use('com.protector.o.e0');

    var collectEnvironment = Decision.a.overload('android.content.Context');
    collectEnvironment.implementation = function (context) {
        return normalizeEnvironment(collectEnvironment.call(this, context));
    };

    var collectPreflightEnvironment = Decision.b.overload('android.content.Context');
    collectPreflightEnvironment.implementation = function (context) {
        return normalizeEnvironment(collectPreflightEnvironment.call(this, context));
    };

    Decision.a.overload('org.json.JSONObject').implementation = function () {
        console.log('[force-clean] [DECISION] Final security decision → true (CLEAN)');
        return true;
    };

    // ===================== POSTURE / OFFLINE PREFLIGHT =====================
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
        putObject.call(json, 'offline_network_probe_mode', Java.use('java.lang.String').$new('local_state_only'));
        putObject.call(
            json,
            'offline_preflight_sha256',
            hashPreflight.call(Posture, canonicalizePreflight.call(Posture, json))
        );

        cleanPreflight = JSONObject.$new(json.toString());
        Posture._b.value = JSONObject.$new(cleanPreflight.toString());
        Posture._c.value = SystemClock.elapsedRealtime();
        Posture._d.value = Java.use('java.lang.String').$new('');
        Posture._a.value.set(passedState);

        console.log('[force-clean] [POSTURE] Offline Preflight → PASSED');
        console.log('[force-clean] [POSTURE]   • play_integrity_cached_known = true');
        console.log('[force-clean] [POSTURE]   • screen_capture_prevention_required = true');
        console.log('[force-clean] [POSTURE]   • security_patch_present = true');
        return JSONObject.$new(cleanPreflight.toString());
    }

    runOfflinePreflight.implementation = function (context) {
        return buildCleanPreflight(context);
    };

    Posture.d.overload().implementation = function () {
        console.log('[force-clean] [POSTURE] Offline preflight state → PASSED');
    };

    Posture.b.overload('java.lang.String').implementation = function (endpoint) {
        console.log('[force-clean] [POSTURE] Network enabled after preflight: ' + endpoint);
    };

    var collectCachedEnvironment = Posture.a.overload();
    collectCachedEnvironment.implementation = function () {
        if (cleanPreflight !== null) {
            return JSONObject.$new(cleanPreflight.toString());
        }
        return normalizeEnvironment(collectCachedEnvironment.call(this));
    };

    // ===================== APPLICATION BOOT =====================
    var ProtectorApplication = Java.use('com.protector.stub.ProtectorApplication');
    var ProtectedAttacher = Java.use('com.protector.o.v0');

    ProtectedAttacher.a.overload(
        'java.lang.ClassLoader', 'android.content.Context', 'boolean', 'java.lang.String'
    ).implementation = function (loader, context, required, verifier) {
        console.log('[force-clean] [RUNTIME] Protected runtime reverify → ALLOWED');
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
            console.log('[force-clean] [BOOT] Worker preflight bypassed');

            if (!Config.q()) {
                console.log('[force-clean] [BOOT] Mode: ONLINE');
                return bootOnline.call(this, context, fullAttestation, callback);
            }
            if (Config.p()) {
                console.log('[force-clean] [BOOT] Mode: OFFLINE');
                return this.bootOffline(context, callback);
            }
            console.log('[force-clean] [BOOT] Mode: OFFLINE CERTIFICATE');
            return this.bootOfflineWithCert(context, fullAttestation, callback);
        } finally {
            this.bootInProgress.value.set(false);
        }
    };

    // ===================== API / REGISTER =====================
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
            console.log('\n[force-clean] [API] ════════════════════════════════════════');
            console.log('[force-clean] [API] REGISTER REQUEST');
            console.log('[force-clean] [API] url: ' + Config.J().replace(/\/+$/, '') + path);

            if (payload.has('play_integrity_token')) {
                var tokenLen = String(payload.opt('play_integrity_token')).length;
                console.log('[force-clean] [API] Play Integrity Token: present (length=' + tokenLen + ') → redacted');
            } else {
                console.log('[force-clean] [API] Play Integrity Token: not present');
            }

            if (payload.has('play_store_install')) {
                console.log('[force-clean] [API] play_store_install = ' + payload.optBoolean('play_store_install'));
            }

            console.log(redactedPayload(payload).toString(2));
            console.log('[force-clean] [API] Note: Environment flags dapat diubah lokal.');
            console.log('[force-clean] [API] Play Integrity token, attestation chain, nonce, dan key binding tetap diverifikasi server.');
            console.log('[force-clean] [API] ════════════════════════════════════════\n');
        }

        try {
            return postJson.call(this, path, payload, token, userAuth);
        } catch (error) {
            var detail = throwableText(error);
            console.log('\n[force-clean] [API ERROR] endpoint: POST ' + path);
            console.log(detail);
            throw error;
        }
    };

    console.log('\n[force-clean] =================================================');
    console.log('[force-clean] ALL HOOKS INSTALLED');
    console.log('[force-clean] =================================================\n');
});