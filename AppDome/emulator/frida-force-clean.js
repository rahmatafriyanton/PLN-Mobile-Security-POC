'use strict';

let resultSanitizer;
let resultSanitizerListener;

function installResultSanitizer() {
  const loader = Process.getModuleByName('libloader.so');
  resultSanitizer = new CModule(`
    #include <gum/guminterceptor.h>
    #include <stdint.h>

    void on_enter(GumInvocationContext *context) {
      uintptr_t event =
          (uintptr_t) gum_invocation_context_get_nth_argument(context, 0);
      uint8_t *payload =
          (uint8_t *) gum_invocation_context_get_nth_argument(context, 1);
      if (event == 136 && payload != NULL)
        payload[177] = 1;
    }
  `);
  resultSanitizerListener = Interceptor.attach(
    loader.base.add(0x98468),
    { onEnter: resultSanitizer.on_enter }
  );
  send({ tag: 'result-sanitizer-ready' });
}

function sanitizeDetectionPolicies() {
  const names = [
    'ActiveADBDetected',
    'AppIntegrityError',
    'AppIsDebuggable',
    'CodeInjectionDetected',
    'DebuggerThreatDetected',
    'FridaAttachDetected',
    'FridaCustomDetected',
    'FridaDetected',
    'FridaSpawnDetected',
    'GoogleEmulatorDetected',
    'HookFrameworkDetected',
    'InlineHookDetected',
    'JavaHookDetected',
    'MagiskManagerDetected',
    'OsRemountDetected',
    'RootedDevice',
    'SeccompDetected',
    'TrickyStoreDetected',
    'ZygiskDetected',
  ];
  const bytes = function (text) {
    return Array.from(text)
      .map(function (character) {
        return character.charCodeAt(0).toString(16).padStart(2, '0');
      })
      .join(' ');
  };
  const scan = function (range, pattern) {
    try {
      return Memory.scanSync(range.base, range.size, pattern);
    } catch (_error) {
      return [];
    }
  };
  const pages = new Set();
  const ranges = Process.enumerateRanges('rw-').filter(function (range) {
    return range.size <= 0x400000 &&
      scan(range, `${bytes('Detected')} 00`).length > 0;
  });
  ranges.forEach(function (range) {
    names.forEach(function (name) {
      scan(range, bytes(name)).forEach(function (match) {
        const page = match.address.sub(match.address.toUInt32() & 0xfff);
        if (
          page.compare(range.base) >= 0 &&
          page.add(4096).compare(range.base.add(range.size)) <= 0 &&
          page.add(105).readU8() === 0 &&
          page.add(106).readU8() === 1 &&
          page.add(107).readU8() === 0
        ) {
          pages.add(page.toString());
        }
      });
    });
  });
  pages.forEach(function (address) {
    const page = ptr(address);
    page.add(106).writeU8(0);
    page.add(3600).writeU8(page.add(3600).readU8() & ~0x01);
    page.add(3608).writeU8(page.add(3608).readU8() & ~0x20);
  });
  send({ tag: 'detection-policies-sanitized', count: pages.size });
}

function installTerminationGuard() {
  const instructions = [
    [0x20, 0, 0, 0],
    [0x15, 0, 2, 94],
    [0x20, 0, 0, 24],
    [0x15, 12, 11, 9],
    [0x15, 0, 4, 129],
    [0x20, 0, 0, 16],
    [0x15, 0, 2, Process.id],
    [0x20, 0, 0, 24],
    [0x15, 7, 0, 9],
    [0x20, 0, 0, 0],
    [0x15, 0, 4, 131],
    [0x20, 0, 0, 16],
    [0x15, 0, 2, Process.id],
    [0x20, 0, 0, 32],
    [0x15, 1, 0, 9],
    [0x06, 0, 0, 0x7fff0000],
    [0x06, 0, 0, 0x00050001],
  ];
  const filter = Memory.alloc(instructions.length * 8);
  instructions.forEach(function (instruction, index) {
    const target = filter.add(index * 8);
    target.writeU16(instruction[0]);
    target.add(2).writeU8(instruction[1]);
    target.add(3).writeU8(instruction[2]);
    target.add(4).writeU32(instruction[3]);
  });

  const program = Memory.alloc(16);
  program.writeU16(instructions.length);
  program.add(8).writePointer(filter);
  const prctl = new NativeFunction(
    Module.getExportByName('libc.so', 'prctl'),
    'int',
    ['int', 'ulong', 'ulong', 'ulong', 'ulong']
  );
  const syscall = new NativeFunction(
    Module.getExportByName('libc.so', 'syscall'),
    'long',
    ['long', 'long', 'long', 'pointer']
  );
  const noNewPrivileges = prctl(38, 1, 0, 0, 0);
  const result = Number(syscall(277, 1, 1, program).toString());
  if (noNewPrivileges !== 0 || result !== 0) {
    throw new Error(
      `Unable to install termination guard: prctl=${noNewPrivileges}, seccomp=${result}`
    );
  }
  send({ tag: 'termination-guard-ready' });
}

function disableEnforcementDecision() {
  Java.performNow(function () {
    const enforcement = Java.use('tkIz24.mamTp0.kJFy54.buNKX9');
    const decision = enforcement.oIjyT9.overload(
      'android.app.Activity',
      'java.lang.Boolean'
    );
    decision.implementation = function (_activity, detected) {
      send({ tag: 'enforcement-skipped', detected: String(detected) });
    };
  });
}

function sanitizeUserIndications() {
  const producer = Java.use('tkIz24.lgH6M2.yiWzn5');
  const indication = producer.qHIoU1.overload(
    'java.lang.String',
    'java.lang.String',
    'boolean',
    'boolean',
    'java.lang.String',
    'java.lang.String'
  );
  let initialized = false;
  indication.implementation = function (
    first,
    second,
    third,
    fourth,
    fifth,
    sixth
  ) {
    if (third) {
      send({ tag: 'threat-indication-sanitized', title: String(second) });
      if (initialized) return;
      initialized = true;
      return indication.call(this, '', '', false, false, '', '');
    }
    return indication.call(
      this,
      first,
      second,
      third,
      fourth,
      fifth,
      sixth
    );
  };
}

function traceJavaTermination() {
  const Log = Java.use('android.util.Log');
  const Exception = Java.use('java.lang.Exception');
  const stack = function () {
    return String(Log.getStackTraceString(Exception.$new()));
  };
  const ProcessClass = Java.use('android.os.Process');
  const killProcess = ProcessClass.killProcess.overload('int');
  killProcess.implementation = function (pid) {
    send({ tag: 'kill-process', pid: pid, stack: stack() });
    if (pid === Process.id) return;
    return killProcess.call(this, pid);
  };
  const System = Java.use('java.lang.System');
  const systemExit = System.exit.overload('int');
  systemExit.implementation = function (code) {
    send({ tag: 'system-exit', code: code, stack: stack() });
    return systemExit.call(this, code);
  };
  const Runtime = Java.use('java.lang.Runtime');
  const runtimeExit = Runtime.exit.overload('int');
  runtimeExit.implementation = function (code) {
    send({ tag: 'runtime-exit', code: code, stack: stack() });
    return runtimeExit.call(this, code);
  };
}

// Keep at most one main-thread probe queued so a stalled UI cannot accumulate work.
function monitorUi() {
  const Activity = Java.use('android.app.Activity');
  const dispatch = Activity.dispatchTouchEvent.overload(
    'android.view.MotionEvent'
  );
  let touches = 0;
  let pending = false;
  dispatch.implementation = function (event) {
    const result = dispatch.call(this, event);
    if (event.getActionMasked() === 1) {
      touches++;
      send({ tag: 'ui-touch', touches: touches });
    }
    return result;
  };
  setInterval(function () {
    if (pending) return;
    pending = true;
    Java.scheduleOnMainThread(function () {
      pending = false;
      send({ tag: 'ui-heartbeat', touches: touches });
    });
  }, 1000);
}

try {
  installTerminationGuard();
  if (globalThis.APPDOME_INTERACTIVE === true) {
    send({ tag: 'appdome-ready' });
  } else {
    Java.perform(function () {
      try {
        disableEnforcementDecision();
        monitorUi();
        send({ tag: 'appdome-ready' });
      } catch (error) {
        send({ tag: 'setup-error', error: String(error), stack: error.stack });
      }
    });
  }
} catch (error) {
  send({ tag: 'setup-error', error: String(error), stack: error.stack });
}
