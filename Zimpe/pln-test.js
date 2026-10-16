'use strict';
// Shared patch definitions for the early native bootstrap and Frida agent.
const PLN_PATCH_PLAN = {
  "module": "liboutlookinvolve.so",
  "apkEntry": "lib/arm64-v8a/liboutlookinvolve.so",
  "patches": [
    {
      "offset": 4914060,
      "expected": "00013fd6",
      "replacement": "1f2003d5"
    },
    {
      "offset": 4913476,
      "expected": "00013fd6",
      "replacement": "1f2003d5"
    },
    {
      "offset": 5869896,
      "expected": "00013fd6",
      "replacement": "1f2003d5"
    },
    {
      "offset": 4923432,
      "expected": "00013fd6",
      "replacement": "1f2003d5"
    },
    {
      "offset": 5710696,
      "expected": "00013fd6",
      "replacement": "1f2003d5"
    },
    {
      "offset": 4914316,
      "expected": "00013fd6",
      "replacement": "1f2003d5"
    },
    {
      "offset": 5207048,
      "expected": "00013fd6",
      "replacement": "1f2003d5"
    },
    {
      "offset": 5627832,
      "expected": "00013fd6",
      "replacement": "1f2003d5"
    },
    {
      "offset": 4916220,
      "expected": "00013fd6",
      "replacement": "1f2003d5"
    },
    {
      "offset": 4077196,
      "expected": "00013fd6",
      "replacement": "1f2003d5"
    },
    {
      "offset": 5875652,
      "expected": "00013fd6",
      "replacement": "1f2003d5"
    },
    {
      "offset": 5878936,
      "expected": "00013fd6",
      "replacement": "1f2003d5"
    },
    {
      "offset": 7099812,
      "expected": "00013fd6",
      "replacement": "1f2003d5"
    },
    {
      "offset": 6740620,
      "expected": "00013fd6",
      "replacement": "1f2003d5"
    },
    {
      "offset": 4921488,
      "expected": "00013fd6",
      "replacement": "1f2003d5"
    },
    {
      "offset": 5617916,
      "expected": "00013fd6",
      "replacement": "1f2003d5"
    },
    {
      "offset": 6758072,
      "expected": "00013fd6",
      "replacement": "1f2003d5"
    },
    {
      "offset": 7741248,
      "expected": "ff8300d1fd7b01a9",
      "replacement": "000080d2c0035fd6"
    },
    {
      "offset": 7741408,
      "expected": "fafaff97",
      "replacement": "d8ffff17"
    }
  ]
};
if (typeof Process === 'undefined') {
  if (process.argv[2] !== '--patch-plan') throw new Error('Use python run-pln.py; --patch-plan exports bootstrap definitions.');
  process.stdout.write(JSON.stringify(PLN_PATCH_PLAN));
} else {
// Local, in-memory experiment. No APK modifications.
const patched = new Set();
const base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function report(event, fields) { send(Object.assign({event:event,pid:Process.id},fields||{})); }
function decodeBase64(value) {
  let binary = '';
  for (let i = 0; i < value.length; i += 4) {
    const a = base64Chars.indexOf(value[i]);
    const b = base64Chars.indexOf(value[i + 1]);
    const c = value[i + 2] === '=' ? 64 : base64Chars.indexOf(value[i + 2]);
    const d = value[i + 3] === '=' ? 64 : base64Chars.indexOf(value[i + 3]);
    binary += String.fromCharCode((a << 2) | (b >> 4));
    if (c !== 64) binary += String.fromCharCode(((b & 15) << 4) | (c >> 2));
    if (d !== 64) binary += String.fromCharCode(((c & 3) << 6) | d);
  }
  return decodeURIComponent(Array.from(binary, c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join(''));
}
function encodeBase64(value) {
  const binary = encodeURIComponent(value).replace(/%([0-9A-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  let encoded = '';
  for (let i = 0; i < binary.length; i += 3) {
    const a = binary.charCodeAt(i);
    const b = i + 1 < binary.length ? binary.charCodeAt(i + 1) : NaN;
    const c = i + 2 < binary.length ? binary.charCodeAt(i + 2) : NaN;
    encoded += base64Chars[a >> 2];
    encoded += base64Chars[((a & 3) << 4) | (b >> 4)];
    encoded += Number.isNaN(b) ? '=' : base64Chars[((b & 15) << 2) | (c >> 6)];
    encoded += Number.isNaN(c) ? '=' : base64Chars[c & 63];
  }
  return encoded;
}
function readCppString(p) {
  const isLong = !!(p.readU8() & 1);
  const length = isLong ? p.add(8).readU64().toNumber() : p.readU8() >>> 1;
  return (isLong ? p.add(16).readPointer() : p.add(1)).readUtf8String(length);
}
function writeCppString(p, value) {
  const isLong = !!(p.readU8() & 1);
  if (!isLong) throw new Error('Replacement unexpectedly exceeds a short std::string');
  p.add(16).readPointer().writeUtf8String(value);
  p.add(8).writeU64(value.length);
}
function isRootThreat(threat) {
  const description = threat.lang_description || {};
  return /root|jailbreak|magisk/i.test([
    threat.internalName,
    threat.forensicJson,
    description.internalLocalizationName,
    description.deviceName
  ].join(' '));
}
function sanitizeDeviceStatus(payload) {
  const envelope = JSON.parse(payload);
  const status = JSON.parse(decodeBase64(envelope.device_status_base64));
  const before = status.threats.length;
  status.threats = status.threats.filter(threat => !isRootThreat(threat));
  if (status.threats.length === before) return null;
  envelope.device_status_base64 = encodeBase64(JSON.stringify(status));
  return {payload:JSON.stringify(envelope),removed:before-status.threats.length};
}
function installDeviceStatusFilter(module) {
  const timer = setInterval(function () {
    const post = module.base.add(0x840070).readPointer();
    if (post.isNull() || (post.compare(module.base) >= 0 && post.compare(module.base.add(module.size)) < 0)) return;
    clearInterval(timer);
    Interceptor.attach(post, {onEnter(args) {
      if (this.returnAddress.compare(module.base) < 0 || this.returnAddress.compare(module.base.add(module.size)) >= 0) return;
      try {
        const object = args[1];
        if (object.readS32() !== 3) return;
        const job = ptr(object.add(8).readU64().toString());
        const callable = job.add(8).readPointer().add(0x20).readPointer();
        const invoke = callable.readPointer().add(0x30).readPointer().sub(module.base);
        if (!invoke.equals(ptr(0x7797a0))) return;
        if (readCppString(callable.add(0x30)) !== 'com.zimperium.device.status') return;
        const payload = callable.add(0x48);
        const sanitized = sanitizeDeviceStatus(readCppString(payload));
        if (sanitized === null) return;
        writeCppString(payload, sanitized.payload);
        report('root-threats-filtered', {removed:sanitized.removed});
      } catch (error) {
        report('root-filter-error', {error:String(error)});
      }
    }});
  }, 10);
}
if (!isRootThreat({internalName:'rooted_files'}) || isRootThreat({internalName:'network_anomaly'})) {
  throw new Error('Root threat matcher self-check failed');
}
const linker = Process.getModuleByName('linker64');
const constructors = linker.enumerateSymbols().filter(s => /soinfo.*call_constructors/.test(s.name));
if (constructors.length !== 1) throw new Error('Expected one call_constructors: '+JSON.stringify(constructors));
function patchTarget(m) {
    if (patched.has(m.base.toString())) return;
    patched.add(m.base.toString());
    installDeviceStatusFilter(m);
    for (const patch of PLN_PATCH_PLAN.patches) {
      const at = m.base.add(patch.offset);
      const current = Array.from(new Uint8Array(at.readByteArray(patch.expected.length / 2)),
        x => x.toString(16).padStart(2, '0')).join('');
      if (current !== patch.expected && current !== patch.replacement)
        throw new Error('Unexpected native bytes at ' + patch.offset.toString(16));
      if (current !== patch.replacement) {
        const bytes = patch.replacement.match(/../g).map(x => parseInt(x, 16));
        Memory.patchCode(at, bytes.length, code => code.writeByteArray(bytes));
      }
    }
    report('root-enforcement-patches-verified', {module:m.name, count:PLN_PATCH_PLAN.patches.length});
    report('target-patched', {module:m.name});
    constructorListener.detach();
}
const constructorListener=Interceptor.attach(constructors[0].address, {
  onEnter() {
    const m = Process.enumerateModules().find(x => /liboutlookinvolve\.so$/.test(x.name));
    if (m) patchTarget(m);
  }
});
const loadedTarget = Process.enumerateModules().find(x => /liboutlookinvolve\.so$/.test(x.name));
if (loadedTarget) patchTarget(loadedTarget);

}
