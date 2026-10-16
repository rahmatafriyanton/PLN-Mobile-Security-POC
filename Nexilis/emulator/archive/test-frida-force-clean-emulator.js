'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(
  path.join(__dirname, '..', 'frida-force-clean-emulator.js'),
  'utf8'
);

assert.match(source, /\.nexilis_emulator_bootstrap\.json/);
assert.match(source, /emulator-provisioned/);
assert.match(source, /server status skipped for provisioned emulator/);
assert.match(source, /Pixel registration state supplied/);
assert.match(source, /Pixel payload key supplied from private storage/);
assert.match(source, /emulator-protected-runtime/);
assert.match(source, /EMBEDDED_BOOTSTRAP/);
assert.match(source, /provisioning written from embedded state/);
assert.doesNotMatch(
  source,
  /provisioning:start \*\/ null \/\* provisioning:end/
);

console.log('self-contained emulator Frida checks passed');
