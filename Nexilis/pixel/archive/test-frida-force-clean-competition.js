'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(
  path.join(__dirname, '..', 'frida-force-clean-competition.js'),
  'utf8'
);

assert.match(source, /step\(\s*'01'/);
assert.match(source, /step\(\s*'12'/);
assert.match(source, /APPLICATION IS RUNNING/);
assert.match(source, /emulator-protected-runtime|pixel-application-running/);

console.log('competition trace checks passed');
