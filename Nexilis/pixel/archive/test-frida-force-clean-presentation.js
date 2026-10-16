'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(
  path.join(__dirname, '..', 'frida-force-clean-presentation.js'),
  'utf8'
);

assert.match(source, /FLAG_SECURE/);
assert.match(source, /clearFlags/);
assert.match(source, /setSecure/);
assert.match(source, /SCREEN SHARING ENABLED/);
assert.match(source, /pixel-application-running/);

console.log('presentation screen-sharing checks passed');
