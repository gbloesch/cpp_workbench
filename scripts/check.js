'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
for (const folder of ['src', 'scripts', 'tests']) {
  for (const file of fs.readdirSync(path.join(root, folder)).filter(f => f.endsWith('.js'))) {
    const result = spawnSync(process.execPath, ['--check', path.join(root, folder, file)], { stdio: 'inherit' });
    if (result.status !== 0) process.exit(1);
  }
}
for (const name of ['security_analyzer', 'pattern_analyzer']) {
  const file = path.join(root, 'bin', `${process.platform}-${process.arch}`, name + (process.platform === 'win32' ? '.exe' : ''));
  if (!fs.existsSync(file)) { console.error(`Missing ${name}. Run: node scripts/build.js`); process.exit(1); }
}
console.log('JavaScript syntax and native executable paths checked.');
