'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const out = path.join(root, 'bin', `${process.platform}-${process.arch}`);
fs.mkdirSync(out, { recursive: true });
// CXX is an executable name or absolute path, not a shell command with flags.
const candidates = process.env.CXX ? [process.env.CXX] : ['g++', 'clang++', 'cl.exe'];
let compiler;
for (const candidate of candidates) {
  const probe = spawnSync(candidate, /(?:^|[\\/])cl(?:\.exe)?$/i.test(candidate) ? [] : ['--version'], { encoding: 'utf8', windowsHide: true });
  if (!probe.error) { compiler = candidate; break; }
}
if (!compiler) {
  console.error('No C++17 compiler found. Install GCC/MinGW or MSVC Build Tools.\nFor MSVC, run this build from Developer Command Prompt for Visual Studio.\nSee README.md, "Windows compiler setup". You can also set CXX to your compiler path.');
  process.exit(1);
}
const msvc = /(?:^|[\\/])cl(?:\.exe)?$/i.test(compiler);
for (const name of ['security_analyzer', 'pattern_analyzer']) {
  const input = path.join(root, 'native', `${name}.cpp`);
  const output = path.join(out, name + (process.platform === 'win32' ? '.exe' : ''));
  const args = msvc
    ? ['/nologo', '/std:c++17', '/EHsc', '/utf-8', '/W4', '/O2', '/MT', input, `/Fe:${output}`, `/Fo:${path.join(out, name + '.obj')}`]
    : ['-std=c++17', '-O2', '-Wall', '-Wextra', '-pedantic', input, '-o', output, ...(process.platform === 'win32' && /g\+\+/.test(compiler) ? ['-static'] : [])];
  console.log(`Building ${name} with ${compiler}...`);
  const result = spawnSync(compiler, args, { stdio: 'inherit', cwd: root, windowsHide: true });
  if (result.error) console.error(result.error.message);
  if (result.error || result.status !== 0) process.exit(1);
}
require('./check');
console.log('Build complete. Press F5 in VS Code to test the extension.');
