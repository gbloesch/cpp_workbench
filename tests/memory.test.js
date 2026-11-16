
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');

const executable = path.join(
  root,
  'bin',
  `${process.platform}-${process.arch}`,
  'security_analyzer' + (process.platform === 'win32' ? '.exe' : '')
);

const rules = {
  schemaVersion: 1,
  sqlEnabled: false,
  memoryEnabled: true
};

function analyze(source) {
  const result = spawnSync(executable, [], {
    input: JSON.stringify({ source, rules }),
    encoding: 'utf8',
    timeout: 5000,
    maxBuffer: 8 * 1024 * 1024
  });

  if (result.error) throw result.error;

  assert.equal(
    result.status,
    0,
    result.stderr || `Analyzer exited with ${result.status}`
  );

  return JSON.parse(result.stdout);
}

function memoryFindings(source) {
  return analyze(source).findings.filter(
    finding => finding.type === 'memory-leak'
  );
}

test('new with delete does not leak', () => {
  const source = 'void f() { int* p = new int(5); delete p; }';
  assert.equal(memoryFindings(source).length, 0);
});

test('new without delete reports a leak', () => {
  const source = 'void f() { int* p = new int(5); }';
  assert.equal(memoryFindings(source).length, 1);
});

test('new array with delete array does not leak', () => {
  const source = 'void f() { int* p = new int[10]; delete[] p; }';
  assert.equal(memoryFindings(source).length, 0);
});

test('malloc with free does not leak', () => {
  const source =
    'void f() { int* p = (int*)malloc(40); free(p); }';

  assert.equal(memoryFindings(source).length, 0);
});

test('malloc without free reports a leak', () => {
  const source =
    'void f() { int* p = (int*)malloc(40); }';

  assert.equal(memoryFindings(source).length, 1);
});

test('new with free must report mismatched deallocation', () => {
  const source = 'void f() { int* p = new int(5); free(p); }';

  assert.ok(
    memoryFindings(source).length > 0,
    'Expected a memory diagnostic for mismatched deallocation'
  );
});

test('malloc with delete must report mismatched deallocation', () => {
  const source =
    'void f() { int* p = (int*)malloc(40); delete p; }';

  assert.ok(
    memoryFindings(source).length > 0,
    'Expected a memory diagnostic for mismatched deallocation'
  );
});

test('new array with scalar delete must report mismatch', () => {
  const source =
    'void f() { int* p = new int[10]; delete p; }';

  assert.ok(
    memoryFindings(source).length > 0,
    'Expected a memory diagnostic for mismatched deallocation'
  );
});

test('scalar new with delete array must report mismatch', () => {
  const source =
    'void f() { int* p = new int(5); delete[] p; }';

  assert.ok(
    memoryFindings(source).length > 0,
    'Expected a memory diagnostic for mismatched deallocation'
  );
});
