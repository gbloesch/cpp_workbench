'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const vm = require('node:vm');

async function waitFor(predicate) {
  for (let i = 0; i < 100; ++i) { if (predicate()) return; await new Promise(r => setTimeout(r, 5)); }
  assert.fail('Timed out waiting for extension behavior');
}
async function fixture() {
  const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'cpp-extension-'));
  const handlers = {}, commands = {}, pending = [], published = [], discarded = [], diagnosticSets = [], openedUrls = [];
  const config = { enabled: false, scanIntervalMs: 500, websiteUrl: 'https://example.com/project', maxFileBytes: 524288, analysisTimeoutMs: 10000 };
  const disposable = { dispose() {} };
  const listen = key => callback => { handlers[key] = callback; return disposable; };
  const uri = { scheme: 'file', fsPath: '/demo.cpp', toString: () => 'file:///demo.cpp' };
  const doc = { uri, fileName: '/demo.cpp', version: 1, languageId: 'cpp', isClosed: false, source: 'void f(){ int* p=new int; }', getText() { return this.source; }, positionAt: offset => offset };
  class FakePipeline {
    analyze(snapshot, timeout, signal) {
      return new Promise((resolve, reject) => {
        pending.push({ snapshot, resolve, reject });
        signal.addEventListener('abort', () => reject(new Error('cancelled')), { once: true });
      });
    }
    async publish(job) { published.push(job.report.documentVersion); }
    async discard(job) { discarded.push(job.report.documentVersion); }
    async remove() {}
  }
  const vscode = {
    StatusBarAlignment: { Left: 1 }, ViewColumn: { Beside: 2 }, DiagnosticSeverity: { Warning: 1 },
    Uri: { file: p => ({ fsPath: p, toString: () => p }), parse: s => ({ toString: () => s }) },
    Range: class { constructor(start, end) { this.start = start; this.end = end; } },
    Diagnostic: class { constructor(range, message) { this.range = range; this.message = message; } },
    DiagnosticRelatedInformation: class {}, Location: class {},
    commands: { registerCommand: (id, fn) => { commands[id] = fn; return disposable; } },
    env: { openExternal: async uri => { openedUrls.push(uri.toString()); return true; } },
    languages: { createDiagnosticCollection: () => ({ set: (uri, ds) => diagnosticSets.push(ds), delete() {}, dispose() {} }) },
    window: {
      activeTextEditor: { document: doc },
      createOutputChannel: () => ({ appendLine() {}, dispose() {} }),
      createStatusBarItem: () => ({ show() {}, dispose() {} }),
      showErrorMessage() {}, showInformationMessage() {},
      createWebviewPanel: () => ({ webview: {}, reveal() {}, onDidDispose() {}, dispose() {} })
    },
    workspace: {
      textDocuments: [doc], getConfiguration: () => ({ get: (key, fallback) => config[key] ?? fallback }),
      onDidOpenTextDocument: listen('open'), onDidChangeTextDocument: listen('change'),
      onDidCloseTextDocument: listen('close'), onDidChangeConfiguration: listen('config')
    }
  };
  const filename = path.resolve(__dirname, '../src/extension.js');
  const sandbox = {
    module: { exports: {} }, process, Buffer, URL, AbortController, setTimeout, clearTimeout, setInterval, clearInterval,
    require: name => name === 'vscode' ? vscode : name === './pipeline' ? { AnalysisPipeline: FakePipeline, byteOffsetToUtf16: (s, b) => b } : name === './reports' ? require('../src/reports') : require(name)
  };
  vm.runInNewContext(fs.readFileSync(filename, 'utf8'), sandbox, { filename });
  const context = { subscriptions: [], globalStorageUri: { fsPath: storage }, extensionPath: path.resolve(__dirname, '..') };
  await sandbox.module.exports.activate(context);
  function finish(index) {
    const request = pending[index];
    const report = { documentVersion: request.snapshot.version, documentUri: uri.toString(), filePath: doc.fileName, analyzedAt: '2026-01-01', totalFindings: 0, memoryLeakCount: 0, sqlInjectionCount: 0, findings: [], rows: [], analysis: { notes: [] } };
    request.resolve({ report, key: 'test', folder: 'test' });
  }
  async function cleanup() {
    context.subscriptions.forEach(x => x.dispose());
    await new Promise(r => setTimeout(r, 10));
    fs.rmSync(storage, { recursive: true, force: true });
  }
  return { handlers, commands, pending, published, discarded, diagnosticSets, openedUrls, doc, config, finish, cleanup };
}

test('editing during a scan discards old results and analyzes the newest snapshot', async () => {
  const f = await fixture();
  try {
    f.commands['cppSecurity.scan'](); await waitFor(() => f.pending.length === 1);
    f.doc.version = 2; f.doc.source = 'void f(){}'; f.handlers.change({ document: f.doc, contentChanges: [{}] });
    f.commands['cppSecurity.scan']();
    f.finish(0); await waitFor(() => f.pending.length === 2);
    assert.deepEqual(f.discarded, [1]); assert.equal(f.published.length, 0); assert.equal(f.diagnosticSets.length, 0);
    assert.equal(f.pending[1].snapshot.source, 'void f(){}');
    f.finish(1); await waitFor(() => f.published.length === 1);
    assert.deepEqual(f.published, [2]); assert.equal(f.diagnosticSets.length, 1);
  } finally { await f.cleanup(); }
});
test('closing a file while analysis runs prevents publication', async () => {
  const f = await fixture();
  try {
    f.commands['cppSecurity.scan'](); await waitFor(() => f.pending.length === 1);
    f.doc.isClosed = true; f.handlers.close(f.doc); f.finish(0);
    await waitFor(() => f.discarded.length === 1);
    assert.equal(f.published.length, 0); assert.equal(f.diagnosticSets.length, 0);
  } finally { await f.cleanup(); }
});
test('timer settings take effect live; unchanged versions are not counted again', async () => {
  const f = await fixture();
  try {
    f.config.enabled = true; f.config.scanIntervalMs = 100;
    f.handlers.config({ affectsConfiguration: () => true });
    await waitFor(() => f.pending.length === 1); f.finish(0);
    await waitFor(() => f.published.length === 1);
    await new Promise(r => setTimeout(r, 230)); assert.equal(f.pending.length, 1);
    f.doc.version = 2; f.handlers.change({ document: f.doc, contentChanges: [{}] });
    await waitFor(() => f.pending.length === 2); f.finish(1);
    await waitFor(() => f.published.length === 2);
    await f.commands['cppSecurity.website']();
    assert.equal(f.openedUrls[0], 'https://example.com/project');
  } finally { await f.cleanup(); }
});
