'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { getGuidance, renderGuidance, constantOverflowEdit, registerQuickFixes } = require('../src/quickFixes');
const code = 'int bad = 2147483647 + 1; // overflow';
const vscode = {
  Range: class {
    constructor(lineA, charA, lineB, charB) {
      this.start = { line: lineA, character: charA };
      this.end = { line: lineB, character: charB };
    }
  },
  CodeActionKind: { QuickFix: 'quickfix' },
  CodeAction: class {
    constructor(title, kind) { this.title = title; this.kind = kind; }
  },
  WorkspaceEdit: class {
    constructor() { this.edits = []; }
    replace(uri, range, replacement) { this.edits.push({ uri, range, replacement }); }
  }
};
function document(text) {
  return { languageId: 'cpp', uri: 'file:///test.cpp', lineAt: () => ({ text }) };
}
function diagnostic(rule, position = 21) {
  return { source: 'C++ Security Workbench', code: { value: rule },
    range: { start: { line: 0, character: position } }, message: 'overflow' };
}
test('informational guidance remains available as a helper', () => {
  for (const type of ['sql-injection', 'memory-leak', 'integer-overflow']) {
    assert.ok(getGuidance(type));
    assert.match(renderGuidance(type), /Recommended approach/);
  }
});
test('constant overflowing int declaration has a real edit', () => {
  const fix = constantOverflowEdit(vscode, document(code), diagnostic('integer.overflow-proven'));
  assert.equal(fix.replacement, 'long long bad = 2147483647LL + 1;');
});
test('safe and unknown expressions are not modified', () => {
  assert.equal(constantOverflowEdit(vscode, document('int safe = 10 + 20;'), diagnostic('integer.overflow-proven', 14)), null);
  assert.equal(constantOverflowEdit(vscode, document('int answer = x + 2;'), diagnostic('integer.overflow-proven', 15)), null);
});
test('the provider offers only a genuine workspace edit', () => {
  let provider;
  const mock = {
    ...vscode,
    languages: { registerCodeActionsProvider: (_selector, p) => {
      provider = p; return { dispose() {} };
    }}
  };
  const ctx = { subscriptions: [] };
  registerQuickFixes(mock, ctx);
  const result = provider.provideCodeActions(document(code), null,
    { diagnostics: [diagnostic('integer.overflow-proven'), diagnostic('sql.tainted-query')] });
  assert.equal(result.length, 1);
  assert.equal(result[0].kind, 'quickfix');
  assert.equal(result[0].edit.edits.length, 1);
  assert.match(result[0].edit.edits[0].replacement, /long long bad/);
});
