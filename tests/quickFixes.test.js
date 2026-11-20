'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { getGuidance, renderGuidance, registerQuickFixes } = require('../src/quickFixes');

test('each detector has non-destructive remediation guidance', () => {
  for (const type of ['sql-injection', 'memory-leak', 'integer-overflow']) {
    const guide = getGuidance(type);
    assert.ok(guide);
    const text = renderGuidance(type, 'Example finding');
    assert.match(text, /Example finding/);
    assert.match(text, /not an automatic patch/);
    assert.match(text, /has not changed your source file/);
  }
  assert.equal(renderGuidance('unknown'), null);
});

test('quick fixes use only this extensions diagnostics and do not modify the document', () => {
  let provider;
  const registrations = [];
  const ctx = { subscriptions: registrations };
  const mock = {
    CodeActionKind: { QuickFix: 'quickfix' },
    CodeAction: class {
      constructor(title, kind) { this.title = title; this.kind = kind; }
    },
    commands: { registerCommand: () => ({ dispose() {} }) },
    languages: {
      registerCodeActionsProvider(_selector, value) {
        provider = value;
        return { dispose() {} };
      }
    }
  };
  registerQuickFixes(mock, ctx);
  assert.equal(registrations.length, 2);
  const diagnostics = [
    { source: 'C++ Security Workbench', code: { value: 'sql.tainted-query' }, message: 'SQL risk' },
    { source: 'C++ Security Workbench', code: { value: 'memory.unreleased' }, message: 'Leak risk' },
    { source: 'C++ Security Workbench', code: { value: 'integer.overflow-proven' }, message: 'Overflow risk' },
    { source: 'Other extension', code: { value: 'sql.tainted-query' }, message: 'Other' }
  ];
  const actions = provider.provideCodeActions({}, null, { diagnostics });
  assert.equal(actions.length, 3);
  assert.ok(actions.every(action => action.kind === 'quickfix'));
  assert.ok(actions.every(action => action.edit === undefined));
  assert.deepEqual(actions.map(a => a.command.arguments[0]), ['sql-injection', 'memory-leak', 'integer-overflow']);
});
