'use strict';

// Guidance-only Quick Fixes: never silently rewrite potentially unsafe C++.
const guidance = Object.freeze({
  'sql-injection': {
    title: 'SQL injection: use bound parameters',
    why: 'Untrusted text may become SQL syntax when it is concatenated into a query.',
    steps: [
      'Keep the SQL statement constant, with placeholders for values.',
      'Prepare the statement with your database library.',
      'Bind each user-supplied value using that library\'s parameter binding API.',
      'Execute the prepared statement and handle errors and cleanup.'
    ],
    example: [
      '// SQLite example (adapt to your program):',
      'sqlite3_stmt* stmt = nullptr;',
      'sqlite3_prepare_v2(db, "SELECT * FROM users WHERE name = ?", -1, &stmt, nullptr);',
      'sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);',
      'while (sqlite3_step(stmt) == SQLITE_ROW) { /* process result */ }',
      'sqlite3_finalize(stmt);'
    ].join('\n'),
    note: 'Illustrative SQLite code only. Check all return codes and use your actual database API.'
  },
  'memory-leak': {
    title: 'Memory leak: use automatic ownership',
    why: 'An allocated object may be lost or a path may exit before the corresponding release.',
    steps: [
      'Find the allocation and identify which scope owns it.',
      'Prefer std::unique_ptr<T> or std::vector<T> instead of manually managed new/delete.',
      'For C allocations, ensure free() runs on every required path, or use an RAII wrapper.',
      'Do not mechanically insert delete: ownership may have been transferred.'
    ],
    example: [
      '#include <memory>',
      'auto number = std::make_unique<int>(42);',
      '// Destruction releases owned memory automatically.'
    ].join('\n'),
    note: 'Only replace ownership patterns after verifying allocation and lifetime semantics.'
  },
  'integer-overflow': {
    title: 'Integer overflow: check before calculating',
    why: 'Signed overflow is undefined behavior in C++.',
    steps: [
      'Identify the signed type and permitted value range.',
      'Validate operands before arithmetic, or use a suitably wider type.',
      'For checked addition, compare against INT_MAX / INT_MIN before adding.',
      'Do not assume a wider destination alone makes a narrow intermediate expression safe.'
    ],
    example: [
      '#include <climits>',
      '#include <stdexcept>',
      'if ((b > 0 && a > INT_MAX - b) || (b < 0 && a < INT_MIN - b))',
      '    throw std::overflow_error("int addition overflow");',
      'int result = a + b;'
    ].join('\n'),
    note: 'Addition example only. Subtraction, multiplication, and increment need operation-specific checks.'
  }
});

function getGuidance(type) { return guidance[type] || null; }
function renderGuidance(type, findingMessage = '') {
  const g = getGuidance(type);
  if (!g) return null;
  return [
    '# ' + g.title,
    '',
    '**Reported finding:** ' + (findingMessage || 'Review the highlighted source code.'),
    '',
    '**Why it matters:** ' + g.why,
    '',
    '## Recommended approach',
    ...g.steps.map((step, i) => String(i + 1) + '. ' + step),
    '',
    '## Example (review and adapt; not an automatic patch)',
    '```cpp',
    g.example,
    '```',
    '',
    '**Important:** ' + g.note,
    '',
    'This recommendation is informational. The extension has not changed your source file.'
  ].join('\n');
}
function registerQuickFixes(vscode, context) {
  const command = 'cppSecurity.reviewQuickFix';
  context.subscriptions.push(
    vscode.commands.registerCommand(command, async (type, message) => {
      const markdown = renderGuidance(type, message);
      if (!markdown) return;
      const document = await vscode.workspace.openTextDocument({ language: 'markdown', content: markdown });
      await vscode.window.showTextDocument(document, { viewColumn: vscode.ViewColumn.Beside, preview: true, preserveFocus: false });
    }),
    vscode.languages.registerCodeActionsProvider(
      { language: 'cpp', scheme: 'file' },
      {
        provideCodeActions(document, range, codeActionContext) {
          const actions = [];
          for (const diagnostic of codeActionContext.diagnostics) {
            if (diagnostic.source !== 'C++ Security Workbench') continue;
            const type = diagnostic.code && typeof diagnostic.code === 'object'
              ? String(diagnostic.code.value || '') : String(diagnostic.code || '');
            const findingType = type.startsWith('sql.') ? 'sql-injection'
              : type.startsWith('memory.') ? 'memory-leak'
              : type.startsWith('integer.') ? 'integer-overflow' : null;
            if (!findingType) continue;
            const action = new vscode.CodeAction(
              'C++ Security: Review suggested fix (' + findingType + ')',
              vscode.CodeActionKind.QuickFix
            );
            action.diagnostics = [diagnostic];
            action.command = {
              title: 'Review suggested fix',
              command,
              arguments: [findingType, diagnostic.message]
            };
            // Do not set an edit: complex security remediation needs human review.
            actions.push(action);
          }
          return actions;
        }
      },
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );
}
module.exports = { getGuidance, renderGuidance, registerQuickFixes };
