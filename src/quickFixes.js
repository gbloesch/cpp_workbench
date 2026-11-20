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
// Deliberately narrow: only constant arithmetic in a simple int declaration.
// Converts both the destination and arithmetic into 64-bit signed long long.
// No action is offered for unknown values, SQL, or memory ownership.
function constantOverflowEdit(vscode, document, diagnostic) {
  if (document.languageId !== 'cpp' || !diagnostic.range) return null;
  const lineNumber = diagnostic.range.start.line;
  const line = document.lineAt(lineNumber).text;
  const pattern = /^(\\s*)int\\s+([A-Za-z_]\\w*)\\s*=\\s*(\\d+)\\s*([+*\\-])\\s*(\\d+)\\s*;/;
  const match = pattern.exec(line);
  if (!match) return null;
  if (diagnostic.range.start.character < match.index ||
      diagnostic.range.start.character >= match[0].length) return null;
  let left, right;
  try { left = BigInt(match[3]); right = BigInt(match[5]); }
  catch { return null; }
  const min = -2147483648n, max = 2147483647n;
  // Only transform int32 nonnegative literals; wider literal semantics need review.
  if (left > max || right > max) return null;
  const result = match[4] === '+' ? left + right
    : match[4] === '-' ? left - right : left * right;
  if (result >= min && result <= max) return null;
  if (result < -(2n ** 63n) || result > (2n ** 63n - 1n)) return null;
  const replacement = match[1] + 'long long ' + match[2] +
    ' = ' + match[3] + 'LL ' + match[4] + ' ' + match[5] + ';';
  return {
    range: new vscode.Range(lineNumber, 0, lineNumber, match[0].length),
    replacement
  };
}

function registerQuickFixes(vscode, context) {
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { language: 'cpp', scheme: 'file' },
      {
        provideCodeActions(document, range, codeActionContext) {
          const actions = [];
          for (const diagnostic of codeActionContext.diagnostics) {
            if (diagnostic.source !== 'C++ Security Workbench') continue;
            const rule = diagnostic.code && typeof diagnostic.code === 'object'
              ? String(diagnostic.code.value || '') : String(diagnostic.code || '');
            if (rule !== 'integer.overflow-proven' && rule !== 'integer.overflow-constant') continue;
            const fix = constantOverflowEdit(vscode, document, diagnostic);
            if (!fix) continue;
            const action = new vscode.CodeAction(
              'C++ Security: Use 64-bit arithmetic for this constant expression',
              vscode.CodeActionKind.QuickFix
            );
            action.diagnostics = [diagnostic];
            action.edit = new vscode.WorkspaceEdit();
            action.edit.replace(document.uri, fix.range, fix.replacement);
            actions.push(action);
          }
          return actions;
        }
      },
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );
}
module.exports = { getGuidance, renderGuidance, constantOverflowEdit, registerQuickFixes };
