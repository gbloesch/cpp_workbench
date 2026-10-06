'use strict';
const locations = ['for', 'while', 'do-while', 'if', 'else', 'case', 'default', 'switch', 'try', 'catch', 'function', 'global-or-unknown'];
const labels = { for: 'For loop', while: 'While loop', 'do-while': 'Do / while loop', if: 'If branch', else: 'Else branch', case: 'Switch case', default: 'Switch default', switch: 'Switch condition / body', try: 'Try block', catch: 'Catch block', function: 'Function body', 'global-or-unknown': 'Global / unrecognized' };
const percentage = (n, d) => d ? Math.round(10000 * n / d) / 100 : 0;
function aggregate(reports, statuses = []) {
  const documents = [...reports].sort((a, b) => a.filePath.localeCompare(b.filePath));
  const findings = documents.flatMap(d => d.findings.map(f => ({ ...f, filePath: d.filePath, documentUri: d.documentUri, documentVersion: d.documentVersion })));
  const totals = { 'memory-leak': 0, 'sql-injection': 0 };
  const counts = new Map();
  // Sum C++-produced category counts; do not reclassify code in JavaScript.
  for (const d of documents) {
    totals['memory-leak'] += d.memoryLeakCount; totals['sql-injection'] += d.sqlInjectionCount;
    for (const row of d.rows) { const key = `${row.type}:${row.location}`; counts.set(key, (counts.get(key) || 0) + row.count); }
  }
  const total = findings.length;
  const rows = Object.keys(totals).flatMap(type => locations.map(location => {
    const count = counts.get(`${type}:${location}`) || 0;
    return { type, location, label: labels[location], count, percentOfType: percentage(count, totals[type]), percentOfAll: percentage(count, total) };
  }));
  return {
    schemaVersion: 1, generatedAt: new Date().toISOString(),
    scope: 'latest-completed-scan-of-currently-open-cpp-documents',
    counting: { unit: 'distinct finding in the current document version', primaryLocation: 'innermost recognized construct; memory leaks use the allocation site', percentOfTypeDenominator: 'all findings of the same type', percentOfAllDenominator: 'all findings of both types', repeatedScansAccumulate: false },
    totals: { documents: documents.length, findings: total, memoryLeaks: totals['memory-leak'], sqlInjections: totals['sql-injection'] },
    rows, findings, documents, documentStatuses: statuses
  };
}
const escapeHtml = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function renderPatterns(report) {
  const e = escapeHtml;
  const total = report.totals;
  const table = type => `<table><thead><tr><th>Location</th><th>Count</th><th>% of this type</th><th>% of all findings</th></tr></thead><tbody>${report.rows.filter(r => r.type === type).map(r => `<tr><td>${e(r.label)}</td><td>${r.count}</td><td>${r.percentOfType.toFixed(2)}%</td><td>${r.percentOfAll.toFixed(2)}%</td></tr>`).join('')}</tbody></table>`;
  const statuses = report.documentStatuses.filter(s => s.state !== 'complete');
  const notes = report.documents.flatMap(d => (d.analysis.notes || []).map(n => `${d.filePath}: ${n}`));
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';"><title>Security Patterns</title><style>
  body{font-family:var(--vscode-font-family,system-ui);color:var(--vscode-foreground,#222);background:var(--vscode-editor-background,#fff);padding:24px;max-width:1100px;margin:auto;line-height:1.5}h1{margin-bottom:4px}h2{margin-top:30px}.muted{opacity:.8}.cards{display:flex;flex-wrap:wrap;gap:16px;margin:24px 0}.card{padding:14px 22px;border:1px solid var(--vscode-panel-border,#aaa);border-radius:6px}.card strong{display:block;font-size:28px}table{border-collapse:collapse;width:100%;margin:14px 0 22px}th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--vscode-panel-border,#ccc)}th{font-weight:600}td:not(:first-child){font-variant-numeric:tabular-nums}code{font-family:var(--vscode-editor-font-family,monospace)}li{margin-bottom:8px}.notice{padding:12px;border-left:3px solid var(--vscode-editorWarning-foreground,#a66b00);background:var(--vscode-textBlockQuote-background,#8881)}.path{overflow-wrap:anywhere}small{opacity:.85}details{margin-top:20px}
  </style></head><body><h1>Security Patterns</h1><p class="muted">Current findings across ${total.documents} analyzed open C++ document(s). Updated ${e(new Date(report.generatedAt).toLocaleString())}.</p>
  <div class="cards"><div class="card"><strong>${total.findings}</strong>Total findings</div><div class="card"><strong>${total.memoryLeaks}</strong>Possible memory leaks</div><div class="card"><strong>${total.sqlInjections}</strong>Possible SQL injections</div></div>
  <p class="notice">These are heuristic review findings, not verified vulnerabilities or a security certification. Zero findings means no supported rule matched. Each finding is counted once under its innermost recognized construct. Memory findings are grouped by allocation location; the possible exit path appears in the detail.</p>
  ${statuses.length ? `<h2>Scan status</h2><ul>${statuses.map(s => `<li class="path">${e(s.filePath)} — ${e(s.state)}${s.message ? ': ' + e(s.message) : ''}</li>`).join('')}</ul>` : ''}
  <h2>Memory leaks by location</h2>${table('memory-leak')}<h2>SQL injection by location</h2>${table('sql-injection')}
  <p><b>% of this type</b> = count ÷ findings of the same type × 100. <b>% of all findings</b> = count ÷ all findings × 100. These percentages describe reported findings, not the percentage of source lines that are flawed. Zero denominators display 0%. Rounded columns may differ slightly from 100%.</p>
  <p>Repeated timer scans replace the previous result. This view does not count keystrokes, historical mistakes, closed files, or individual people.</p>
  <h2>Finding details</h2>${report.findings.length ? `<ol>${report.findings.map(f => `<li><strong>${e(f.type)} · ${e(labels[f.primaryContext] || f.primaryContext)}</strong><br><span class="path">${e(f.filePath)}:${f.line}</span><br>${e(f.message)}<br><small>Nested location: ${e(f.contexts.join(' → '))}. ${e(f.evidence)}${f.relatedLocation ? ` Possible exit/overwrite: line ${f.relatedLocation.line}, ${e((f.relatedLocation.contexts || []).join(' → '))}.` : ''}</small></li>`).join('')}</ol>` : '<p>No findings in the completed scans currently shown.</p>'}
  ${notes.length ? `<details><summary>Analysis notes (${notes.length})</summary><ul>${notes.map(n => `<li class="path">${e(n)}</li>`).join('')}</ul></details>` : ''}
  <h2>Use this data on your website</h2><p>Run <b>C++ Security: Export Patterns JSON</b> from the Command Palette. Each item in <code>rows</code> contains <code>type</code>, <code>location</code>, <code>count</code>, <code>percentOfType</code>, and <code>percentOfAll</code>. Use those numeric fields as bar-chart values. The extension opens the configured website with the globe button.</p></body></html>`;
}
module.exports = { aggregate, renderPatterns, byteLocations: locations };
