'use strict';
const vscode = require('vscode');
const fs = require('node:fs/promises');
const path = require('node:path');
const { AnalysisPipeline, byteOffsetToUtf16 } = require('./pipeline');
const { aggregate, renderPatterns } = require('./reports');

async function activate(context) 
{
  const output = vscode.window.createOutputChannel('C++ Security Workbench');
  const diagnostics = vscode.languages.createDiagnosticCollection('cpp-security-workbench');
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 30);
  status.command = 'cppSecurity.patterns'; status.text = '$(shield) C++ Security'; status.tooltip = 'View security patterns'; status.show();
  
  context.subscriptions.push(output, diagnostics, status);
  // Each VS Code extension host gets its own directory, so two windows do not
  // delete each other's snapshots. Remove only abandoned host sessions.
  
  const storageRoot = context.globalStorageUri.fsPath;
  await fs.mkdir(storageRoot, { recursive: true });
  
  for (const name of await fs.readdir(storageRoot)) 
    {
    const match = /^session-(\d+)$/.exec(name);
    if (!match || Number(match[1]) === process.pid) continue;
    try { process.kill(Number(match[1]), 0); }
    catch (error) { if (error.code === 'ESRCH') await fs.rm(path.join(storageRoot, name), { recursive: true, force: true }); }
  }

  const storage = path.join(storageRoot, `session-${process.pid}`);
  await fs.mkdir(storage, { recursive: true });
  // This is a current-session report, not a history of users' source code.
  await Promise.all(['jobs', 'snapshots'].map(name => fs.rm(path.join(storage, name), { recursive: true, force: true })));

  const pipeline = new AnalysisPipeline(context.extensionPath, storage);
  const reports = new Map(), states = new Map(), seen = new Map(), queue = new Map();
  const manualScans = new Set();
  let panel, timer, refreshTimer, running = false, disposed = false, activeController;
  let errorNotified = false;
  const configuration = () => vscode.workspace.getConfiguration('cppSecurity');
  const isCpp = doc => !doc.isClosed && doc.languageId === 'cpp' && ['file', 'untitled'].includes(doc.uri.scheme);
  const buildReport = () => aggregate(reports.values(), [...states.values()]);

  function refresh() {
    if (disposed) return;
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(() => {
      if (disposed) return;
      const report = buildReport();
      if (panel) panel.webview.html = renderPatterns(report);
      status.text = `$(shield) C++: ${report.totals.findings} findings`;
      fs.writeFile(path.join(storage, 'patterns-latest.json'), JSON.stringify(report, null, 2)).catch(e => output.appendLine(`[report] ${e.message}`));
    }, 100);
  }
  function invalidate(doc) {
    const key = doc.uri.toString();
    const changed = reports.delete(key) || states.get(key)?.state !== 'pending';
    diagnostics.delete(doc.uri);
    states.set(key, { documentUri: key, filePath: doc.fileName, version: doc.version, state: 'pending' });
    if (changed) refresh();
  }
  function enqueue(doc, force = false) {
    if (!isCpp(doc) || disposed) return;
    const key = doc.uri.toString();
    if (!force && seen.get(key) === doc.version) return;
    queue.set(key, doc);
    void pump();
  }
  function current(doc, version) { return !disposed && isCpp(doc) && doc.version === version; }
  function publishDiagnostics(doc, source, report) {
    const list = report.findings.map(f => {
      const range = new vscode.Range(doc.positionAt(byteOffsetToUtf16(source, f.startByte)), doc.positionAt(byteOffsetToUtf16(source, f.endByte)));
      const diagnostic = new vscode.Diagnostic(range, f.message, vscode.DiagnosticSeverity.Warning);
      diagnostic.source = 'C++ Security Workbench';
      diagnostic.code = { value: f.ruleId, target: vscode.Uri.parse(f.cwe === 'CWE-401' ? 'https://cwe.mitre.org/data/definitions/401.html' : 'https://cwe.mitre.org/data/definitions/89.html') };
      if (f.relatedLocation) {
        const r = f.relatedLocation;
        const related = new vscode.Range(doc.positionAt(byteOffsetToUtf16(source, r.startByte)), doc.positionAt(byteOffsetToUtf16(source, r.endByte)));
        diagnostic.relatedInformation = [new vscode.DiagnosticRelatedInformation(new vscode.Location(doc.uri, related), r.message)];
      }
      return diagnostic;
    });
    diagnostics.set(doc.uri, list);
  }
  async function pump() {
    if (running || disposed) return;
    running = true;
    try {
      while (queue.size && !disposed) {
        const [key, doc] = queue.entries().next().value;
        queue.delete(key);
        if (!isCpp(doc)) continue;
        const version = doc.version, source = doc.getText();
        const snapshot = { uri: key, filePath: doc.fileName, version, source };
        seen.set(key, version); invalidate(doc);
        if (Buffer.byteLength(source, 'utf8') > configuration().get('maxFileBytes', 524288)) {
          states.set(key, { documentUri: key, filePath: doc.fileName, version, state: 'skipped', message: 'File exceeds cppSecurity.maxFileBytes.' });
          refresh(); continue;
        }
        states.set(key, { documentUri: key, filePath: doc.fileName, version, state: 'analyzing' }); refresh();
        const controller = new AbortController(); activeController = controller;
        try {
          const job = await pipeline.analyze(snapshot, configuration().get('analysisTimeoutMs', 10000), controller.signal);
          if (!current(doc, version)) { await pipeline.discard(job); continue; }
          await pipeline.publish(job);
          if (!current(doc, version)) { await pipeline.remove(key); continue; }
          reports.set(key, job.report);
          states.set(key, { documentUri: key, filePath: doc.fileName, version, state: 'complete', analyzedAt: job.report.analyzedAt });
          publishDiagnostics(doc, source, job.report);

          if (manualScans.has(key)) 
          {
            manualScans.delete(key);
            if (job.report.totalFindings === 0) 
            {
              vscode.window.showInformationMessage(
              'C++ Security: Analysis complete! No security issues found.');
            }  
          }

          output.appendLine(`[scan] ${doc.fileName} | version ${version} | ${job.report.totalFindings} findings | copies: ${path.join(storage, 'snapshots', job.key)}`);
        } catch (error) {
          if (current(doc, version)) {
            reports.delete(key); diagnostics.delete(doc.uri);
            states.set(key, { documentUri: key, filePath: doc.fileName, version, state: 'failed', message: error.message });
            output.appendLine(`[error] ${doc.fileName}: ${error.message}`);
            if (!errorNotified) { errorNotified = true; vscode.window.showErrorMessage(`C++ Security: ${error.message}`); }
          }
        } finally { if (activeController === controller) activeController = undefined; refresh(); }
      }
    } finally { running = false; }
  }
  function tick() {
    if (!configuration().get('enabled', true)) return;
    for (const doc of vscode.workspace.textDocuments) enqueue(doc);
  }
  function restartTimer() {
    clearInterval(timer);
    const interval = Math.max(100, Math.min(60000, Number(configuration().get('scanIntervalMs', 500)) || 500));
    timer = setInterval(tick, interval);
    output.appendLine(`[settings] Scan interval: ${interval} ms. Settings: cppSecurity.scanIntervalMs / cppSecurity.websiteUrl`);
    tick();
  }
  context.subscriptions.push(
    vscode.commands.registerCommand('cppSecurity.scan', () => {
      const doc = vscode.window.activeTextEditor?.document;
      if (!doc || !isCpp(doc)) return vscode.window.showInformationMessage('Open a C++ document, then select Analyze.');
      errorNotified = false;
      manualScans.add(doc.uri.toString());
      enqueue(doc, true);
    }),
    vscode.commands.registerCommand('cppSecurity.website', async () => {
      const value = configuration().get('websiteUrl', 'https://example.com');
      try {
        const url = new URL(value);
        if (!['https:', 'http:'].includes(url.protocol)) throw new Error('Use an HTTP or HTTPS URL.');
        const opened = await vscode.env.openExternal(vscode.Uri.parse(url.href));
        if (!opened) vscode.window.showErrorMessage('C++ Security could not open the website.');
      } catch (error) { vscode.window.showErrorMessage(`Edit cppSecurity.websiteUrl in Settings. ${error.message}`); }
    }),
    vscode.commands.registerCommand('cppSecurity.patterns', () => {
      if (panel) panel.reveal(vscode.ViewColumn.Beside);
      else {
        panel = vscode.window.createWebviewPanel('cppSecurityPatterns', 'Security Patterns', vscode.ViewColumn.Beside, { enableScripts: false, localResourceRoots: [] });
        panel.onDidDispose(() => { panel = undefined; });
      }
      panel.webview.html = renderPatterns(buildReport());
    }),
    vscode.commands.registerCommand('cppSecurity.export', async () => {
      const uri = await vscode.window.showSaveDialog({ defaultUri: vscode.Uri.file(path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || storage, 'security-patterns.json')), filters: { JSON: ['json'] } });
      if (!uri) return;
      try { await vscode.workspace.fs.writeFile(uri, Buffer.from(JSON.stringify(buildReport(), null, 2), 'utf8')); vscode.window.showInformationMessage('Security pattern report exported.'); }
      catch (error) { vscode.window.showErrorMessage(`Export failed: ${error.message}`); }
    }),
    vscode.commands.registerCommand('cppSecurity.snapshots', async () => {
      const folder = path.join(storage, 'snapshots'); await fs.mkdir(folder, { recursive: true });
      await vscode.env.openExternal(vscode.Uri.file(folder));
    }),
    vscode.workspace.onDidOpenTextDocument(doc => { if (isCpp(doc) && configuration().get('enabled', true)) { invalidate(doc); enqueue(doc); } }),
    vscode.workspace.onDidChangeTextDocument(event => { if (isCpp(event.document) && event.contentChanges.length) invalidate(event.document); }),
    vscode.workspace.onDidCloseTextDocument(doc => {
      const key = doc.uri.toString(); queue.delete(key); seen.delete(key); reports.delete(key); states.delete(key); diagnostics.delete(doc.uri);
      pipeline.remove(key).catch(e => output.appendLine(`[cleanup] ${e.message}`)); refresh();
    }),
    vscode.workspace.onDidChangeConfiguration(event => { if (event.affectsConfiguration('cppSecurity')) restartTimer(); }),
    { dispose: () => { disposed = true; clearInterval(timer); clearTimeout(refreshTimer); activeController?.abort(); queue.clear(); panel?.dispose(); } }
  );
  restartTimer(); refresh();
}
function deactivate() {}
module.exports = { activate, deactivate };
