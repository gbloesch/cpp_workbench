'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { runNative } = require('./nativeRunner');

function validateFindings(findings, bytes) {
  if (!Array.isArray(findings) || findings.length > 10000) throw new Error('Invalid findings array');
  for (const f of findings) {
    if (!['memory-leak', 'sql-injection'].includes(f.type) || !Number.isInteger(f.startByte) || !Number.isInteger(f.endByte) || f.startByte < 0 || f.endByte < f.startByte || f.endByte > bytes || typeof f.message !== 'string' || typeof f.ruleId !== 'string') throw new Error('Invalid finding from native analyzer');
  }
}
function documentKey(uri) { return crypto.createHash('sha256').update(uri).digest('hex').slice(0, 24); }
class AnalysisPipeline {
  constructor(extensionPath, storagePath) {
    this.extensionPath = extensionPath; this.storagePath = storagePath;
    this.bin = path.join(extensionPath, 'bin', `${process.platform}-${process.arch}`);
  }
  executable(name) { return path.join(this.bin, name + (process.platform === 'win32' ? '.exe' : '')); }
  async analyze(snapshot, timeoutMs, signal) {
    const key = documentKey(snapshot.uri);
    // One job per document at a time. Version subfolders prevent cross-version mixing.
    const folder = path.join(this.storagePath, 'jobs', key, String(snapshot.version));
    const securityFolder = path.join(folder, 'security');
    const patternsFolder = path.join(folder, 'patterns');
    await Promise.all([fs.mkdir(securityFolder, { recursive: true }), fs.mkdir(patternsFolder, { recursive: true })]);
    try {
      // Two separate source copies: one for each requested C++ program.
      await Promise.all([
        fs.writeFile(path.join(securityFolder, 'snapshot.cpp'), snapshot.source, 'utf8'),
        fs.writeFile(path.join(patternsFolder, 'snapshot.cpp'), snapshot.source, 'utf8')
      ]);
      const rules = JSON.parse(await fs.readFile(path.join(this.extensionPath, 'rules', 'security-rules.json'), 'utf8'));
      const securitySource = await fs.readFile(path.join(securityFolder, 'snapshot.cpp'), 'utf8');
      const analysis = await runNative(this.executable('security_analyzer'), { source: securitySource, rules }, timeoutMs, signal);
      validateFindings(analysis.findings, Buffer.byteLength(securitySource));
      await fs.writeFile(path.join(securityFolder, 'findings.json'), JSON.stringify(analysis, null, 2));
      const patternSource = await fs.readFile(path.join(patternsFolder, 'snapshot.cpp'), 'utf8');
      const report = await runNative(this.executable('pattern_analyzer'), { source: patternSource, analysis }, timeoutMs, signal);
      validateFindings(report.findings, Buffer.byteLength(patternSource));
      if (!Array.isArray(report.rows) || report.totalFindings !== report.findings.length) throw new Error('Invalid pattern report');
      report.documentUri = snapshot.uri; report.filePath = snapshot.filePath;
      report.documentVersion = snapshot.version; report.analyzedAt = new Date().toISOString();
      report.sourceHash = crypto.createHash('sha256').update(snapshot.source).digest('hex');
      await fs.writeFile(path.join(patternsFolder, 'report.json'), JSON.stringify(report, null, 2));
      return { report, folder, key };
    } catch (error) { await fs.rm(folder, { recursive: true, force: true }); throw error; }
  }
  async publish(job) {
    const latest = path.join(this.storagePath, 'snapshots', job.key);
    await fs.mkdir(path.dirname(latest), { recursive: true });
    await fs.rm(latest, { recursive: true, force: true });
    await fs.rename(job.folder, latest);
    await fs.writeFile(path.join(latest, 'document.json'), JSON.stringify({ uri: job.report.documentUri, filePath: job.report.filePath, version: job.report.documentVersion }, null, 2));
  }
  async discard(job) { await fs.rm(job.folder, { recursive: true, force: true }); }
  async remove(uri) { await fs.rm(path.join(this.storagePath, 'snapshots', documentKey(uri)), { recursive: true, force: true }); }
}
function byteOffsetToUtf16(source, byte) { return Buffer.from(source, 'utf8').subarray(0, byte).toString('utf8').length; }
module.exports = { AnalysisPipeline, byteOffsetToUtf16, validateFindings };
