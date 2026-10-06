'use strict';
const { spawn } = require('node:child_process');
function runNative(executable, request, timeoutMs = 10000, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error('Analysis cancelled'));
    const child = spawn(executable, [], { shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    const chunks = []; let bytes = 0, stderr = '', finished = false;
    const finish = (error, result) => {
      if (finished) return; finished = true;
      clearTimeout(timer); signal?.removeEventListener('abort', abort);
      if (error) { child.kill(); reject(error); } else resolve(result);
    };
    const abort = () => finish(new Error('Analysis cancelled'));
    const timer = setTimeout(() => finish(new Error(`Analyzer exceeded ${timeoutMs} ms`)), timeoutMs);
    signal?.addEventListener('abort', abort, { once: true });
    child.on('error', error => finish(new Error(`Cannot start analyzer: ${error.message}. Run node scripts/build.js in the extension folder.`)));
    child.stdin.on('error', error => { if (error.code !== 'EPIPE') finish(error); });
    child.stdout.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > 8 * 1024 * 1024) return finish(new Error('Analyzer output exceeds 8 MiB'));
      chunks.push(chunk);
    });
    child.stderr.on('data', chunk => { stderr = (stderr + chunk.toString('utf8')).slice(-12000); });
    child.on('close', code => {
      if (finished) return;
      if (code !== 0) return finish(new Error(stderr.trim() || `Analyzer exited with ${code}`));
      try { finish(null, JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (error) { finish(new Error(`Invalid analyzer JSON: ${error.message}`)); }
    });
    child.stdin.end(JSON.stringify(request), 'utf8');
  });
}
module.exports = { runNative };
