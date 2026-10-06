'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { AnalysisPipeline, byteOffsetToUtf16 } = require('../src/pipeline');
const { aggregate, renderPatterns } = require('../src/reports');
const root = path.resolve(__dirname, '..');
const rules = JSON.parse(fs.readFileSync(path.join(root, 'rules/security-rules.json')));
const executable = name => path.join(root, 'bin', `${process.platform}-${process.arch}`, name + (process.platform === 'win32' ? '.exe' : ''));
function native(name, request) {
  const r = spawnSync(executable(name), [], { input: JSON.stringify(request), encoding: 'utf8', timeout: 5000, maxBuffer: 8 * 1024 * 1024 });
  assert.equal(r.status, 0, r.stderr || r.error?.message);
  return JSON.parse(r.stdout);
}
function analyze(source, override = {}) { return native('security_analyzer', { source, rules: { ...rules, ...override } }); }
function report(source) { return native('pattern_analyzer', { source, analysis: analyze(source) }); }
function flaws(source, type = 'memory-leak') { return analyze(source).findings.filter(f => f.type === type); }

test('sample: two memory findings, two SQL findings, expected percentages', () => {
  const r = report(fs.readFileSync(path.join(root, 'examples/vulnerable.cpp'), 'utf8'));
  assert.equal(r.memoryLeakCount, 2); assert.equal(r.sqlInjectionCount, 2);
  for (const [type, location] of [['memory-leak', 'for'], ['memory-leak', 'if'], ['sql-injection', 'for'], ['sql-injection', 'case']]) {
    const row = r.rows.find(x => x.type === type && x.location === location);
    assert.deepEqual([row.count, row.percentOfType, row.percentOfAll], [1, 50, 25]);
  }
});
test('safe examples have zero findings and finite zero percentages', () => {
  const r = report(fs.readFileSync(path.join(root, 'examples/safe.cpp'), 'utf8'));
  assert.equal(r.totalFindings, 0);
  assert(r.rows.every(row => row.percentOfAll === 0 && row.percentOfType === 0));
});
test('raw allocation and malloc are reported', () => {
  assert.equal(flaws('void f(){ int* p=new int(1); }').length, 1);
  assert.equal(flaws('void f(){ char* p=(char*)malloc(100); }').length, 1);
});
test('cleanup through aliases and array cleanup are recognized', () => {
  assert.equal(flaws('void f(){ int* p=new int(1); auto q=p; delete q; }').length, 0);
  assert.equal(flaws('void f(){ int* p=new int[3]; delete[] p; }').length, 0);
  assert.equal(flaws('void f(){ auto p=malloc(10); free(p); }').length, 0);
});
test('early return leaks despite a later delete', () => {
  const f = flaws('void f(bool error){ int* p=new int(1); if(error) return; delete p; }');
  assert.equal(f.length, 1); assert.match(f[0].message, /exit can skip cleanup/);
});
test('cleanup on both if branches is safe', () => {
  assert.equal(flaws('void f(bool b){ int* p=new int; if(b) delete p; else delete p; }').length, 0);
});
test('malloc null failure branch is not treated as a successful allocation', () => {
  assert.equal(flaws('void f(){ auto p=malloc(10); if(!p) return; free(p); }').length, 0);
});
test('pointer overwrite and direct realloc assignment are detected', () => {
  assert.equal(flaws('void f(){ int* p=new int; p=nullptr; }').length, 1);
  assert(analyze('void f(){ auto p=malloc(10); p=realloc(p,20); free(p); }').findings.some(f => f.ruleId === 'memory.realloc-overwrite'));
});
test('returned pointers and unknown ownership transfers are not falsely claimed as leaks', () => {
  assert.equal(flaws('int* f(){ int* p=new int; return p; }').length, 0);
  assert.equal(flaws('void f(){ int* p=new int; takeOwnership(p); }').length, 0);
});
test('raw smart-pointer ownership is cleaned up on early return', () => {
  assert.equal(flaws('void f(bool b){ std::unique_ptr<int> p(new int); if(b) return; }').length, 0);
});
test('shadowed pointers restore outer ownership bindings', () => {
  assert.equal(flaws('void f(){ int* p=new int; { int* p=new int; delete p; } delete p; }').length, 0);
});
test('comments and ordinary/raw strings are not executable code', () => {
  const s = 'void f(){ // int* p=new int;\n const char* s="mysql_query(db,argv[1]); new int"; auto raw=R"TAG(new int; if(x){ mysql_query(db,argv[1]); })TAG"; /* new int */ }';
  assert.equal(analyze(s).findings.length, 0);
});
test('SQL tracks cin through assignment and multiline sink', () => {
  const f = flaws('void f(){ std::string user; std::cin >> user; std::string q="SELECT " + user; mysql_query(\n db,\n q.c_str()); }', 'sql-injection');
  assert.equal(f.length, 1); assert.equal(f[0].evidence, 'standard input');
});
test('SQL tracks getline, getenv and sprintf', () => {
  assert.equal(flaws('void f(){ std::string u; std::getline(std::cin,u); mysql_query(db,u.c_str()); }', 'sql-injection').length, 1);
  assert.equal(flaws('void f(){ auto u=getenv("USER"); char q[100]; sprintf(q,"SELECT %s",u); PQexec(db,q); }', 'sql-injection').length, 1);
});
test('constant queries, bound parameter values and overwritten input are safe in supported model', () => {
  assert.equal(flaws('void f(char* user){ mysql_query(db,"SELECT 1"); PQexecParams(db,"SELECT $1",1,0,user,0,0,0); }', 'sql-injection').length, 0);
  assert.equal(flaws('void f(std::string user){ user="constant"; mysql_query(db,user.c_str()); }', 'sql-injection').length, 0);
});
test('SQL prepare API is still flagged if query text itself is input-derived', () => {
  assert.equal(flaws('void f(char* user){ sqlite3_prepare_v2(db,user,-1,stmt,0); }', 'sql-injection').length, 1);
});
test('parameter taint assumption is configurable', () => {
  assert.equal(analyze('void f(char* user){ mysql_query(db,user); }', { treatParametersAsInput: false }).findings.length, 0);
});
test('nested locations use one primary context while retaining all contexts', () => {
  const r = report('void f(bool b){ for(;;){ if(b){ int* p=new int; } } }');
  assert.equal(r.totalFindings, 1); assert.equal(r.findings[0].primaryContext, 'if');
  assert.deepEqual(r.findings[0].contexts, ['function', 'for', 'if']);
  assert.equal(r.rows.reduce((n, row) => n + row.count, 0), 1);
});
test('unbraced branches, else, do-while, while and switch default classification', () => {
  for (const [body, expected] of [
    ['if(b) int* p=new int;', 'if'],
    ['if(b){} else { int* p=new int; }', 'else'],
    ['do { int* p=new int; } while(b);', 'do-while'],
    ['while(b){ int* p=new int; }', 'while'],
    ['switch(x){ default: { int* p=new int; break; } }', 'default']
  ]) { const r = report(`void f(bool b,int x){ ${body} }`); assert.equal(r.findings[0]?.primaryContext, expected); }
});
test('allocation attribution and related exit attribution are separate', () => {
  const r = report('void f(bool b){ int* p=new int; if(b) return; delete p; }');
  assert.equal(r.findings[0].primaryContext, 'function');
  assert.deepEqual(r.findings[0].relatedLocation.contexts, ['function', 'if']);
});
test('UTF-8 byte locations convert to VS Code UTF-16 offsets', () => {
  const source = 'void f(){ auto s="é😀"; int* p=new int; }';
  const f = flaws(source)[0];
  assert.equal(byteOffsetToUtf16(source, f.startByte), source.indexOf('new'));
});
test('malformed protocol fails clearly', () => {
  const r = spawnSync(executable('security_analyzer'), [], { input: '{invalid', encoding: 'utf8' });
  assert.notEqual(r.status, 0); assert.match(r.stderr, /Security analyzer/);
});
test('incomplete editor code returns notes instead of crashing', () => {
  const result = analyze('void f(){ if(');
  assert(result.notes.length > 0);
});
test('pipeline copies exact unsaved source twice and returns native pattern JSON', async () => {
  const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'cpp-security-test-'));
  try {
    const pipeline = new AnalysisPipeline(root, storage);
    const source = 'void f(){ int* p=new int(7); }\n// unsaved é😀';
    const job = await pipeline.analyze({ uri: 'untitled:test.cpp', filePath: 'test.cpp', version: 7, source }, 10000);
    assert.equal(fs.readFileSync(path.join(job.folder, 'security/snapshot.cpp'), 'utf8'), source);
    assert.equal(fs.readFileSync(path.join(job.folder, 'patterns/snapshot.cpp'), 'utf8'), source);
    assert.equal(job.report.documentVersion, 7); assert.equal(job.report.memoryLeakCount, 1);
    await pipeline.publish(job);
    assert(fs.existsSync(path.join(storage, 'snapshots', job.key, 'patterns/report.json')));
    await pipeline.remove('untitled:test.cpp'); assert(!fs.existsSync(path.join(storage, 'snapshots', job.key)));
  } finally { fs.rmSync(storage, { recursive: true, force: true }); }
});
test('aggregation sums native categories and escapes displayed filenames', () => {
  const a = report('void f(){ int* p=new int; }'); a.filePath = '<script>alert(1)</script>.cpp'; a.documentUri = 'file:test';
  const b = report('void f(char* user){ mysql_query(db,user); }'); b.filePath = 'b.cpp'; b.documentUri = 'file:b';
  const all = aggregate([a, b]); assert.equal(all.totals.findings, 2);
  assert.equal(all.rows.reduce((n, row) => n + row.count, 0), 2);
  const html = renderPatterns(all); assert(!html.includes('<script>')); assert(html.includes('&lt;script&gt;'));
});
