import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeProject, inspectFile, validateFiles, LIMITS } from '../src/engine.js';
import { exportReport, signalText } from '../src/reports.js';
import { sample } from '../src/sample.js';
import { catalog } from '../src/i18n.js';
const inspect = (content, path='test.js') => inspectFile({path,content});
const flows = code => inspect(code).findings.filter(f => f.mode === 'ast');

test('query parameters propagate into HTML, URLs and React output', async () => {
  const result = await analyzeProject(sample);
  assert.equal(result.incomplete, false);
  const ast = result.findings.filter(f => f.mode === 'ast' && f.path === 'browser.tsx');
  assert.equal(ast.filter(f => f.category === 'html').length, 2);
  assert.equal(ast.filter(f => f.category === 'url').length, 1);
  assert.equal(ast[0].source.line, 3);
  assert.ok(ast[0].steps.some(s => s.text === 'html'));
  assert.equal(new Set(result.findings.map(f => f.id)).size, result.findings.length);
});
test('textContent and constant reassignment do not create AST HTML flows', () => {
  assert.equal(flows('const q=location.hash; out.textContent=q;').length,0);
  assert.equal(flows('let q=location.hash; q="constant"; out.innerHTML=q;').length,0);
});
test('function parameters and lexical block declarations shadow taint', () => {
  assert.equal(flows('const q=location.hash; function render(q){out.innerHTML=q;}').length,0);
  assert.equal(flows('const q=location.hash; { const q="constant"; out.innerHTML=q; }').length,0);
  assert.equal(flows('let q=location.hash; { q="constant"; } out.innerHTML=q;').length,0);
});
test('branches merge conservatively and HTML sanitizer does not sanitize URLs', () => {
  assert.equal(flows('let q="fixed"; if(flag){q=location.hash;} out.innerHTML=q;').length,1);
  const html = flows('out.innerHTML=DOMPurify.sanitize(location.hash);')[0];
  assert.equal(html.priority,'medium'); assert.equal(html.sanitized,true);
  const url = flows('location.href=DOMPurify.sanitize(location.hash);')[0];
  assert.equal(url.category,'url'); assert.equal(url.priority,'high');
});
test('JS/TS/JSX/TSX parse modes and multiline coordinates are real', () => {
  for (const path of ['test.js','test.jsx','test.ts','test.tsx','test.mjs','test.cjs']) assert.equal(inspect('const q=location.hash;\nout.innerHTML=q;',path).findings.find(f=>f.mode==='ast').line,2);
  assert.equal(inspect('const q: string=location.hash;\nconst v=<b dangerouslySetInnerHTML={{__html:q}}/>;','test.tsx').notes.length,0);
});
test('syntax errors, unsupported files and bounded traversal report gaps', () => {
  assert.ok(inspect('const = ; out.innerHTML=x;').notes.some(n=>n.code==='parse'));
  assert.equal(inspect('anything','test.py').analyzed,false);
  const deep='let q=location.hash; out.innerHTML='+ '!'.repeat(100)+'q;';
  assert.ok(inspect(deep).notes.some(n=>n.code==='analysisBudget' || n.code==='parse'));
});
test('source is never executed, and comments only produce pattern signals', async () => {
  globalThis.__xss_test_executed=false;
  const result=await analyzeProject([{path:'inert.js',content:'globalThis.__xss_test_executed=true;\n// eval(location.hash)\n// out.innerHTML=location.hash;'}]);
  assert.equal(globalThis.__xss_test_executed,false);
  assert.equal(result.findings.filter(f=>f.mode==='ast').length,0);
  assert.ok(result.findings.some(f=>f.mode==='pattern'));
});
test('size, count, binary and duplicate limits reject invalid input', () => {
  assert.throws(()=>validateFiles(Array.from({length:101},(_,i)=>({path:i+'.js',content:''}))),/fileCount/);
  assert.throws(()=>validateFiles([{path:'a.js',content:'a'.repeat(LIMITS.fileBytes+1)}]),/fileSize/);
  assert.throws(()=>validateFiles([{path:'a.js',content:'\0'}]),/binary/);
  assert.throws(()=>validateFiles([{path:'a.js',content:''},{path:'a.js',content:''}]),/invalidFile/);
  assert.throws(()=>validateFiles(Array.from({length:21},(_,i)=>({path:i+'.js',content:'x'.repeat(LIMITS.fileBytes)}))),/totalSize/);
});
test('review identities are stable until any source changes', async () => {
  const input=[{path:'a.js',content:'out.innerHTML=location.hash;'}];
  const first=await analyzeProject(input), second=await analyzeProject(input);
  assert.equal(first.findings[0].id,second.findings[0].id);
  input[0].content+='\n// changed';
  assert.notEqual(first.findings[0].id,(await analyzeProject(input)).findings[0].id);
});
test('all report formats preserve reviews and escape hostile content', async () => {
  const result=await analyzeProject(sample);
  result.findings[0].note='</pre><script>reportAttack()</script>';
  result.findings[0].status='false_positive';
  for (const lang of ['zh','en']) {
    assert.equal(JSON.parse(exportReport(result,lang,'json').text).findings[0].status,'false_positive');
    const html=exportReport(result,lang,'html').text;
    assert.ok(!html.includes('<script>')); assert.ok(!html.includes('src="https:'));
    assert.ok(html.includes('&lt;script&gt;reportAttack()'));
    assert.ok(exportReport(result,lang,'markdown').text.includes('reportAttack()'));
    assert.ok(signalText(result.findings[0],lang).includes(result.findings[0].path));
  }
});
test('translation catalogs have identical keys',()=>assert.deepEqual(Object.keys(catalog.zh).sort(),Object.keys(catalog.en).sort()));
