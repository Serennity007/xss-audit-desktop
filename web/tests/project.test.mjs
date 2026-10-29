import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeProject, inspectFile, validateFiles } from '../src/engine.js';
import { DEFAULT_SCOPE, globMatches, normalizePath, validateScope } from '../src/scope.js';
import { importSources } from '../src/imports.js';
import { compareBaseline, clearComparison, parseBaseline, validateBaseline } from '../src/baseline.js';
import { exportReport, csvCell } from '../src/reports.js';
import { filterFindings } from '../src/filters.js';
import { componentSample } from '../src/sample.js';
import { translate } from '../src/i18n.js';

const risky = {path:'src/main.ts',content:'const q=location.hash;\noutput.innerHTML=q;'};
const clean = {path:'src/safe.ts',content:'const q=location.hash;\noutput.textContent=q;'};
const blob = (name, content, extra={}) => ({name, size:new TextEncoder().encode(content).length, async arrayBuffer(){return new TextEncoder().encode(content).buffer;},...extra});

test('glob semantics are segment based, root aware, case sensitive and exclusion wins', async()=>{
  assert.equal(globMatches('**/*.ts','main.ts'),true);
  assert.equal(globMatches('src/*','src/nested/main.ts'),false);
  assert.equal(globMatches('src/**/m?in.ts','src/nested/main.ts'),true);
  assert.equal(globMatches('src/**','Src/main.ts'),false);
  assert.throws(()=>validateScope({include:['**/a**'],exclude:[]}),/invalidScope/);
  assert.throws(()=>validateScope({include:['!src/*'],exclude:[]}),/invalidScope/);
  const report=await analyzeProject([risky,{...risky,path:'node_modules/pkg/main.ts'},clean],{scope:{include:['**/*.ts'],exclude:['**/node_modules/**','src/safe.ts']}});
  assert.equal(report.incomplete,false);
  assert.deepEqual(report.files.filter(f=>!f.analyzed).map(f=>f.reason),['excluded','excluded']);
  assert.equal(report.findings.length,1);
});

test('paths reject traversal, drives, absolute names, controls and normalized collisions',()=>{
  for (const path of ['../q.js','/q.js','a/./q.js','C:/q.js','a//b.js','a\n.js','a/../b.js']) assert.throws(()=>normalizePath(path),/invalidFile/);
  assert.equal(normalizePath('src\\main.ts'),'src/main.ts');
  assert.throws(()=>validateFiles([{path:'src\\main.ts',content:''}]),/invalidFile/);
});

test('folder import strips only the selected root and never reads excluded or unsupported contents',async()=>{
  const failRead=()=>{throw Error('must not be read');};
  const imported=await importSources([
    blob('main.ts',risky.content,{webkitRelativePath:'project/src/main.ts'}),
    blob('huge.js','',{size:1000000000,webkitRelativePath:'project/node_modules/lib/huge.js',arrayBuffer:failRead}),
    blob('private.bin','',{webkitRelativePath:'project/private.bin',arrayBuffer:failRead})
  ],[],{directory:true});
  assert.deepEqual(imported.files,[risky]);
  assert.deepEqual(imported.skipped.map(f=>f.reason),['excluded','unsupported']);
});

test('imports are atomic on invalid encoding, binary content, collision and metadata overflow',async()=>{
  const existing=[{...clean}];
  await assert.rejects(importSources([blob('bad.js','',{arrayBuffer:async()=>new Uint8Array([255]).buffer})],existing),/decode/);
  await assert.rejects(importSources([blob('bad.js','\0')],existing),/binary/);
  await assert.rejects(importSources([blob('safe.ts',''),blob('safe.ts','')],existing),/invalidFile/);
  await assert.rejects(importSources(new Array(5001).fill(blob('x.js','')),existing),/inventoryLimit/);
  assert.deepEqual(existing,[clean]);
});

test('imports apply budgets before reading and allow a BOM without executing source',async()=>{
  let read=false;
  await assert.rejects(importSources([blob('x.js','',{size:262145,arrayBuffer:async()=>{read=true;return new ArrayBuffer(0);}})]),/fileSize/);
  assert.equal(read,false);
  const imported=await importSources([blob('main.ts','\uFEFFglobalThis.shouldNotRun=true;')]);
  assert.equal(imported.files[0].content,'globalThis.shouldNotRun=true;');
  assert.equal(globalThis.shouldNotRun,undefined);
  await assert.rejects(importSources([blob('readme.md','text')]),/noImportable/);
});

test('Vue and Svelte inline scripts retain original source, sink and column coordinates',()=>{
  for (const file of componentSample.slice(0,2)) {
    const scan=inspectFile(file), f=scan.findings.find(f=>f.mode==='ast');
    assert.ok(f); assert.equal(scan.blocks,1);
    assert.match(f.context,/innerHTML/);
    assert.equal(file.content.split('\n')[f.line-1].indexOf('innerHTML')>=0,true);
    assert.equal(file.content.split('\n')[f.source.line-1].includes('location.'),true);
    assert.ok(scan.notes.some(n=>n.code==='templateUncovered'));
  }
  const inline=inspectFile({path:'a.html',content:'<p>text</p><script>out.innerHTML=location.hash;</script>'});
  assert.equal(inline.findings.find(f=>f.mode==='ast').column,20);
});

test('HTML scripts parse independently, JSON/external scripts and inert templates never become AST evidence',()=>{
  const content='<template><script>out.innerHTML=location.hash;</script></template>\n<script type="application/json">{"x":"innerHTML"}</script>\n<script src="https://invalid.example/x.js"></script>\n<script>const q=location.hash;</script>\n<script>out.innerHTML=q;</script>';
  const scan=inspectFile({path:'page.html',content});
  assert.equal(scan.findings.filter(f=>f.mode==='ast').length,0);
  assert.ok(scan.notes.some(n=>n.code==='nonScript'));
  assert.ok(scan.notes.some(n=>n.code==='externalScript'));
  assert.equal(scan.blocks,2);
});

test('component parse failures are isolated and unsupported blocks remain explicit',()=>{
  const scan=inspectFile({path:'a.vue',content:'<script lang="coffee">x</script>\n<script>const = ;</script>\n<script>out.innerHTML=location.hash;</script>'});
  assert.ok(scan.notes.some(n=>n.code==='nonScript'));
  assert.ok(scan.notes.some(n=>n.code==='parse' && n.line===2));
  assert.equal(scan.findings.filter(f=>f.mode==='ast').length,1);
  const bad=inspectFile({path:'a.html',content:'<script>out.innerHTML=location.hash;'});
  assert.ok(bad.notes.some(n=>n.code==='unclosedScript'));
  assert.equal(bad.findings.length,0);
});

test('script extraction stops at sixteen blocks and exposes the unprocessed scope',()=>{
  const scan=inspectFile({path:'many.html',content:'<script>out.innerHTML=location.hash;</script>\n'.repeat(17)});
  assert.equal(scan.blocks,16);assert.ok(scan.notes.some(n=>n.code==='scriptBudget'));
  assert.equal(scan.findings.filter(f=>f.mode==='ast').length,16);
});

test('finding budgets retain every file in coverage and label the remaining files unprocessed',async()=>{
  const content='out.innerHTML=location.hash;\n'.repeat(1001);
  const report=await analyzeProject(['a.js','b.js','c.js'].map(path=>({path,content})));
  assert.equal(report.findings.length,2000);assert.equal(report.files.length,3);
  assert.equal(report.files[2].reason,'projectBudget');assert.equal(report.files[2].analyzed,false);
  assert.equal(report.incomplete,true);assert.ok(report.notes.some(n=>n.code==='findingBudget'));
  assert.ok(report.notes.some(n=>n.code==='projectBudget'));
});

test('very long lines and identifiers cannot inflate every finding into a whole-file report',async()=>{
  const longName='input' + 'x'.repeat(500);
  const content='/*' + 'x'.repeat(20000) + '*/ const ' + longName + '=location.hash; out.innerHTML=' + longName + ';';
  const report=await analyzeProject([{path:'long.ts',content}]);
  const f=report.findings.find(f=>f.mode==='ast');
  assert.ok(f);assert.ok(f.context.length <= 4096);assert.equal(f.context_truncated,true);assert.equal(f.evidence_truncated,true);
  assert.ok(f.context.includes('out.innerHTML'));assert.ok(f.steps.every(s=>s.text.length <= 120));
  assert.ok(exportReport(report,'en','html').text.includes('text was shortened'));
  assert.equal(f.line,1);assert.equal(content.slice(f.column-1).startsWith('out.innerHTML'),true);
});

test('static computed source and sink names produce local evidence, dynamic properties do not pretend to resolve',()=>{
  const scan=inspectFile({path:'a.js',content:"out['innerHTML']=location['hash'];"});
  assert.equal(scan.findings.find(f=>f.mode==='ast').source.text,"location['hash']");
  assert.equal(inspectFile({path:'a.js',content:'out[unknown]=location.hash;'}).findings.filter(f=>f.mode==='ast').length,0);
});

test('local or overwritten sanitizer names cannot lower HTML flow priority',()=>{
  for (const code of [
    'function sanitizeHtml(x){return x;} out.innerHTML=sanitizeHtml(location.hash);',
    'out.innerHTML=sanitizeHtml(location.hash); function sanitizeHtml(x){return x;}',
    'const DOMPurify={sanitize:x=>x}; out.innerHTML=DOMPurify.sanitize(location.hash);',
    'function render(DOMPurify){out.innerHTML=DOMPurify.sanitize(location.hash);}',
    'try {} catch (DOMPurify) {out.innerHTML=DOMPurify.sanitize(location.hash);}',
    'DOMPurify["sanitize"]=x=>x; out.innerHTML=DOMPurify.sanitize(location.hash);',
    'import DOMPurify from "./custom"; out.innerHTML=DOMPurify.sanitize(location.hash);'
  ]) {
    const f=inspectFile({path:'a.js',content:code}).findings.find(f=>f.mode==='ast');
    assert.ok(f,code); assert.equal(f.priority,'high',code); assert.equal(f.sanitized,false,code);
  }
  const imported=inspectFile({path:'a.js',content:'import DOMPurify from "dompurify"; out.innerHTML=DOMPurify.sanitize(location.hash);'});
  assert.equal(imported.findings.find(f=>f.mode==='ast').priority,'medium');
  const block=inspectFile({path:'a.js',content:'{ const DOMPurify={}; } out.innerHTML=DOMPurify.sanitize(location.hash);'});
  assert.equal(block.findings.find(f=>f.mode==='ast').priority,'medium');
});

test('baseline round trip is unchanged until source changes; absence never sets a review decision',async()=>{
  const first=await analyzeProject([risky]), baseline=parseBaseline(exportReport(first,'en','json').text);
  const same=await analyzeProject([risky]);
  assert.equal(compareBaseline(same,baseline).unchanged,1);
  const changed=await analyzeProject([{...risky,content:risky.content+'\n// comment'}]);
  assert.equal(compareBaseline(changed,baseline).new,1);
  assert.equal(changed.comparison.not_observed.length,1);
  assert.equal(changed.findings[0].status,'pending');
  const fixed=await analyzeProject([{...risky,content:'out.textContent=location.hash;'}]);
  assert.equal(compareBaseline(fixed,baseline).not_observed.length,1);
  assert.equal(fixed.comparison.notice,'absence-is-not-a-fix');
  clearComparison(changed); assert.equal(changed.comparison,undefined); assert.equal(changed.findings[0].baseline_state,undefined);
});

test('baseline rejects incomplete, foreign, filtered, malformed and duplicate identities',async()=>{
  const report=await analyzeProject([risky]);
  for (const patch of [{incomplete:true},{engine:'web-ast/0.1.0'},{export_scope:'filtered'},{notes:[{code:'parse'}]},{files:[{path:'../x',analyzed:true}]},{findings:[report.findings[0],report.findings[0]]}]) assert.throws(()=>validateBaseline({...report,...patch}),/invalidBaseline/);
  assert.throws(()=>parseBaseline('{bad'),/invalidBaseline/);
  assert.throws(()=>validateBaseline({schema_version:2}),/invalidBaseline/);
});

test('baseline comparison exposes scope changes, missing files and current coverage failures',async()=>{
  const baseline=validateBaseline(await analyzeProject([risky,clean]));
  const narrowed=await analyzeProject([risky],{scope:{include:['**/*'],exclude:['src/**']}});
  compareBaseline(narrowed,baseline);
  assert.equal(narrowed.comparison.scope_changed,true);
  assert.equal(narrowed.comparison.not_observed[0].reason,'outsideScope');
  const missing=await analyzeProject([clean]); compareBaseline(missing,baseline);
  assert.equal(missing.comparison.not_observed[0].reason,'fileMissing');
  const broken=await analyzeProject([{...risky,content:'const = ;'}]); compareBaseline(broken,baseline);
  assert.equal(broken.comparison.current_incomplete,true);
});

test('combined filters use saved statuses, evidence, scope, keywords and comparison without mutating full results',async()=>{
  const report=await analyzeProject([risky,{path:'other.js',content:'// out.innerHTML = x;'}]);
  report.findings[0].status='false_positive';report.findings[0].note='reviewed sanitizer';report.findings[0].baseline_state='unchanged';
  const filtered=filterFindings(report,{status:'false_positive',mode:'ast',category:'html',priority:'high',query:'sanitizer',baseline:'unchanged',path:'src/main.ts'},key=>translate('en',key));
  assert.equal(filtered.length,1);
  assert.equal(filterFindings(report,{status:'pending',mode:'ast'},key=>key).length,0);
  assert.equal(JSON.parse(exportReport(report,'en','json').text).findings.length,2);
});

test('CSV protects formulas even after whitespace and preserves quote/newline structure',async()=>{
  for (const value of ['=2+2',' +SUM(1)','@SUM(1)','-1','\ttext','\rformula',' \t=1']) assert.ok(csvCell(value).startsWith('"\''));
  assert.equal(csvCell('plain "quoted"\ntext'),'"plain ""quoted""\ntext"');
  const report=await analyzeProject([risky]); report.findings[0].note='=DANGEROUS()';
  const csv=exportReport(report,'zh','csv').text;
  assert.ok(csv.startsWith('\uFEFF')); assert.ok(csv.includes("\"'=DANGEROUS()\"")); assert.ok(csv.includes('coverage'));
});

test('SARIF preserves code flows, manual decisions, fingerprint, scope and coverage as unverified review signals',async()=>{
  const report=await analyzeProject([risky]); report.findings[0].status='false_positive';
  compareBaseline(report,validateBaseline(report));
  const sarif=JSON.parse(exportReport(report,'en','sarif').text), run=sarif.runs[0], f=run.results[0];
  assert.equal(sarif.version,'2.1.0');assert.equal(f.baselineState,'unchanged');
  assert.equal(f.properties.reviewStatus,'false_positive');assert.equal(f.properties.exploitability,'unverified');
  assert.equal(f.locations[0].physicalLocation.artifactLocation.uri,'src/main.ts');
  assert.equal(f.codeFlows[0].threadFlows[0].locations.at(-1).location.physicalLocation.region.startLine,2);
  assert.equal(run.invocations[0].executionSuccessful,true);
  const partial=await analyzeProject(componentSample);
  assert.equal(JSON.parse(exportReport(partial,'en','sarif').text).runs[0].invocations[0].executionSuccessful,false);
});

test('all exports include coverage and comparison and HTML remains inert for adversarial filenames and notes',async()=>{
  const report=await analyzeProject([{path:'<img onerror=alert(1)>.js',content:risky.content}]);
  report.import_inventory=[{path:'<script>alert(1)</script>.png',reason:'unsupported'}];
  report.findings[0].note='</pre><svg onload="alert(1)">';
  compareBaseline(report,validateBaseline(report));
  const html=exportReport(report,'en','html').text;
  assert.ok(!html.includes('<svg')); assert.ok(!html.includes('<img'));assert.ok(!html.includes('<script>'));
  assert.ok(html.includes('import_inventory'));assert.ok(html.includes('absence-is-not-a-fix'));
  for (const format of ['json','markdown','html','csv','sarif']) assert.ok(exportReport(report,'en',format).text.includes('scope'));
});
