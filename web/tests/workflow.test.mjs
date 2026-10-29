import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { zipSync, strToU8, Zip, ZipDeflate } from 'fflate';
import { importArchive, ZIP_BYTES } from '../src/archive.js';
import { exportSnapshot, parseSnapshot, searchSources, applyReviewBatch } from '../src/project.js';
import { analyzeProject } from '../src/engine.js';
import { validateBaseline, compareBaseline } from '../src/baseline.js';
import { exportReport } from '../src/reports.js';
import { translate } from '../src/i18n.js';
import { VERSION, ENGINE } from '../src/version.js';
import { startArchiveImport } from '../src/runner.js';
import { DEFAULT_SCOPE } from '../src/scope.js';

const source='const q=location.hash;\noutput.innerHTML=q;';
const file={path:'src/main.ts',content:source};
const pack=(files,options={})=>zipSync(Object.fromEntries(Object.entries(files).map(([name,value])=>[name,strToU8(value)])),options);
function central(bytes) { const v=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength); return {v,p:v.getUint32(bytes.length-6,true)}; }

test('ZIP imports stored and deflated UTF-8 sources, optionally removing a common root',()=>{
  for (const level of [0,6]) {
    const bytes=pack({'repo/':'','repo/src/main.ts':source,'repo/中文.js':'out.textContent="示例";','repo/node_modules/lib.js':source,'repo/README.md':'notes'},{level});
    const imported=importArchive(bytes,{stripRoot:true});
    assert.equal(imported.removed_root,'repo/');
    assert.deepEqual(imported.files,[file,{path:'中文.js',content:'out.textContent="示例";'}]);
    assert.deepEqual(imported.skipped.map(x=>x.reason),['excluded','unsupported']);
    assert.equal(importArchive(bytes).files[0].path,'repo/src/main.ts');
  }
});
test('ZIP supports streaming data descriptors and never executes accepted source',()=>{
  const chunks=[]; const zip=new Zip((error,data)=>{if(error) throw error;chunks.push(data);});
  const entry=new ZipDeflate('main.js');zip.add(entry);entry.push(strToU8('globalThis.zipMustNotExecute=true;'),true);zip.end();
  const bytes=new Uint8Array(chunks.reduce((n,x)=>n+x.length,0));let pos=0;
  for(const chunk of chunks){bytes.set(chunk,pos);pos+=chunk.length;}
  assert.equal(importArchive(bytes).files.length,1);assert.equal(globalThis.zipMustNotExecute,undefined);
});
test('ZIP rejects unsafe paths, Windows aliases, collisions and file/directory conflicts',()=>{
  for(const path of ['../bad.js','/bad.js','C:/bad.js','a\\bad.js','CON.js','x:a.js','folder./a.js'])
    assert.throws(()=>importArchive(pack({[path]:source})),/zipInvalid/);
  for(const files of [{'a.js':source,'A.js':source},{'src':source,'src/a.js':source}])
    assert.throws(()=>importArchive(pack(files)),/zipInvalid/);
});
test('ZIP rejects corrupt payloads, truncated archives, encrypted entries and links',()=>{
  const stored=pack({'main.js':source},{level:0});stored[37]^=1;
  assert.throws(()=>importArchive(stored),/zipInvalid/);
  const clean=pack({'main.js':source});assert.throws(()=>importArchive(clean.subarray(0,clean.length-1)),/zipInvalid/);
  const encrypted=pack({'main.js':source});let c=central(encrypted);c.v.setUint16(c.p+8,1,true);
  assert.throws(()=>importArchive(encrypted),/zipUnsupported/);
  const link=pack({'main.js':source});c=central(link);c.v.setUint32(c.p+38,0xa1ff0000,true);
  assert.throws(()=>importArchive(link),/zipUnsupported/);
});
test('ZIP checks advertised budgets and actual inflation rather than trusting metadata',()=>{
  assert.throws(()=>importArchive(new Uint8Array(ZIP_BYTES+1)),/zipSize/);
  assert.throws(()=>importArchive(pack({'main.js':'x'.repeat(262145)})),/fileSize/);
  const lying=pack({'main.js':'x'.repeat(200000)});const {v,p}=central(lying);
  v.setUint32(p+24,1,true);v.setUint32(22,1,true);
  assert.throws(()=>importArchive(lying),/zipInvalid/);
  const count=pack({'main.js':source});const view=new DataView(count.buffer);
  view.setUint16(count.length-14,5001,true);view.setUint16(count.length-12,5001,true);
  assert.throws(()=>importArchive(count),/inventoryLimit/);
});
test('ZIP validates skipped metadata but never inflates excluded payloads',()=>{
  const bytes=pack({'src/main.ts':source,'node_modules/huge.js':'x'.repeat(500000),'README.md':'x'});
  assert.deepEqual(importArchive(bytes).files,[file]);
  const custom=importArchive(bytes,{scope:{include:['**/*.ts'],exclude:[]}});
  assert.deepEqual(custom.skipped.map(f=>f.reason),['notIncluded','unsupported']);
  assert.throws(()=>importArchive(pack({'README.md':'only docs'})),/noImportable/);
  assert.throws(()=>importArchive(pack({'node_modules/../bad.js':source,'main.js':source})),/zipInvalid/);
});
test('ZIP import errors, timeout and cancellation terminate disposable Workers',()=>{
  for(const action of ['cancel','timeout','error','result']){
    const calls=[];let timer;
    const worker={terminate(){this.stopped=true;},postMessage(input){this.input=input;}};
    const stop=startArchiveImport(new Uint8Array([1]),{result:r=>calls.push(r),error:e=>calls.push(e)},{scope:DEFAULT_SCOPE,stripRoot:true,createWorker:()=>worker,schedule:fn=>{timer=fn;return 1;},unschedule:()=>{}});
    assert.equal(worker.input.task,'archive');assert.equal(worker.input.stripRoot,true);
    if(action==='cancel')stop();
    if(action==='timeout')timer();
    if(action==='error')worker.onmessage({data:{error:'zipInvalid'}});
    if(action==='result')worker.onmessage({data:{result:{files:[file]}}});
    worker.onmessage({data:{result:'late'}});
    assert.ok(worker.stopped);assert.equal(calls.length,action==='cancel'?0:1);
  }
});
test('project snapshots round-trip source, scope, complete baseline and manual notes',async()=>{
  const report=await analyzeProject([file]);const baseline=validateBaseline(report), id=report.findings[0].id;
  const text=exportSnapshot([file],DEFAULT_SCOPE,{baseline,reviews:{[id]:{status:'false_positive',note:'<script>inert note</script>'}},inventory:[{path:'README.md',reason:'unsupported'}]});
  const loaded=parseSnapshot(text);assert.deepEqual(loaded.files,[file]);assert.equal(loaded.reviews[id].note,'<script>inert note</script>');
  const current=await analyzeProject(loaded.files);compareBaseline(current,loaded.baseline);
  assert.equal(current.comparison.new,0);assert.equal(current.comparison.unchanged,report.findings.length);
  assert.equal(VERSION,'0.3.0');assert.equal(ENGINE,'web-ast/0.2.0');
});
test('snapshots reject foreign formats, unsafe paths, invalid reviews and partial baselines atomically',async()=>{
  const text=exportSnapshot([file],DEFAULT_SCOPE), original=[structuredClone(file)];
  const badValues=[{engine:'desktop'},{format:'report'},{files:[{path:'../a.js',content:source}]},{reviews:{'__proto__':{status:'fixed',note:'bad'},x:{status:'fixed',note:'bad'}}},{reviews:{['a'.repeat(64)]:{status:'safe',note:''}}},{scope:{include:['!bad'],exclude:[]}},{baseline:{incomplete:true}},{inventory:[{path:'../outside',reason:'excluded'}]}];
  for(const changes of badValues) assert.throws(()=>parseSnapshot(JSON.stringify({...JSON.parse(text),...changes})),/snapshotInvalid/);
  assert.throws(()=>parseSnapshot('{'),/snapshotInvalid/);assert.deepEqual(original,[file]);
});
test('restored decisions attach only to recomputed identities, not edited-source findings',async()=>{
  const before=await analyzeProject([file]), id=before.findings[0].id;
  const saved=parseSnapshot(exportSnapshot([file],DEFAULT_SCOPE,{reviews:{[id]:{status:'confirmed',note:'manual'}}}));
  const after=await analyzeProject([{...file,content:file.content+'\n// change'}]);
  assert.ok(after.findings.every(f=>!saved.reviews[f.id]));
});
test('source search returns literal per-line locations and bounds output, including Unicode prefixes',()=>{
  const files=[{path:'a.js',content:'İ😀 InnerHTML\ninnerHTML + innerHTML'},{path:'b.ts',content:'<script> innerHTML'}];
  let found=searchSources(files,'innerhtml');assert.equal(found.matches.length,3);assert.equal(found.matches[0].column,5);
  assert.equal(searchSources(files,'innerHTML',{caseSensitive:true}).matches.length,2);
  assert.equal(searchSources(files,'.*').matches.length,0);
  assert.equal(searchSources(files,'').matches.length,0);
  found=searchSources([{path:'a.js',content:'needle\n'.repeat(201)}],'needle');assert.equal(found.matches.length,200);assert.ok(found.truncated);
  assert.ok(searchSources([{path:'long.js',content:'x'.repeat(10000)+'needle'}],'needle').matches[0].excerpt.length<=240);
});
test('batch review affects only explicitly filtered IDs, preserves notes and rejects stale IDs atomically',async()=>{
  const report=await analyzeProject([file,{...file,path:'b.ts'}]);const chosen=report.findings[0];chosen.note='keep this note';
  applyReviewBatch(report,[chosen.id],'false_positive');assert.equal(chosen.note,'keep this note');assert.equal(chosen.review_origin,'manual');
  assert.ok(report.findings.slice(1).every(f=>f.status==='pending'));
  assert.throws(()=>applyReviewBatch(report,[chosen.id,'stale'],'fixed'),/reviewInvalid/);assert.equal(chosen.status,'false_positive');
});
test('imported-decision provenance and inert notes survive all report formats',async()=>{
  const report=await analyzeProject([file]);report.findings[0].review_origin='snapshot';report.findings[0].note='<script>alert(1)</script>';
  for(const format of ['json','markdown','html','csv','sarif']){
    const output=exportReport(report,'en',format).text;
    assert.match(output,/snapshot|imported snapshot/);
    if(format==='html')assert.ok(!output.includes('<script>'));
  }
});
test('new UI selectors exist and visible controls/error messages have bilingual translations',async()=>{
  const app=await readFile(new URL('../src/app.js',import.meta.url),'utf8'), html=await readFile(new URL('../index.html',import.meta.url),'utf8');
  const ids=new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]));
  for(const match of app.matchAll(/\$\('([^']+)'\)/g))assert.ok(ids.has(match[1]),match[1]);
  const keys=[...html.matchAll(/data-(?:i18n|placeholder)="([^"]+)"/g)].map(m=>m[1]);
  keys.push('zipInvalid','zipUnsupported','zipEncoding','zipSize','snapshotInvalid','snapshotSize','batchConfirm','importedReview');
  for(const language of ['zh','en']) for(const key of keys)assert.notEqual(translate(language,key),key,language+':'+key);
});
