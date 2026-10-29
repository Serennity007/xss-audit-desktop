// DOM integration with explicit platform shims and real Node-backed Workers.
// This exercises application wiring; it is not a browser/layout/clipboard-permission test.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Worker as NodeWorker } from 'node:worker_threads';
import { parseHTML } from 'linkedom';
import { zipSync, strToU8 } from 'fflate';
import { translate } from '../src/i18n.js';

const built=process.env.XSS_WEB_TEST_BUILT==='1';
test((built ? 'built' : 'source')+' workbench DOM integration with actual analysis/import Workers',async t=>{
  const {document}=parseHTML(await readFile(new URL(built ? '../dist/index.html' : '../index.html',import.meta.url),'utf8'));
  const $=id=>document.getElementById(id), storage=new Map(), downloads=[], confirmations=[];
  let writes=0;
  Object.assign(globalThis,{document,confirm:message=>{confirmations.push(message);return true;},localStorage:{
    getItem:key=>storage.get(key)||null,setItem:(key,value)=>{writes++;storage.set(key,value);},removeItem:key=>storage.delete(key)
  }});
  for(const node of document.querySelectorAll('select')) Object.defineProperty(node,'value',{writable:true,value:node.querySelector('option')?.getAttribute('value')||''});
  for(const node of document.querySelectorAll('input[type=checkbox]')) node.checked=node.hasAttribute('checked');
  for(const node of document.querySelectorAll('textarea')) {
    node.selectionStart=0;node.selectionEnd=0;
    node.setSelectionRange=(start,end)=>{node.selectionStart=start;node.selectionEnd=end;};node.select=()=>{};
  }
  $('copy-dialog').showModal=()=>{$('copy-dialog').open=true;};$('copy-dialog').close=()=>{$('copy-dialog').open=false;};
  URL.createObjectURL=blob=>{downloads.push(blob);return 'blob:test-'+downloads.length;};URL.revokeObjectURL=()=>{};
  const workerBootstrap=new URL('data:text/javascript,'+encodeURIComponent(`
    import {parentPort,workerData} from 'node:worker_threads';
    globalThis.self={postMessage:data=>parentPort.postMessage(data)};
    await import(workerData.url);
    parentPort.on('message',data=>self.onmessage({data}));
  `));
  const workers=[];
  globalThis.Worker=class {
    constructor(url){this.worker=new NodeWorker(workerBootstrap,{workerData:{url:url.href}});workers.push(this.worker);this.worker.on('message',data=>this.onmessage?.({data}));this.worker.on('error',error=>this.onerror?.(error));}
    postMessage(data){this.worker.postMessage(data);}
    terminate(){this.worker.terminate();}
  };
  t.after(async()=>{await Promise.all(workers.map(w=>w.terminate()));});
  const wait=async predicate=>{const end=Date.now()+6000;while(!predicate()){if(Date.now()>end)throw Error('Timed out: '+$('status').textContent);await new Promise(r=>setTimeout(r,15));}};
  const analyze=async()=>{$('analyze').click();await wait(()=>$('status').textContent===translate('zh','done'));};
  await import(new URL(built ? '../dist/app.js' : '../src/app.js',import.meta.url));
  await t.test('sample analysis and source navigation use the attached controls',async()=>{
    $('sample').click();await analyze();assert.equal($('metric-count').textContent,'6');
    $('source-query').value='innerHTML';$('source-query').oninput();await wait(()=>$('source-matches').children.length>0);
    $('source-matches').querySelector('button').click();
    assert.equal($('code').value.slice($('code').selectionStart,$('code').selectionEnd),'innerHTML');
  });
  await t.test('batch review obeys the current filter and preserves full report scope',async()=>{
    $('priority').value='high';$('priority').onchange();assert.equal($('batch-count').textContent,'3');
    $('batch-status').value='false_positive';$('batch-apply').click();assert.equal($('metric-reviewed').textContent,'3');
    document.querySelector('[data-format=json]').click();const report=JSON.parse(await downloads.at(-1).text());
    assert.equal(report.findings.length,6);assert.equal(report.findings.filter(f=>f.status==='false_positive').length,3);
    assert.ok(confirmations.at(-1).includes('3'));assert.equal(writes,1);
  });
  let snapshot;
  await t.test('snapshot restoration requires fresh analysis and does not persist imported decisions',async()=>{
    $('use-baseline').click();$('save-project').click();snapshot=await downloads.at(-1).text();
    assert.equal(JSON.parse(snapshot).format,'XSS-AUDIT-PROJECT');assert.equal(JSON.parse(snapshot).files.length,2);
    $('reset').click();storage.clear();const before=writes;
    $('project-upload').files=[new File([snapshot],'project.json')];await $('project-upload').onchange();
    assert.equal($('metric-count').textContent,'—');assert.equal(writes,before);
    await analyze();assert.equal($('metric-reviewed').textContent,'3');assert.equal(writes,before);
    document.querySelector('[data-format=json]').click();const report=JSON.parse(await downloads.at(-1).text());
    assert.equal(report.comparison.unchanged,6);assert.equal(report.findings.filter(f=>f.review_origin==='snapshot').length,3);
    document.querySelector('.finding').click();assert.ok($('detail-content').textContent.includes(translate('zh','importedReview')));
  });
  await t.test('ZIP selection reaches the real import Worker, then the analyzer',async()=>{
    const zip=zipSync({'project/src/main.js':strToU8('out.innerHTML=location.hash;'),'project/node_modules/skip.js':strToU8('not read')});
    $('zip-upload').files=[new File([zip],'project.zip')];await $('zip-upload').onchange();
    await wait(()=>$('status').textContent===translate('zh','importDone'));
    assert.equal($('filename').value,'src/main.js');assert.equal($('inventory-count').textContent,'1');
    await analyze();assert.equal($('metric-count').textContent,'1');
  });
  await t.test('cancelling while ZIP bytes load cannot replace the current project later',async()=>{
    let finish;const pending=new Promise(r=>finish=r), before=$('code').value;
    $('zip-upload').files=[{size:100,arrayBuffer:()=>pending}];const job=$('zip-upload').onchange();
    $('cancel').click();finish(zipSync({'late.js':strToU8('late')}).buffer);await job;
    assert.equal($('code').value,before);assert.equal($('status').textContent,translate('zh','cancelled'));
  });
  await t.test('bad ZIP and superseded snapshot reads preserve current source',async()=>{
    const before=$('code').value;
    $('zip-upload').files=[new File([new Uint8Array([1,2,3])],'bad.zip')];await $('zip-upload').onchange();
    await wait(()=>$('status').textContent===translate('zh','zipInvalid'));assert.equal($('code').value,before);
    let finish;const pending=new Promise(r=>finish=r);
    $('project-upload').files=[{size:snapshot.length,arrayBuffer:()=>pending}];const job=$('project-upload').onchange();
    $('code').value=before+'\n// newer edit';$('code').oninput();finish(new TextEncoder().encode(snapshot).buffer);await job;
    assert.equal($('code').value,before+'\n// newer edit');
  });
  await t.test('language changes localize the new controls without dropping project state',()=>{
    const before=$('code').value;$('language').value='en';$('language').onchange();
    assert.equal($('save-project').textContent,'Download project snapshot');assert.equal($('zip-import').textContent,'Import project ZIP');assert.equal($('code').value,before);
  });
});
