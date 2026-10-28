import test from 'node:test';
import assert from 'node:assert/strict';
import { startAnalysis } from '../src/runner.js';
function fixture() {
  const calls=[], workers=[], timers=[];
  const options={ createWorker:()=> { const w={terminate(){this.terminated=true;},postMessage(data){this.input=data;}}; workers.push(w); return w; }, schedule:(fn,delay)=>{ assert.equal(delay,10000); timers.push(fn); return timers.length; }, unschedule:()=>{} };
  const handlers={result:r=>calls.push(['result',r]),error:e=>calls.push(['error',e])};
  return {options,handlers,calls,workers,timers};
}
test('cancelled and superseded workers cannot publish late results',()=>{
  const f=fixture(), input=[{path:'a.js',content:'first'}];
  const cancel=startAnalysis(input,f.handlers,f.options);
  input[0].content='changed';
  assert.equal(f.workers[0].input.files[0].content,'first');
  cancel(); startAnalysis(input,f.handlers,f.options);
  f.workers[0].onmessage({data:{result:'stale'}});
  f.workers[1].onmessage({data:{result:'current'}});
  assert.deepEqual(f.calls,[['result','current']]);
  assert.ok(f.workers.every(w=>w.terminated));
});
test('timeout terminates work and blocks subsequent result',()=>{
  const f=fixture(); startAnalysis([],f.handlers,f.options);
  f.timers[0](); f.workers[0].onmessage({data:{result:'late'}});
  assert.deepEqual(f.calls,[['error','timeout']]); assert.ok(f.workers[0].terminated);
});
test('worker faults and analysis errors are reported once',()=>{
  for (const failure of ['event','payload']) {
    const f=fixture(); startAnalysis([],f.handlers,f.options);
    if(failure==='event') f.workers[0].onerror(); else f.workers[0].onmessage({data:{error:'fileSize'}});
    f.timers[0]();
    assert.deepEqual(f.calls,[['error',failure==='event'?'workerError':'fileSize']]);
  }
});
