import { VERSION } from './version.js';
// One disposable Worker per run. Stopped jobs cannot publish late results.
export function startAnalysis(files, handlers, options = {}) {
  return startWorkerJob({files:structuredClone(files),scope:options.scope},handlers,options);
}
export function startArchiveImport(bytes,handlers,options={}) {
  return startWorkerJob({task:'archive',bytes,scope:options.scope,stripRoot:options.stripRoot},handlers,options);
}
function startWorkerJob(message,handlers,options) {
  const createWorker = options.createWorker || (() => new Worker(new URL('worker.js?v=' + VERSION, import.meta.url), { type:'module' }));
  const schedule = options.schedule || setTimeout;
  const unschedule = options.unschedule || clearTimeout;
  let running = true, timer;
  const worker = createWorker();
  const cancel = () => { if (!running) return; running = false; unschedule(timer); worker.terminate(); };
  worker.onmessage = ({data}) => {
    if (!running) return;
    cancel();
    if (data.error) handlers.error(data.error); else handlers.result(data.result);
  };
  worker.onerror = () => { if (running) { cancel(); handlers.error('workerError'); } };
  timer = schedule(() => { if (running) { cancel(); handlers.error('timeout'); } },10000);
  try { worker.postMessage(message); }
  catch { cancel(); throw Error('workerError'); }
  return cancel;
}
