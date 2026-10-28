// One disposable Worker per run. Stopped jobs cannot publish late results.
export function startAnalysis(files, handlers, options = {}) {
  const createWorker = options.createWorker || (() => new Worker(new URL('worker.js', import.meta.url), { type:'module' }));
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
  worker.postMessage({files:structuredClone(files)});
  return cancel;
}
