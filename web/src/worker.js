import { analyzeProject } from './engine.js';
import { importArchive } from './archive.js';
self.onmessage = async ({ data }) => {
  try { self.postMessage({ result: data.task==='archive' ? importArchive(data.bytes,{scope:data.scope,stripRoot:data.stripRoot}) : await analyzeProject(data.files, {scope:data.scope}) }); }
  catch (error) { self.postMessage({ error: error.message }); }
};
