import { analyzeProject } from './engine.js';
self.onmessage = async ({ data }) => {
  try { self.postMessage({ result: await analyzeProject(data.files) }); }
  catch (error) { self.postMessage({ error: error.message }); }
};
