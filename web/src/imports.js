import { LIMITS, validateFiles } from './inputs.js';
import { DEFAULT_SCOPE, normalizePath, scopeReason, validateScope } from './scope.js';

// Metadata is inspected before any file content is read; rejected batches never mutate the project.
export async function importSources(uploaded, existing = [], options = {}) {
  if (!Array.isArray(uploaded) || uploaded.length > 5000) throw Error('inventoryLimit');
  const scope = validateScope(options.scope || DEFAULT_SCOPE), skipped = [], accepted = [];
  const seen = new Set(existing.map(f => f.path));
  let total = existing.reduce((sum, f) => sum + new TextEncoder().encode(f.content).length, 0);
  for (const item of uploaded) {
    let path = item.webkitRelativePath || item.name;
    if (options.directory && item.webkitRelativePath) path = path.slice(path.indexOf('/') + 1);
    path = normalizePath(path);
    const reason = scopeReason(path, scope);
    if (reason) { skipped.push({path, reason}); continue; }
    if (seen.has(path)) throw Error('invalidFile'); seen.add(path);
    if (accepted.length + existing.length >= LIMITS.files) throw Error('fileCount');
    if (!Number.isSafeInteger(item.size) || item.size < 0 || item.size > LIMITS.fileBytes) throw Error('fileSize');
    total += item.size; if (total > LIMITS.totalBytes) throw Error('totalSize');
    accepted.push({ item, path });
  }
  if (!accepted.length) throw Error('noImportable');
  const next = [...existing];
  for (const {item, path} of accepted) {
    let content;
    try { content = new TextDecoder('utf-8', {fatal: true}).decode(await item.arrayBuffer()); } catch { throw Error('decode'); }
    next.push({path, content});
  }
  validateFiles(next);
  return {files: next, skipped};
}
