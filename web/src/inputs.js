import { normalizePath } from './scope.js';
export const LIMITS = { files: 100, fileBytes: 262144, totalBytes: 5242880, findings: 2000, nodes: 40000, depth: 80 };
export function validateFiles(files) {
  if (!Array.isArray(files) || files.length > LIMITS.files) throw Error('fileCount');
  let bytes = 0;
  const paths = new Set();
  for (const file of files) {
    if (!file || typeof file.content !== 'string') throw Error('invalidFile');
    const path = normalizePath(file.path);
    if (path !== file.path || paths.has(path)) throw Error('invalidFile');
    paths.add(path);
    const size = new TextEncoder().encode(file.content).length;
    if (size > LIMITS.fileBytes) throw Error('fileSize');
    if (file.content.includes('\0')) throw Error('binary');
    bytes += size;
  }
  if (bytes > LIMITS.totalBytes) throw Error('totalSize');
}

