import { ENGINE } from './version.js';
import { LIMITS, validateFiles } from './inputs.js';
import { normalizePath, validateScope } from './scope.js';
import { validateBaseline } from './baseline.js';

export const SNAPSHOT_BYTES=32*1024*1024;
export const REVIEW_STATUSES=new Set(['pending','confirmed','false_positive','fixed']);
const record = value => value && typeof value==='object' && !Array.isArray(value);
function baselineData(baseline) {
  if (!baseline) return null;
  return {schema_version:2,engine:baseline.engine,created_at:baseline.created_at,scope:baseline.scope,
    incomplete:false,notes:[],files:baseline.files.map(f=>({...f,...(f.analyzed ? {complete:true} : {})})),findings:baseline.findings};
}
export function validateSnapshot(data) {
  try {
    if (!record(data) || data.format!=='XSS-AUDIT-PROJECT' || data.version!==1 || data.engine!==ENGINE || typeof data.created_at!=='string' || !Number.isFinite(Date.parse(data.created_at))) throw Error();
    validateFiles(data.files); if (!data.files.length) throw Error();
    const scope=validateScope(data.scope), files=data.files.map(({path,content})=>({path,content}));
    if (!record(data.reviews) || Object.keys(data.reviews).length>LIMITS.findings) throw Error();
    const reviews=Object.create(null);
    for (const [id,r] of Object.entries(data.reviews)) {
      if (!/^[a-f0-9]{64}$/.test(id) || !record(r) || !REVIEW_STATUSES.has(r.status) || typeof r.note!=='string' || r.note.length>2000) throw Error();
      reviews[id]={status:r.status,note:r.note};
    }
    if (!Array.isArray(data.inventory) || data.inventory.length>5000) throw Error();
    const inventory=data.inventory.map(item=>{
      if (!record(item) || normalizePath(item.path)!==item.path || !['excluded','unsupported','notIncluded'].includes(item.reason)) throw Error();
      return {path:item.path,reason:item.reason};
    });
    const baseline=data.baseline ? validateBaseline(data.baseline) : null;
    return {files,scope,reviews,inventory,baseline};
  } catch { throw Error('snapshotInvalid'); }
}
export function parseSnapshot(text) {
  if (typeof text!=='string' || new TextEncoder().encode(text).length>SNAPSHOT_BYTES) throw Error('snapshotSize');
  let data; try { data=JSON.parse(text); } catch { throw Error('snapshotInvalid'); }
  return validateSnapshot(data);
}
export function exportSnapshot(files,scope,options={}) {
  const data={format:'XSS-AUDIT-PROJECT',version:1,engine:ENGINE,created_at:new Date().toISOString(),files,scope,
    reviews:options.reviews || {},inventory:options.inventory || [],baseline:baselineData(options.baseline)};
  validateSnapshot(data);
  const text=JSON.stringify(data);
  if (new TextEncoder().encode(text).length>SNAPSHOT_BYTES) throw Error('snapshotSize');
  return text;
}

// Literal bounded search. No regex from user input and no interpretation as HTML.
export function searchSources(files,query,options={}) {
  if (typeof query!=='string' || !query || query.length>200) return {matches:[],truncated:false};
  const fold=value=>value.replace(/[A-Z]/g,c=>c.toLowerCase());
  const needle=options.caseSensitive ? query : fold(query), matches=[];
  for (const file of files) {
    const lines=file.content.split('\n');
    for (let index=0;index<lines.length;index++) {
      const line=lines[index], haystack=options.caseSensitive ? line : fold(line);
      const column=haystack.indexOf(needle);
      if (column<0) continue;
      if (matches.length===200) return {matches,truncated:true};
      const start=Math.max(0,column-70);
      matches.push({path:file.path,line:index+1,column:column+1,length:query.length,excerpt:line.slice(start,start+240)});
    }
  }
  return {matches,truncated:false};
}
// Apply only explicit IDs from the current filtered view; preserve individual notes.
export function applyReviewBatch(result,ids,status) {
  if (!result || !REVIEW_STATUSES.has(status) || !Array.isArray(ids)) throw Error('reviewInvalid');
  const selected=new Set(ids), found=result.findings.filter(f=>selected.has(f.id));
  if (found.length!==selected.size) throw Error('reviewInvalid');
  for (const finding of found) { finding.status=status; finding.review_origin='manual'; }
  return found;
}
