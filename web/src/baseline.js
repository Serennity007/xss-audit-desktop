import { ENGINE } from './version.js';
import { LIMITS } from './inputs.js';
import { normalizePath, validateScope } from './scope.js';

const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export const BASELINE_BYTES = 16777216;

export function validateBaseline(data) {
  if (!data || data.schema_version !== 2 || data.engine !== ENGINE || data.incomplete !== false || !Array.isArray(data.notes) || data.notes.length || !Array.isArray(data.files) || data.files.length > LIMITS.files || !Array.isArray(data.findings) || data.findings.length > LIMITS.findings || (data.export_scope !== undefined && data.export_scope !== 'all-results') || typeof data.created_at !== 'string' || !Number.isFinite(Date.parse(data.created_at))) throw Error('invalidBaseline');
  let scope;
  try { scope = validateScope(data.scope); } catch { throw Error('invalidBaseline'); }
  const paths = new Map(), ids = new Set(), files = [], findings = [];
  for (const file of data.files) {
    try { if (normalizePath(file.path) !== file.path) throw Error(); } catch { throw Error('invalidBaseline'); }
    if (paths.has(file.path) || typeof file.analyzed !== 'boolean' || (file.analyzed && (!digest(file.sha256) || file.complete !== true)) || (!file.analyzed && !['excluded','notIncluded'].includes(file.reason))) throw Error('invalidBaseline');
    const safe = {path:file.path, analyzed:file.analyzed, sha256:file.sha256, reason:file.reason};
    paths.set(file.path, safe); files.push(safe);
  }
  for (const f of data.findings) {
    if (!f || !digest(f.id) || ids.has(f.id) || !paths.get(f.path)?.analyzed || typeof f.rule !== 'string' || !/^[A-Z][A-Z0-9-]{0,79}$/.test(f.rule) || !Number.isSafeInteger(f.line) || f.line < 1 || !Number.isSafeInteger(f.column) || f.column < 1) throw Error('invalidBaseline');
    ids.add(f.id); findings.push({id:f.id, path:f.path, rule:f.rule, line:f.line, column:f.column});
  }
  return {engine:data.engine, created_at:data.created_at, scope, files, findings};
}

export function parseBaseline(text) {
  if (typeof text !== 'string' || new TextEncoder().encode(text).length > BASELINE_BYTES) throw Error('baselineSize');
  let data; try { data = JSON.parse(text); } catch { throw Error('invalidBaseline'); }
  return validateBaseline(data);
}

export function compareBaseline(current, baseline) {
  const previous = new Map(baseline.findings.map(f => [f.id, f])), previousFiles = new Map(baseline.files.map(f => [f.path, f]));
  const currentFiles = new Map(current.files.map(f => [f.path, f])), observed = new Set();
  let unchanged = 0;
  for (const f of current.findings) {
    const old = previous.get(f.id), sameFile = previousFiles.get(f.path)?.sha256 === currentFiles.get(f.path)?.sha256;
    const same = old && sameFile && old.path === f.path && old.rule === f.rule && old.line === f.line && old.column === f.column;
    f.baseline_state = same ? 'unchanged' : 'new';
    if (same) { unchanged++; observed.add(f.id); }
  }
  const not_observed = baseline.findings.filter(f => !observed.has(f.id)).map(f => ({...f, reason: !currentFiles.has(f.path) ? 'fileMissing' : !currentFiles.get(f.path).analyzed ? 'outsideScope' : current.incomplete ? 'currentIncomplete' : 'notObserved'}));
  current.comparison = {created_at:baseline.created_at, new:current.findings.length - unchanged, unchanged, not_observed, current_incomplete:current.incomplete, scope_changed:JSON.stringify(current.scope) !== JSON.stringify(baseline.scope), notice:'absence-is-not-a-fix'};
  return current.comparison;
}

export function clearComparison(result) {
  if (!result) return;
  delete result.comparison;
  for (const finding of result.findings) delete finding.baseline_state;
}
