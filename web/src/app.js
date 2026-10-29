import { sample, componentSample } from './sample.js';
import { validateFiles } from './inputs.js';
import { translate } from './i18n.js';
import { signalText, reportText, exportReport } from './reports.js';
import { startAnalysis, startArchiveImport } from './runner.js';
import { DEFAULT_SCOPE, validateScope } from './scope.js';
import { importSources } from './imports.js';
import { BASELINE_BYTES, validateBaseline, parseBaseline, compareBaseline, clearComparison } from './baseline.js';
import { filterFindings } from './filters.js';
import { ZIP_BYTES } from './archive-limits.js';
import { SNAPSHOT_BYTES, parseSnapshot, exportSnapshot, searchSources, applyReviewBatch } from './project.js';

const $ = id => document.getElementById(id);
const REVIEW_KEY = 'xss-audit-studio.reviews.v1';
const statuses = new Set(['pending', 'confirmed', 'false_positive', 'fixed']);
let language = 'zh', files = [{ path:'review.ts', content:'' }], active = 0;
let result = null, selected = null, stopAnalysis = null, statusKey = 'ready';
let baseline = null, projectVersion = 0, baselineVersion = 0, importInventory = [];
const drafts = new Map();
let projectReviews = new Map(), visibleSignals = [], searchTimer;
const t = key => translate(language, key);
function element(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
function announce(key) { statusKey = key; $('status').textContent = t(key); }
function cancelWorker() { if (stopAnalysis) stopAnalysis(); stopAnalysis = null; $('cancel').hidden = true; $('analyze').disabled = false; }
function invalidate(key = 'stale') { projectVersion++; drafts.clear(); cancelWorker(); result = null; selected = null; announce(key); renderResults(); renderDetail(); metrics(); renderBaseline(); renderFiles(); scheduleSourceSearch(); }
function readScope() { return validateScope({include:$('include').value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean), exclude:$('exclude').value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean)}); }
function reviews() {
  try {
    const raw = localStorage.getItem(REVIEW_KEY);
    if (!raw || raw.length > 4000000) return {};
    const data = JSON.parse(raw);
    return data && !Array.isArray(data) && typeof data === 'object' ? data : {};
  } catch { return {}; }
}
function restoreReviews() {
  const saved = reviews();
  for (const f of result.findings) {
    const record = projectReviews.get(f.id) || saved[f.id];
    if (record && statuses.has(record.status) && typeof record.note === 'string') { f.status = record.status; f.note = record.note.slice(0, 2000); f.review_origin = record.origin === 'snapshot' ? 'snapshot' : 'manual'; }
  }
}
function metrics() {
  $('metric-files').textContent = result ? result.files.filter(f => f.analyzed).length : '—';
  $('metric-count').textContent = result ? result.findings.length : '—';
  $('metric-high').textContent = result ? result.findings.filter(f => f.priority === 'high').length : '—';
  $('metric-reviewed').textContent = result ? result.findings.filter(f => f.status !== 'pending').length : '—';
  document.querySelectorAll('[data-format]').forEach(b => b.disabled = !result);
  $('copy-all').disabled = !result;
  $('use-baseline').disabled = !result || result.incomplete;
  $('save-project').disabled = !files.length;
}
function renderFiles() {
  $('file-list').replaceChildren(); $('file-count').textContent = String(files.length).padStart(2, '0');
  files.forEach((file, index) => {
    const button = element('button', file.path, 'file-item' + (active === index ? ' active' : ''));
    const count = result?.findings.filter(f=>f.path === file.path).length;
    if (count !== undefined) button.append(element('span', String(count), 'file-signal-count'));
    button.title = file.path; button.setAttribute('aria-pressed', String(active === index)); button.onclick = () => choose(index); $('file-list').append(button);
  });
  $('remove').disabled = files.length === 0;
}
function updateGutter() {
  $('gutter').textContent = Array.from({length: $('code').value.split('\n').length}, (_, i) => i + 1).join('\n');
  $('gutter').scrollTop = $('code').scrollTop;
  $('cursor').textContent = 'L' + ($('code').value.slice(0, $('code').selectionStart).split('\n').length);
}
function choose(index) {
  active = index;
  const file = files[index];
  $('code').value = file?.content || ''; $('filename').value = file?.path || '';
  $('code').disabled = !file; $('filename').disabled = !file;
  $('file-type').textContent = file?.path.split('.').pop().toUpperCase().slice(0, 8) || '—';
  updateGutter(); renderFiles();
  if ($('file-only').checked) renderResults();
}
function empty(key, description) { const box = element('div', undefined, 'empty'); box.append(element('span', '{ }', 'empty-icon'), element('strong', t(key))); if (description) box.append(element('p', t(description))); return box; }
function renderResults() {
  $('findings').replaceChildren(); $('coverage').replaceChildren();
  if (!result) { visibleSignals=[]; $('batch-count').textContent='0'; $('batch-apply').disabled=true; $('result-count').textContent = '—'; $('findings').append(empty('empty', 'intro')); return; }
  const visible = filterFindings(result,{query:$('search').value,priority:$('priority').value,status:$('status-filter').value,category:$('category').value,mode:$('mode').value,baseline:$('change-filter').value,path:$('file-only').checked ? files[active]?.path : ''},t);
  visibleSignals=visible; $('batch-count').textContent=String(visible.length); $('batch-apply').disabled=!visible.length;
  $('result-count').textContent = visible.length + ' / ' + result.findings.length;
  for (const f of visible) {
    const button = element('button', undefined, 'finding' + (selected === f ? ' selected' : ''));
    const top = element('span', undefined, 'finding-top'); top.append(element('span', t(f.priority), 'badge ' + f.priority), element('span', t(f.mode)));
    if (f.baseline_state) top.append(element('span', t(f.baseline_state), 'change-badge ' + f.baseline_state));
    button.append(top, element('strong', t(f.category), 'finding-title'), element('span', f.path + ':' + f.line + ' · ' + t(f.status), 'finding-path'));
    button.onclick = () => {
      selected = f; const index = files.findIndex(file => file.path === f.path); if (index >= 0) choose(index);
      renderResults(); renderDetail();
      const start = files[index].content.split('\n').slice(0, f.line - 1).reduce((n, s) => n + s.length + 1, 0);
      $('code').focus(); $('code').setSelectionRange(start, start + (files[index].content.split('\n')[f.line - 1]?.length || 0));
      $('code').scrollTop = Math.max(0, (f.line - 5) * 22.8); updateGutter();
    };
    $('findings').append(button);
  }
  if (!visible.length) $('findings').append(empty(result.findings.length ? 'noFiltered' : 'noResults'));
  for (const n of result.notes) $('coverage').append(element('li', n.path + (n.line ? ':' + n.line : '') + ' — ' + t(n.code)));
  for (const file of result.files) $('coverage').append(element('li', file.path + ' — ' + (file.reason ? t(file.reason) : t(file.complete ? 'complete' : 'incompleteFile'))));
}
function renderDetail() {
  $('detail-content').replaceChildren(); $('review-form').hidden = !selected; $('copy').disabled = !selected;
  if (!selected) { $('detail-content').append(element('p', t('pick'), 'subtle')); return; }
  const f = selected, container = $('detail-content');
  container.append(element('h3', t(f.category)), element('div', f.path + ':' + f.line + ':' + f.column + ' · ' + f.rule + ' · ' + t(f.mode), 'detail-meta'));
  const evidence = element('div', undefined, 'evidence');
  if (f.mode === 'ast') {
    evidence.append(element('p', t('source') + ' · L' + f.source.line + ' ' + f.source.text));
    for (const s of f.steps) evidence.append(element('p', t('assignment') + ' · L' + s.line + ' ' + s.text));
    evidence.append(element('p', t('sink') + ' · L' + f.sink.line + ' ' + f.sink.text));
    if (f.sanitized) evidence.append(element('p', t('sanitized')));
    evidence.append(element('p', t('unverified'), 'subtle'));
  } else evidence.append(element('p', t('evidenceMissing')));
  container.append(evidence, element('pre', f.context, 'code-context'), element('p', t(f.mode === 'pattern' ? 'patternFix' : f.category + 'Fix')));
  if (f.context_truncated || f.evidence_truncated) container.append(element('p',t('excerptTruncated'),'coverage-warning'));
  if (f.review_origin==='snapshot') container.append(element('p',t('importedReview'),'coverage-warning'));
  const draft = drafts.get(f.id);
  $('review-status').value = draft?.status || f.status; $('review-note').value = draft?.note ?? f.note;
}
function renderInventory() {
  $('inventory-list').replaceChildren(); $('inventory-count').textContent = String(importInventory.length);
  for (const item of importInventory.slice(0,100)) $('inventory-list').append(element('li',item.path + ' — ' + t(item.reason)));
  if (importInventory.length > 100) $('inventory-list').append(element('li',t('moreItems') + ' (' + (importInventory.length - 100) + ')'));
  $('inventory').hidden = !importInventory.length;
}
function renderBaseline() {
  $('baseline-summary').replaceChildren(); $('missing-list').replaceChildren();
  $('clear-baseline').disabled = !baseline; $('change-filter').disabled = !baseline;
  if (!baseline) { $('baseline-summary').append(element('p',t('baselineEmpty'),'subtle')); return; }
  $('baseline-summary').append(element('p', baseline.created_at + ' · ' + baseline.findings.length + ' ' + t('counts'), 'subtle'));
  if (!result?.comparison) { $('baseline-summary').append(element('p',t('baselineReady'),'subtle')); return; }
  const c = result.comparison;
  const stats = element('div',undefined,'comparison-stats');
  for (const [key,count] of [['new',c.new],['unchanged',c.unchanged],['notObserved',c.not_observed.length]]) stats.append(element('span',t(key) + ' · ' + count));
  $('baseline-summary').append(stats);
  if (c.scope_changed) $('baseline-summary').append(element('p',t('scopeChanged'),'coverage-warning'));
  if (c.current_incomplete) $('baseline-summary').append(element('p',t('currentIncomplete'),'coverage-warning'));
  for (const f of c.not_observed.slice(0,100)) $('missing-list').append(element('li',f.path + ':' + f.line + ' · ' + f.rule + ' — ' + t(f.reason)));
  if (c.not_observed.length > 100) $('missing-list').append(element('li',t('moreItems')));
}
function scheduleSourceSearch() { clearTimeout(searchTimer); searchTimer=setTimeout(renderSourceSearch,150); }
function renderSourceSearch() {
  clearTimeout(searchTimer); $('source-matches').replaceChildren();
  const found=searchSources(files,$('source-query').value,{caseSensitive:$('source-case').checked});
  $('source-count').textContent=found.matches.length+(found.truncated ? '+' : '')+' '+t('sourceRows');
  for (const hit of found.matches) {
    const button=element('button',undefined,'source-hit');
    button.append(element('strong',hit.path+':'+hit.line+':'+hit.column),element('code',hit.excerpt));
    button.onclick=()=>{
      const index=files.findIndex(f=>f.path===hit.path); if (index<0) return;
      choose(index); selected=null; renderDetail(); renderResults();
      const start=files[index].content.split('\n').slice(0,hit.line-1).reduce((n,line)=>n+line.length+1,0)+hit.column-1;
      $('code').focus(); $('code').setSelectionRange(start,start+hit.length);
      $('code').scrollTop=Math.max(0,(hit.line-5)*22.8); updateGutter();
    };
    $('source-matches').append(button);
  }
  if (found.truncated) $('source-matches').append(element('p',t('searchTruncated'),'coverage-warning'));
}
function persistReviewEntries(entries) {
  let saved=reviews();
  for (const f of entries) {
    const value={status:f.status,note:f.note,origin:f.review_origin || 'manual',at:Date.now()};
    projectReviews.delete(f.id); projectReviews.set(f.id,value); saved[f.id]=value;
  }
  while (projectReviews.size>2000) projectReviews.delete(projectReviews.keys().next().value);
  saved=Object.fromEntries(Object.entries(saved).filter(([,v])=>v && typeof v.at==='number').sort((a,b)=>b[1].at-a[1].at).slice(0,500));
  try { localStorage.setItem(REVIEW_KEY,JSON.stringify(saved)); announce('saved'); } catch { announce('storageFailed'); }
}
function downloadText(text,type,filename) {
  const url=URL.createObjectURL(new Blob([text],{type:type+';charset=utf-8'})), link=element('a');
  link.href=url; link.download=filename; document.body.append(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000);
}
const filenameTime=()=>new Date().toISOString().replace(/[:.]/g,'-');
const announceError=error=>announce(translate(language,error.message)===error.message ? 'importFailed' : error.message);
function applyBaseline() { clearComparison(result); if (result && baseline) compareBaseline(result,baseline); renderBaseline(); renderResults(); }
function localize() {
  document.documentElement.lang = language === 'zh' ? 'zh-CN' : 'en';
  document.title = 'XSS Audit Studio | ' + t('title');
  document.querySelectorAll('[data-i18n]').forEach(node => node.textContent = t(node.getAttribute('data-i18n')));
  document.querySelectorAll('[data-placeholder]').forEach(node => node.placeholder = t(node.getAttribute('data-placeholder')));
  for (const [id,key] of [['filename','fileName'],['code','editor'],['search','search'],['source-query','sourceSearch'],['batch-status','batchStatus'],['priority','all'],['review-note','notes'],['review-status','status'],['status-filter','allStatuses'],['category','allCategories'],['mode','allModes'],['change-filter','allChanges'],['sample-kind','sampleKind']]) $(id).setAttribute('aria-label', t(key));
  $('metrics').setAttribute('aria-label',t('overview')); $('analyze').title = t('shortcut');
  announce(statusKey); renderResults(); renderDetail(); metrics(); renderInventory(); renderBaseline(); renderSourceSearch();
}
$('language').onchange = () => { language = $('language').value; localize(); };
$('code').oninput = () => { if (!files[active]) return; files[active].content = $('code').value; updateGutter(); invalidate(); };
$('code').onscroll = () => $('gutter').scrollTop = $('code').scrollTop;
$('code').onkeyup = updateGutter; $('code').onclick = updateGutter;
$('filename').onchange = () => {
  const previous = files[active].path, value = $('filename').value.trim();
  try { validateFiles(files.map((f,i)=>i === active ? {...f,path:value} : f)); } catch { $('filename').value = previous; announce('invalidFile'); return; }
  files[active].path = value; invalidate(); renderFiles(); choose(active);
};
$('add').onclick = () => {
  if (files.length >= 100) { announce('fileCount'); return; }
  let n = 1; while (files.some(f => f.path === 'review-' + n + '.ts')) n++;
  files.push({path:'review-' + n + '.ts',content:''}); invalidate('ready'); choose(files.length - 1); $('code').focus();
};
$('remove').onclick = () => { files.splice(active, 1); invalidate('ready'); choose(Math.max(0, active - 1)); };
$('reset').onclick = () => { if (!files.some(f => f.content) || confirm(t('resetConfirm'))) { files = [{path:'review.ts',content:''}]; projectReviews.clear(); baseline = null; baselineVersion++; importInventory = []; resetFilters(); invalidate('ready'); choose(0); renderInventory(); } };
$('sample').onclick = () => {
  if (files.some(f => f.content) && !confirm(t('resetConfirm'))) return;
  files = structuredClone($('sample-kind').value === 'components' ? componentSample : sample); projectReviews.clear(); baseline = null; baselineVersion++; importInventory = []; resetFilters(); invalidate('ready'); choose(0); renderInventory();
};
$('import').onclick = () => $('upload').click();
$('folder').onclick = () => $('folder-upload').click();
async function readUpload(input, directory) {
  const uploaded = [...input.files]; input.value = ''; if (!uploaded.length) return;
  if (directory && files.some(f=>f.content) && !confirm(t('resetConfirm'))) return;
  const version = ++projectVersion;
  cancelWorker(); announce('importing');
  try {
    const existing = directory ? [] : files.filter(f => f.content || f.path !== 'review.ts');
    const imported = await importSources(uploaded, existing, {directory, scope:readScope()});
    if (projectVersion !== version) return;
    files = imported.files; importInventory = directory ? imported.skipped : [...importInventory,...imported.skipped].slice(-5000);
    if (directory) resetFilters();
    invalidate('importDone'); choose(0); renderInventory();
  } catch (error) { if (projectVersion === version) announce(translate(language,error.message) === error.message ? 'importFailed' : error.message); }
}
$('upload').onchange = () => readUpload($('upload'),false);
$('folder-upload').onchange = () => readUpload($('folder-upload'),true);
$('zip-import').onclick=()=>$('zip-upload').click();
$('zip-upload').onchange=async()=>{
  const file=$('zip-upload').files[0]; $('zip-upload').value=''; if (!file) return;
  if (files.some(f=>f.content) && !confirm(t('resetConfirm'))) return;
  cancelWorker(); const version=++projectVersion;
  try {
    if (file.size>ZIP_BYTES) throw Error('zipSize');
    const scope=readScope(), stripRoot=$('strip-root').checked;
    $('analyze').disabled=true; $('cancel').hidden=false; announce('zipReading');
    stopAnalysis=()=>{projectVersion++;};
    const bytes=new Uint8Array(await file.arrayBuffer());
    if (projectVersion!==version) return;
    stopAnalysis=startArchiveImport(bytes,{
      result(imported) {
        if (projectVersion!==version) return;
        cancelWorker(); files=imported.files; importInventory=imported.skipped;
        resetFilters(); invalidate('importDone'); choose(0); renderInventory();
      },
      error(key) { if (projectVersion===version) { cancelWorker(); announceError(Error(key)); } }
    },{scope,stripRoot});
  } catch(error) { if (projectVersion===version) { cancelWorker(); announceError(error); } }
};
$('save-project').onclick=()=>{
  if (!files.length || !confirm(t('snapshotConfirm'))) return;
  try {
    const saved=result ? Object.fromEntries(result.findings.filter(f=>f.status!=='pending' || f.note).map(f=>[f.id,{status:f.status,note:f.note}])) : Object.fromEntries(projectReviews);
    const text=exportSnapshot(files,readScope(),{reviews:saved,baseline,inventory:importInventory});
    downloadText(text,'application/json','xss-project-'+filenameTime()+'.json'); announce('snapshotSaved');
  } catch(error) { announceError(error); }
};
$('load-project').onclick=()=>$('project-upload').click();
$('project-upload').onchange=async()=>{
  const file=$('project-upload').files[0]; $('project-upload').value=''; if (!file) return;
  const version=projectVersion, baseVersion=baselineVersion;
  try {
    if (file.size>SNAPSHOT_BYTES) throw Error('snapshotSize');
    let text; try { text=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer()); } catch { throw Error('snapshotInvalid'); }
    const loaded=parseSnapshot(text);
    if (projectVersion!==version || baselineVersion!==baseVersion) return;
    if (!confirm(t('restoreConfirm'))) return;
    files=loaded.files; baseline=loaded.baseline; baselineVersion++; importInventory=loaded.inventory;
    projectReviews=new Map(Object.entries(loaded.reviews).map(([id,r])=>[id,{...r,origin:'snapshot'}]));
    $('include').value=loaded.scope.include.join('\n'); $('exclude').value=loaded.scope.exclude.join('\n');
    resetFilters(); invalidate('snapshotLoaded'); choose(0); renderInventory();
  } catch(error) { if (projectVersion===version) announceError(error); }
};
$('source-query').oninput=scheduleSourceSearch; $('source-case').onchange=renderSourceSearch;
$('include').oninput = () => invalidate(); $('exclude').oninput = () => invalidate();
$('analyze').onclick = () => {
  let scope;
  try { validateFiles(files); scope = readScope(); if (!files.some(f => f.content.trim())) throw Error('emptyFile'); } catch(error) { announce(translate(language,error.message) === error.message ? 'invalidFile' : error.message); return; }
  invalidate('running');
  $('analyze').disabled = true; $('cancel').hidden = false;
  try {
    stopAnalysis = startAnalysis(files, {
      result(value) { cancelWorker(); result = value; result.import_inventory = structuredClone(importInventory); restoreReviews(); applyBaseline(); announce(result.incomplete ? 'partial' : 'done'); renderResults(); renderDetail(); renderFiles(); metrics(); },
      error(key) { cancelWorker(); announce(translate(language,key) === key ? 'workerError' : key); }
    }, {scope});
  } catch { cancelWorker(); announce('workerError'); }
};
$('cancel').onclick = () => { projectVersion++; cancelWorker(); announce('cancelled'); };
$('search').oninput = renderResults;
for (const id of ['priority','status-filter','category','mode','change-filter','file-only']) $(id).onchange = renderResults;
function resetFilters() { $('search').value = ''; for (const id of ['priority','status-filter','category','mode','change-filter']) $(id).value = ''; $('file-only').checked = false; renderResults(); }
$('reset-filters').onclick = resetFilters;
for (const id of ['review-status','review-note']) $(id).oninput = () => { if (selected) { drafts.set(selected.id,{status:$('review-status').value,note:$('review-note').value}); announce('draft'); } };
$('save').onclick = () => {
  if (!selected) return;
  selected.status = $('review-status').value; selected.note = $('review-note').value.slice(0,2000);
  selected.review_origin='manual';
  drafts.delete(selected.id);
  persistReviewEntries([selected]); renderResults(); renderDetail(); metrics();
};
$('batch-apply').onclick=()=>{
  if (!result || !visibleSignals.length) return;
  const ids=visibleSignals.map(f=>f.id), status=$('batch-status').value;
  if (!confirm(t('batchConfirm')+'\n'+ids.length+' · '+t(status))) return;
  try {
    const changed=applyReviewBatch(result,ids,status);
    for (const f of changed) drafts.delete(f.id);
    persistReviewEntries(changed); renderResults(); renderDetail(); metrics();
  } catch(error) { announceError(error); }
};
$('clear').onclick = () => {
  if (!confirm(t('confirmClear'))) return;
  try { localStorage.removeItem(REVIEW_KEY); } catch { announce('storageFailed'); return; }
  for (const f of result?.findings || []) { f.status='pending'; f.note=''; delete f.review_origin; }
  drafts.clear(); projectReviews.clear();
  renderResults(); renderDetail(); metrics(); announce('clearDone');
};
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); announce('copied'); }
  catch { $('copy-fallback').value = text; $('copy-dialog').showModal(); $('copy-fallback').select(); }
}
$('copy').onclick = () => { if (selected) copyText(signalText(selected,language)); };
$('copy-all').onclick = () => { if (result) copyText(reportText(result,language)); };
$('close-dialog').onclick = () => $('copy-dialog').close();
$('use-baseline').onclick = () => {
  try { baseline = validateBaseline(result); baselineVersion++; applyBaseline(); announce('baselineReady'); } catch { announce('invalidBaseline'); }
};
$('load-baseline').onclick = () => $('baseline-upload').click();
$('baseline-upload').onchange = async () => {
  const file = $('baseline-upload').files[0]; $('baseline-upload').value = ''; if (!file) return;
  const version = ++baselineVersion;
  try {
    if (file.size > BASELINE_BYTES) throw Error('baselineSize');
    let text; try { text = new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer()); } catch { throw Error('invalidBaseline'); }
    const loaded = parseBaseline(text);
    if (baselineVersion !== version) return;
    baseline = loaded; applyBaseline(); announce('baselineReady');
  } catch (error) { if (baselineVersion === version) announce(error.message === 'baselineSize' ? 'baselineSize' : 'invalidBaseline'); }
};
$('clear-baseline').onclick = () => { baseline = null; baselineVersion++; $('change-filter').value = ''; applyBaseline(); announce('baselineCleared'); };
document.querySelectorAll('[data-format]').forEach(button => button.onclick = () => {
  if (!result) { announce('reportUnavailable'); return; }
  const output = exportReport(result,language,button.dataset.format);
  downloadText(output.text,output.type,'xss-review-'+filenameTime()+'.'+output.extension);
});
$('include').value = DEFAULT_SCOPE.include.join('\n'); $('exclude').value = DEFAULT_SCOPE.exclude.join('\n');
document.addEventListener('keydown', event=>{ if ((event.ctrlKey || event.metaKey) && event.key === 'Enter' && !$('analyze').disabled && !$('copy-dialog').open) { event.preventDefault(); $('analyze').click(); } });
choose(0); localize();
