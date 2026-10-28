import { sample } from './sample.js';
import { validateFiles } from './engine.js';
import { translate } from './i18n.js';
import { signalText, exportReport } from './reports.js';
import { startAnalysis } from './runner.js';

const $ = id => document.getElementById(id);
const REVIEW_KEY = 'xss-audit-studio.reviews.v1';
const statuses = new Set(['pending', 'confirmed', 'false_positive', 'fixed']);
let language = 'zh', files = [{ path:'review.ts', content:'' }], active = 0;
let result = null, selected = null, stopAnalysis = null, statusKey = 'ready';
const t = key => translate(language, key);
function element(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
function announce(key) { statusKey = key; $('status').textContent = t(key); }
function cancelWorker() { if (stopAnalysis) stopAnalysis(); stopAnalysis = null; $('cancel').hidden = true; $('analyze').disabled = false; }
function invalidate(key = 'stale') { cancelWorker(); result = null; selected = null; announce(key); renderResults(); renderDetail(); metrics(); }
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
    const record = saved[f.id];
    if (record && statuses.has(record.status) && typeof record.note === 'string') { f.status = record.status; f.note = record.note.slice(0, 2000); }
  }
}
function metrics() {
  $('metric-files').textContent = result ? result.files.filter(f => f.analyzed).length : '—';
  $('metric-count').textContent = result ? result.findings.length : '—';
  $('metric-high').textContent = result ? result.findings.filter(f => f.priority === 'high').length : '—';
  $('metric-reviewed').textContent = result ? result.findings.filter(f => f.status !== 'pending').length : '—';
  document.querySelectorAll('[data-format]').forEach(b => b.disabled = !result);
}
function renderFiles() {
  $('file-list').replaceChildren(); $('file-count').textContent = String(files.length).padStart(2, '0');
  files.forEach((file, index) => {
    const button = element('button', file.path, 'file-item' + (active === index ? ' active' : ''));
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
}
function empty(key, description) { const box = element('div', undefined, 'empty'); box.append(element('span', '{ }', 'empty-icon'), element('strong', t(key))); if (description) box.append(element('p', t(description))); return box; }
function renderResults() {
  $('findings').replaceChildren(); $('coverage').replaceChildren();
  if (!result) { $('result-count').textContent = '—'; $('findings').append(empty('empty', 'intro')); return; }
  const query = $('search').value.toLowerCase(), priority = $('priority').value;
  const visible = result.findings.filter(f => (!priority || f.priority === priority) && [f.path, f.rule, f.context, t(f.category), f.note].join(' ').toLowerCase().includes(query));
  visible.sort((a,b) => ({high:0,medium:1,info:2}[a.priority] - {high:0,medium:1,info:2}[b.priority]) || a.path.localeCompare(b.path) || a.line - b.line);
  $('result-count').textContent = visible.length + ' / ' + result.findings.length;
  for (const f of visible) {
    const button = element('button', undefined, 'finding' + (selected === f ? ' selected' : ''));
    const top = element('span', undefined, 'finding-top'); top.append(element('span', t(f.priority), 'badge ' + f.priority), element('span', t(f.mode)));
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
  $('review-status').value = f.status; $('review-note').value = f.note;
}
function localize() {
  document.documentElement.lang = language === 'zh' ? 'zh-CN' : 'en';
  document.title = 'XSS Audit Studio | ' + t('title');
  document.querySelectorAll('[data-i18n]').forEach(node => node.textContent = t(node.dataset.i18n));
  document.querySelectorAll('[data-placeholder]').forEach(node => node.placeholder = t(node.dataset.placeholder));
  for (const [id,key] of [['filename','fileName'],['code','editor'],['search','search'],['priority','all'],['review-note','notes'],['review-status','status']]) $(id).setAttribute('aria-label', t(key));
  announce(statusKey); renderResults(); renderDetail(); metrics();
}
$('language').onchange = () => { language = $('language').value; localize(); };
$('code').oninput = () => { if (!files[active]) return; files[active].content = $('code').value; updateGutter(); invalidate(); };
$('code').onscroll = () => $('gutter').scrollTop = $('code').scrollTop;
$('code').onkeyup = updateGutter; $('code').onclick = updateGutter;
$('filename').onchange = () => {
  const previous = files[active].path, value = $('filename').value.trim();
  if (!value || files.some((f,i) => i !== active && f.path === value)) { $('filename').value = previous; announce('invalidFile'); return; }
  files[active].path = value; invalidate(); renderFiles(); choose(active);
};
$('add').onclick = () => {
  if (files.length >= 100) { announce('fileCount'); return; }
  let n = 1; while (files.some(f => f.path === 'review-' + n + '.ts')) n++;
  files.push({path:'review-' + n + '.ts',content:''}); invalidate('ready'); choose(files.length - 1); $('code').focus();
};
$('remove').onclick = () => { files.splice(active, 1); invalidate('ready'); choose(Math.max(0, active - 1)); };
$('reset').onclick = () => { if (!files.some(f => f.content) || confirm(t('resetConfirm'))) { files = [{path:'review.ts',content:''}]; invalidate('ready'); choose(0); } };
$('sample').onclick = () => {
  if (files.some(f => f.content) && !confirm(t('resetConfirm'))) return;
  files = structuredClone(sample); invalidate('ready'); choose(0);
};
$('import').onclick = () => $('upload').click();
$('upload').onchange = async () => {
  const uploaded = [...$('upload').files]; $('upload').value = ''; if (!uploaded.length) return;
  try {
    let next = files.filter(f => f.content || f.path !== 'review.ts');
    if (uploaded.length + next.length > 100) throw Error('fileCount');
    let total = next.reduce((n,f) => n + new TextEncoder().encode(f.content).length, 0);
    for (const f of uploaded) {
      if (f.size > 262144) throw Error('fileSize'); total += f.size; if (total > 5242880) throw Error('totalSize');
      let content; try { content = new TextDecoder('utf-8',{fatal:true}).decode(await f.arrayBuffer()); } catch { throw Error('decode'); }
      next.push({path:f.webkitRelativePath || f.name,content});
    }
    validateFiles(next); files = next; invalidate('ready'); choose(0);
  } catch (error) { announce(translate(language,error.message) === error.message ? 'importFailed' : error.message); }
};
$('analyze').onclick = () => {
  try { validateFiles(files); if (!files.some(f => f.content.trim())) throw Error('emptyFile'); } catch(error) { announce(error.message); return; }
  invalidate('running');
  $('analyze').disabled = true; $('cancel').hidden = false;
  try {
    stopAnalysis = startAnalysis(files, {
      result(value) { cancelWorker(); result = value; restoreReviews(); announce(result.incomplete ? 'partial' : 'done'); renderResults(); renderDetail(); metrics(); },
      error(key) { cancelWorker(); announce(translate(language,key) === key ? 'workerError' : key); }
    });
  } catch { cancelWorker(); announce('workerError'); }
};
$('cancel').onclick = () => { cancelWorker(); announce('cancelled'); };
$('search').oninput = renderResults; $('priority').onchange = renderResults;
$('save').onclick = () => {
  if (!selected) return;
  selected.status = $('review-status').value; selected.note = $('review-note').value.slice(0,2000);
  let saved = reviews(); saved[selected.id] = {status:selected.status,note:selected.note,at:Date.now()};
  saved = Object.fromEntries(Object.entries(saved).filter(([,v]) => v && typeof v.at === 'number').sort((a,b) => b[1].at-a[1].at).slice(0,500));
  try { localStorage.setItem(REVIEW_KEY,JSON.stringify(saved)); announce('saved'); } catch { announce('storageFailed'); }
  renderResults(); metrics();
};
$('clear').onclick = () => {
  if (!confirm(t('confirmClear'))) return;
  try { localStorage.removeItem(REVIEW_KEY); } catch { announce('storageFailed'); return; }
  for (const f of result?.findings || []) { f.status='pending'; f.note=''; }
  renderResults(); renderDetail(); metrics(); announce('clearDone');
};
$('copy').onclick = async () => {
  if (!selected) return;
  const text = signalText(selected,language);
  try { await navigator.clipboard.writeText(text); announce('copied'); }
  catch { $('copy-fallback').value = text; $('copy-dialog').showModal(); $('copy-fallback').select(); }
};
$('close-dialog').onclick = () => $('copy-dialog').close();
document.querySelectorAll('[data-format]').forEach(button => button.onclick = () => {
  if (!result) { announce('reportUnavailable'); return; }
  const output = exportReport(result,language,button.dataset.format);
  const url = URL.createObjectURL(new Blob([output.text],{type:output.type + ';charset=utf-8'}));
  const link = element('a'); link.href = url; link.download = 'xss-review-' + new Date().toISOString().replace(/[:.]/g,'-') + '.' + output.extension; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url),1000);
});
choose(0); localize();
