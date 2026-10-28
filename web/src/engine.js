import { parse } from '@babel/parser';

export const LIMITS = { files: 100, fileBytes: 262144, totalBytes: 5242880, findings: 2000, nodes: 40000, depth: 80 };
export const ENGINE = 'web-ast/0.1.0';
const sourcePattern = /^(?:(?:window|document)\.)?location\.(?:hash|search|href)$|^document\.(?:cookie|referrer)$|^(?:req|request)\.(?:query|params|body)(?:\.|\[|$)|^(?:e|ev|event)\.data(?:\.|\[|$)|\.target\.value$/;
const supported = /\.(js|jsx|ts|tsx|mjs|cjs)$/i;
const patterns = [
  ['HTML-PATTERN', 'html', /\b(?:innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML|document\.write)\b/g],
  ['URL-PATTERN', 'url', /\b(?:window\.open|location\.(?:assign|replace)|href|src|action)\b/g],
  ['CODE-PATTERN', 'code', /\b(?:eval|Function|setTimeout|setInterval)\s*\(/g],
  ['SANITIZER-PATTERN', 'sanitizer', /\b(?:DOMPurify|sanitizeHtml|sanitize|ALLOW_DATA_ATTR|ALLOWED_TAGS)\b/g],
  ['MESSAGE-PATTERN', 'message', /\b(?:postMessage|BroadcastChannel|MessageChannel)\b/g]
];
const combine = (...groups) => [...new Map(groups.flat().map(f => [JSON.stringify(f), f])).values()].slice(0, 4);
const keys = node => Object.entries(node).filter(([key, value]) => !['loc', 'tokens', 'comments', 'extra', 'leadingComments', 'trailingComments', 'innerComments'].includes(key) && value && typeof value === 'object').flatMap(([, value]) => Array.isArray(value) ? value : [value]).filter(v => v?.type);
function names(node) {
  if (!node) return [];
  if (node.type === 'Identifier') return [node.name];
  if (node.type === 'ObjectProperty') return names(node.value);
  if (node.type === 'AssignmentPattern') return names(node.left);
  return keys(node).flatMap(names);
}

export function inspectFile(file) {
  const findings = [], notes = [], lines = file.content.split(/\r?\n/);
  const text = node => node ? file.content.slice(node.start, node.end) : '';
  const name = node => text(node).replace(/\s/g, '');
  let visited = 0;
  const seen = new Set();
  function emit(flows, node, category, sink) {
    for (const flow of flows) {
      const key = [node.start, category, flow.line, flow.source].join(':');
      if (seen.has(key)) continue;
      if (findings.length >= 1000) throw Error('findingBudget');
      seen.add(key);
      findings.push({ path: file.path, line: node.loc.start.line, column: node.loc.start.column + 1, rule: 'JS-' + category.toUpperCase() + '-FLOW', category, priority: category === 'html' && flow.sanitized ? 'medium' : 'high', mode: 'ast', source: { line: flow.line, text: flow.source }, steps: flow.steps, sink: { line: node.loc.start.line, text: sink }, sanitized: Boolean(flow.sanitized), context: lines.slice(Math.max(0, node.loc.start.line - 4), node.loc.start.line + 3).join('\n') });
    }
  }
  function walk(node, env, depth = 0) {
    if (!node) return [];
    if (++visited > LIMITS.nodes || depth > LIMITS.depth) throw Error('analysisBudget');
    const type = node.type, line = node.loc?.start.line || 1;
    if (/Literal$/.test(type) || type === 'JSXText' || type.startsWith('Comment')) return [];
    if (type === 'Identifier') return env.get(node.name) || [];
    if (['MemberExpression', 'OptionalMemberExpression'].includes(type) && sourcePattern.test(name(node))) return [{ source: text(node).slice(0, 120), line, steps: [] }];
    if (['TSAsExpression', 'TSTypeAssertion', 'TSNonNullExpression', 'TSSatisfiesExpression', 'ParenthesizedExpression'].includes(type)) return walk(node.expression, env, depth + 1);
    if (type.startsWith('TS')) return [];
    if (['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod', 'ClassMethod'].includes(type)) {
      const local = new Map(env);
      for (const param of node.params || []) for (const key of names(param)) local.set(key, []);
      if (node.id) local.set(node.id.name, []);
      walk(node.body, local, depth + 1); return [];
    }
    if (type === 'BlockStatement') {
      const local = new Map(env), declared = new Set();
      for (const stmt of node.body) {
        if (stmt.type === 'VariableDeclaration') for (const decl of stmt.declarations) for (const key of names(decl.id)) declared.add(key);
        if (stmt.type === 'FunctionDeclaration' && stmt.id) declared.add(stmt.id.name);
      }
      // Hoisted/shadowed names must not inherit outside taint.
      for (const key of declared) local.set(key, []);
      for (const stmt of node.body) walk(stmt, local, depth + 1);
      for (const key of env.keys()) if (!declared.has(key)) env.set(key, local.get(key) || []);
      return [];
    }
    if (type === 'IfStatement' || type === 'ConditionalExpression') {
      walk(node.test, env, depth + 1);
      const left = new Map(env), right = new Map(env);
      const a = walk(node.consequent, left, depth + 1), b = walk(node.alternate, right, depth + 1);
      for (const key of new Set([...left.keys(), ...right.keys()])) env.set(key, combine(left.get(key) || [], right.get(key) || []));
      return combine(a, b);
    }
    if (/^(?:For|While|DoWhile|Switch|Try)/.test(type)) {
      const before = new Map(env);
      for (const child of keys(node)) walk(child, env, depth + 1);
      for (const [key, value] of before) env.set(key, combine(value, env.get(key) || []));
      return [];
    }
    if (type === 'VariableDeclarator') {
      const flows = walk(node.init, env, depth + 1);
      if (node.id.type === 'Identifier') env.set(node.id.name, flows.map(f => ({ ...f, steps: [...f.steps.slice(-4), { line, text: node.id.name }] })));
      else { for (const key of names(node.id)) env.set(key, flows); notes.push({ path: file.path, code: 'destructuring' }); }
      return flows;
    }
    if (type === 'AssignmentExpression') {
      let flows = walk(node.right, env, depth + 1);
      if (node.operator !== '=') flows = combine(walk(node.left, env, depth + 1), flows);
      const target = name(node.left);
      if (node.left.type === 'Identifier') env.set(node.left.name, flows.map(f => ({ ...f, steps: [...f.steps.slice(-4), { line, text: node.left.name }] })));
      else if (/\.(?:innerHTML|outerHTML)$|\[['"](?:innerHTML|outerHTML)['"]\]$/.test(target)) emit(flows, node, 'html', text(node.left));
      else if (/(?:^|\.)location(?:\.href)?$|\.(?:href|src|action)$/.test(target)) emit(flows, node, 'url', text(node.left));
      return flows;
    }
    if (['CallExpression', 'OptionalCallExpression', 'NewExpression'].includes(type)) {
      const callee = name(node.callee), values = (node.arguments || []).map(arg => walk(arg, env, depth + 1));
      const receiver = node.callee?.object ? walk(node.callee.object, env, depth + 1) : [];
      const all = combine(receiver, ...values);
      if (/^(?:window\.)?(?:localStorage|sessionStorage)\.(?:getItem|key)$/.test(callee)) return [{ source: callee, line, steps: [] }];
      if (['DOMPurify.sanitize', 'sanitizeHtml'].includes(callee)) return all.map(f => ({ ...f, sanitized: true }));
      if (['eval', 'window.eval', 'Function'].includes(callee)) emit(all, node, 'code', callee);
      else if (['setTimeout', 'setInterval'].includes(callee)) emit(values[0] || [], node, 'code', callee);
      else if (['window.open', 'location.assign', 'location.replace', 'window.location.assign', 'window.location.replace'].includes(callee)) emit(values[0] || [], node, 'url', callee);
      else if (['document.write', 'document.writeln'].includes(callee) || /\.(?:insertAdjacentHTML|setHTMLUnsafe)$/.test(callee)) emit(callee.endsWith('.insertAdjacentHTML') ? values[1] || [] : all, node, 'html', callee);
      return all;
    }
    if (type === 'JSXAttribute' && node.name?.name === 'dangerouslySetInnerHTML') {
      const flows = walk(node.value, env, depth + 1); emit(flows, node, 'html', 'dangerouslySetInnerHTML'); return flows;
    }
    if (type === 'ObjectProperty') return walk(node.value, env, depth + 1);
    return combine(...keys(node).map(child => walk(child, env, depth + 1)));
  }
  if (!supported.test(file.path)) return { findings: [], notes: [{ path: file.path, code: 'unsupported' }], analyzed: false };
  try {
    const plugins = [];
    if (/\.tsx?$/i.test(file.path)) plugins.push('typescript');
    if (/\.[jt]sx$/i.test(file.path)) plugins.push('jsx');
    const ast = parse(file.content, { sourceType: 'unambiguous', plugins, errorRecovery: false });
    walk(ast.program, new Map());
  } catch (error) {
    notes.push({ path: file.path, code: ['analysisBudget', 'findingBudget'].includes(error.message) ? error.message : 'parse', line: error.loc?.line || null });
  }
  for (const [rule, category, regex] of patterns) {
    regex.lastIndex = 0;
    for (const match of file.content.matchAll(regex)) {
      const line = file.content.slice(0, match.index).split('\n').length;
      if (findings.some(f => f.line === line && f.category === category)) continue;
      findings.push({ path: file.path, line, column: match.index - file.content.lastIndexOf('\n', match.index - 1), rule, category, priority: 'info', mode: 'pattern', context: lines.slice(Math.max(0, line - 4), line + 3).join('\n') });
      if (findings.length >= 1000) { notes.push({ path: file.path, code: 'findingBudget' }); break; }
    }
    if (findings.length >= 1000) break;
  }
  return { findings, notes: [...new Map(notes.map(n => [n.code, n])).values()], analyzed: true };
}

export function validateFiles(files) {
  if (!Array.isArray(files) || files.length > LIMITS.files) throw Error('fileCount');
  let bytes = 0;
  const paths = new Set();
  for (const file of files) {
    if (!file || typeof file.path !== 'string' || typeof file.content !== 'string' || !file.path.trim() || paths.has(file.path)) throw Error('invalidFile');
    paths.add(file.path);
    const size = new TextEncoder().encode(file.content).length;
    if (size > LIMITS.fileBytes) throw Error('fileSize');
    if (file.content.includes('\0')) throw Error('binary');
    bytes += size;
  }
  if (bytes > LIMITS.totalBytes) throw Error('totalSize');
}

export async function analyzeProject(files) {
  validateFiles(files);
  const result = { engine: ENGINE, created_at: new Date().toISOString(), files: [], findings: [], notes: [], incomplete: false };
  for (const file of files) {
    const scanned = inspectFile(file);
    const identityCounts = new Map();
    const sourceDigest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(file.content));
    const sourceHash = [...new Uint8Array(sourceDigest)].map(n => n.toString(16).padStart(2, '0')).join('');
    result.files.push({ path: file.path, analyzed: scanned.analyzed });
    result.notes.push(...scanned.notes);
    for (const finding of scanned.findings) {
      const key = [ENGINE, finding.path, finding.rule, sourceHash, finding.line, finding.column].join('\0');
      const occurrence = identityCounts.get(key) || 0;
      identityCounts.set(key, occurrence + 1);
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key + '\0' + occurrence));
      finding.id = [...new Uint8Array(digest)].map(n => n.toString(16).padStart(2, '0')).join('');
      finding.status = 'pending'; finding.note = '';
      result.findings.push(finding);
      if (result.findings.length >= LIMITS.findings) { result.notes.push({ path: file.path, code: 'projectBudget' }); result.incomplete = true; break; }
    }
    if (result.incomplete) break;
  }
  result.incomplete ||= result.notes.length > 0;
  return result;
}
