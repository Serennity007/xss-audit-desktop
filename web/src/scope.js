export const SOURCE_EXTENSIONS = /\.(?:[cm]?js|jsx|tsx?|vue|svelte|html?)$/i;
export const DEFAULT_SCOPE = Object.freeze({ include: ['**/*'], exclude: ['**/node_modules/**', '**/vendor/**', '**/.git/**', '**/dist/**', '**/build/**', '**/coverage/**', '**/.next/**', '**/.nuxt/**', '**/*.min.js'] });

export function normalizePath(value) {
  if (typeof value !== 'string' || value.length > 1024 || /[\x00-\x1f\x7f]/.test(value)) throw Error('invalidFile');
  const path = value.replaceAll('\\', '/');
  if (!path.trim() || path.startsWith('/') || /^[a-z]:/i.test(path) || path.split('/').some(p => !p || p === '.' || p === '..')) throw Error('invalidFile');
  return path;
}

export function validateScope(input = DEFAULT_SCOPE) {
  const result = {};
  for (const key of ['include', 'exclude']) {
    const list = input?.[key];
    if (!Array.isArray(list) || list.length > 24 || (key === 'include' && !list.length)) throw Error('invalidScope');
    result[key] = [...new Set(list.map(pattern => {
      if (typeof pattern !== 'string' || !pattern || pattern.length > 200 || /[\x00-\x20\\!\[\]{}]/.test(pattern) || pattern.startsWith('/') || pattern.split('/').some(p => !p || p === '.' || p === '..' || (p.includes('**') && p !== '**'))) throw Error('invalidScope');
      return pattern;
    }))];
  }
  return result;
}

// Bounded wildcard matching, without regex backtracking. ** matches whole path segments.
export function globMatches(pattern, path) {
  const patterns = pattern.split('/'), parts = path.split('/'), memo = new Map();
  function segment(glob, part) {
    let row = new Array(part.length + 1).fill(false); row[0] = true;
    for (const c of glob) {
      const next = new Array(part.length + 1).fill(false); next[0] = c === '*' && row[0];
      for (let i = 1; i <= part.length; i++) next[i] = c === '*' ? next[i - 1] || row[i] : row[i - 1] && (c === '?' || c === part[i - 1]);
      row = next;
    }
    return row[part.length];
  }
  function match(i, j) {
    const key = i + ':' + j;
    if (memo.has(key)) return memo.get(key);
    const value = i === patterns.length ? j === parts.length : patterns[i] === '**' ? match(i + 1, j) || (j < parts.length && match(i, j + 1)) : j < parts.length && segment(patterns[i], parts[j]) && match(i + 1, j + 1);
    memo.set(key, value); return value;
  }
  return match(0, 0);
}

export function scopeReason(path, scope) {
  if (!SOURCE_EXTENSIONS.test(path)) return 'unsupported';
  if (scope.exclude.some(p => globMatches(p, path))) return 'excluded';
  if (!scope.include.some(p => globMatches(p, path))) return 'notIncluded';
  return null;
}
