import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const base = path.resolve(fileURLToPath(new URL('../dist/', import.meta.url)));
const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.txt': 'text/plain' };
const server = http.createServer(async (req, res) => {
  let file;
  try {
    const name = new URL(req.url, 'http://localhost').pathname;
    file = path.resolve(base, '.' + decodeURIComponent(name === '/' ? '/index.html' : name));
  } catch { res.writeHead(400).end('Bad request'); return; }
  if (!file.startsWith(base + path.sep) && file !== path.join(base, 'index.html')) { res.writeHead(403).end(); return; }
  try {
    const data = await readFile(file);
    res.writeHead(200, { 'Content-Type': `${types[path.extname(file)] || 'application/octet-stream'}; charset=utf-8`, 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' }); res.end(data);
  } catch { res.writeHead(404).end('Not found'); }
});
server.listen(4178, '127.0.0.1', () => console.log('Local: http://127.0.0.1:4178'));
