import { build } from 'esbuild';
import { mkdir, copyFile, readFile, writeFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
process.chdir(fileURLToPath(new URL('..', import.meta.url)));
await mkdir('dist', { recursive: true });
await build({ entryPoints: ['src/app.js', 'src/worker.js'], bundle: true, outdir: 'dist', format: 'esm', platform: 'browser', target: ['es2022'], minify: true, legalComments: 'eof' });
await Promise.all(['index.html', 'style.css'].map(p => copyFile(p, `dist/${p}`)));
await copyFile('../LICENSE', 'dist/LICENSE.txt');
await copyFile('../NOTICE.md', 'dist/NOTICE.txt');
const notices = [];
for (const dir of await readdir('node_modules/@babel')) {
  const base = 'node_modules/@babel/' + dir;
  const pkg = JSON.parse(await readFile(base + '/package.json', 'utf8'));
  notices.push(pkg.name + ' ' + pkg.version + ' (' + pkg.license + ')\n' + await readFile(base + '/LICENSE', 'utf8'));
}
await writeFile('dist/THIRD-PARTY-NOTICES.txt', notices.join('\n\n---\n\n'));
console.log('Built web/dist: browser-local static application.');
