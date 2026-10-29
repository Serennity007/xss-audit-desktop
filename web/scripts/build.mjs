import { build } from 'esbuild';
import { mkdir, copyFile, readFile, writeFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { VERSION } from '../src/version.js';
process.chdir(fileURLToPath(new URL('..', import.meta.url)));
await mkdir('dist', { recursive: true });
await build({ entryPoints: ['src/app.js', 'src/worker.js'], bundle: true, outdir: 'dist', format: 'esm', platform: 'browser', target: ['es2022'], minify: true, legalComments: 'eof' });
const pkg = JSON.parse(await readFile('package.json','utf8'));
if (pkg.version !== VERSION) throw Error('Package and engine versions differ');
const html = (await readFile('index.html','utf8')).replace('href="style.css"', 'href="style.css?v=' + VERSION + '"').replace('src="app.js"', 'src="app.js?v=' + VERSION + '"');
await writeFile('dist/index.html',html);
await copyFile('style.css','dist/style.css');
await copyFile('../LICENSE', 'dist/LICENSE.txt');
await copyFile('../NOTICE.md', 'dist/NOTICE.txt');
const notices = [];
for (const base of [...(await readdir('node_modules/@babel')).map(dir=>'node_modules/@babel/' + dir), 'node_modules/parse5', 'node_modules/entities', 'node_modules/fflate']) {
  const pkg = JSON.parse(await readFile(base + '/package.json', 'utf8'));
  const license = (await readdir(base)).find(name=>/^LICENSE(?:\.txt)?$/i.test(name));
  if (!license) throw Error('Missing license for ' + pkg.name);
  notices.push(pkg.name + ' ' + pkg.version + ' (' + pkg.license + ')\n' + await readFile(base + '/' + license, 'utf8'));
}
await writeFile('dist/THIRD-PARTY-NOTICES.txt', notices.join('\n\n---\n\n'));
console.log('Built web/dist: browser-local static application.');
