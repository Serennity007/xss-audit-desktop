// Publish only the built static website; never stage the source checkout or use a force push.
import { readFile, readdir, unlink } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID, createHash } from 'node:crypto';
import { VERSION } from '../src/version.js';

const repo = 'Serennity007/xss-audit-desktop';
const root = fileURLToPath(new URL('../..',import.meta.url));
const expected = ['LICENSE.txt','NOTICE.txt','THIRD-PARTY-NOTICES.txt','app.js','index.html','style.css','worker.js'];
const git = (args, options={}) => execFileSync('git',args,{cwd:root,encoding:'utf8',...options}).trim();
const api = (endpoint, method='GET', payload) => JSON.parse(execFileSync('gh',['api',`repos/${repo}/${endpoint}`,...(method==='GET' ? [] : ['--method',method]),...(payload ? ['--input','-'] : [])],{cwd:root,encoding:'utf8',input:payload ? JSON.stringify(payload) : undefined}));
const actual = (await readdir(resolve(root,'web/dist'))).sort();
if (JSON.stringify(actual)!==JSON.stringify([...expected].sort())) throw Error('Build must contain exactly the seven expected static files. Run npm run build first.');
if (!/github\.com[/:]Serennity007\/xss-audit-desktop(?:\.git)?$/i.test(git(['remote','get-url','origin']))) throw Error('Unexpected origin; refusing to publish to another repository.');
const contents = new Map();
for (const name of expected) contents.set(name,await readFile(resolve(root,'web/dist',name)));
if (!contents.get('index.html').toString().includes(`app.js?v=${VERSION}`)) throw Error('Rebuild assets for the current version first.');
const manifest = {web_version:VERSION,source_commit:git(['log','-1','--format=%H','--','web/src','web/index.html','web/style.css','web/scripts/build.mjs']),files:Object.fromEntries([...contents].map(([name,data])=>[name,createHash('sha256').update(data).digest('hex')]))};
contents.set('.nojekyll',Buffer.from(''));
contents.set('deployment.json',Buffer.from(JSON.stringify(manifest,null,2)+'\n'));
if (!process.argv.includes('--publish')) {
  console.log(JSON.stringify({action:'preview',repository:repo,branch:'gh-pages',files:[...contents.keys()],manifest},null,2));
  console.log('Use --publish to push the built site and configure GitHub Pages.');
  process.exit(0);
}
const index = join(tmpdir(),`xss-pages-${randomUUID()}.index`), env={...process.env,GIT_INDEX_FILE:index};
let commit;
try {
  const remote = git(['ls-remote','--heads','origin','gh-pages']);
  let parent;
  if (remote) { git(['fetch','origin','gh-pages']); parent=git(['rev-parse','FETCH_HEAD']); }
  git(['read-tree','--empty'],{env});
  for (const [name,data] of contents) {
    const blob=git(['hash-object','-w','--stdin'],{input:data});
    git(['update-index','--add','--cacheinfo',`100644,${blob},${name}`],{env});
  }
  const tree=git(['write-tree'],{env});
  commit=git(['commit-tree',tree,...(parent ? ['-p',parent] : [])],{input:`deploy: publish web ${VERSION}\n\nSource ${manifest.source_commit}\n`});
  git(['push','origin',`${commit}:refs/heads/gh-pages`]);
} finally {
  for (const name of [index,index+'.lock']) await unlink(name).catch(error=>{if(error.code!=='ENOENT') throw error;});
}
let site;
try { site=api('pages'); }
catch(error) {
  if (!String(error.stderr).includes('404')) throw error;
  site=api('pages','POST',{build_type:'legacy',source:{branch:'gh-pages',path:'/'}});
}
if (site.source?.branch!=='gh-pages' || site.source?.path!=='/') throw Error('Pages uses a different source; publication branch was pushed but existing source settings were preserved.');
console.log(JSON.stringify({url:site.html_url,status:site.status,commit,version:VERSION},null,2));
