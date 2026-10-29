import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const result=spawnSync(process.execPath,['--test','tests/app.test.mjs'],{
  cwd:fileURLToPath(new URL('..',import.meta.url)),stdio:'inherit',env:{...process.env,XSS_WEB_TEST_BUILT:'1'}
});
if (result.error) throw result.error;
process.exit(result.status ?? 1);
