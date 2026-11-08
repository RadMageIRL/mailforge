// Checks every outside link the project publishes: the links in index.html and README.md and the
// RFC references the checks cite. Each address must answer 200 (after redirects), and an address
// with a #fragment must point at an id that exists on that page. Uses the network, so it is run by
// hand before a release rather than in CI.
//
//   node tools/check-links.mjs [--skip <prefix>]
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const MF = createRequire(import.meta.url)('../mailforge-core.js');
const read = (f) => readFileSync(join(ROOT, f), 'utf8');
const skipAt = process.argv.indexOf('--skip');
const SKIP = skipAt > 0 ? process.argv[skipAt + 1] : null;

const urls = new Set();
for (const m of read('index.html').matchAll(/href="(https:[^"]+)"/g)) urls.add(m[1].replace(/&amp;/g, '&'));
for (const m of read('README.md').matchAll(/\]\((https:[^)\s]+)\)/g)) urls.add(m[1]);
for (const m of read('mailforge-core.js').matchAll(/ref\('(\w+)', '([\w.]+)'\)/g)) urls.add(`${MF.RFC[m[1]]}#${/^[A-Z]/.test(m[2]) ? 'appendix' : 'section'}-${m[2]}`);
for (const u of Object.values(MF.RFC)) urls.add(u);

const pages = new Map();
async function get(url) {
  if (!pages.has(url)) {
    pages.set(url, (async () => {
      const res = await fetch(url, { redirect: 'follow', headers: { 'User-Agent': 'mailforge-link-check' }, signal: AbortSignal.timeout(20000) });
      return { status: res.status, body: res.ok ? await res.text() : '' };
    })());
  }
  return pages.get(url);
}

let bad = 0;
for (const url of [...urls].sort()) {
  if (SKIP && url.startsWith(SKIP)) { console.log(`skip ${url}`); continue; }
  const [base, frag] = url.split('#');
  try {
    const { status, body } = await get(base);
    let note = '';
    if (status === 200 && frag && !new RegExp(`id="${frag.replace(/[.]/g, '\\.')}"`).test(body)) { note = ` (no id="${frag}")`; }
    const ok = status === 200 && !note;
    if (!ok) bad++;
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${status} ${url}${note}`);
  } catch (e) {
    bad++;
    console.log(`FAIL ${url} (${e.message})`);
  }
}
console.log(`${urls.size} links, ${bad} broken`);
process.exit(bad ? 1 : 0);
