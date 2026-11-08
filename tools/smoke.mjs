// Browser tests on the production build (dist/, from node tools/build.mjs), in headless Chrome over the
// DevTools protocol with no dependencies. DNS-over-HTTPS answers come from fixtures through request
// interception, so no test reaches Cloudflare or Google.
//
//   node tools/smoke.mjs [--dir dist] [--only <part of a check name>]
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';
import { launchChrome } from './lib/cdp.mjs';
import { serve } from './serve.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const opt = (name, d) => { const i = argv.indexOf(`--${name}`); return i >= 0 ? argv[i + 1] : d; };
const DIR = resolve(ROOT, opt('dir', 'dist'));
const ONLY = opt('only', '');
if (!existsSync(join(DIR, 'index.html'))) { console.error(`No site in ${DIR}: run node tools/build.mjs first.`); process.exit(1); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const KEY = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey;
const KEY_B64 = KEY.export({ type: 'spki', format: 'der' }).toString('base64');
const KEY_PEM = KEY.export({ type: 'spki', format: 'pem' });
const PRIVATE_PEM = generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey.export({ type: 'pkcs8', format: 'pem' });

// What the mocked resolvers answer. Names are lower case; CNAME answers are followed like a resolver.
const XSS = '"><img src=x data-xss=1><b data-xss=1>';
const ZONE = {
  'example.com': { TXT: ['v=spf1 include:_spf.example.net mx -all', 'site-verification=abc123'], MX: ['10 mx1.example.com.'] },
  '_spf.example.net': { TXT: ['v=spf1 ip4:192.0.2.0/24 include:more.example.net ~all'] },
  'more.example.net': { TXT: ['v=spf1 ip6:2001:db8::/32 ~all'] },
  '_dmarc.example.com': { TXT: ['v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com,mailto:agg@reports.example.net'] },
  'example.com._report._dmarc.reports.example.net': { TXT: ['v=DMARC1'] },
  'selector1._domainkey.example.com': { TXT: [`v=DKIM1; k=rsa; p=${KEY_B64}`] },
  'selector2._domainkey.example.com': { CNAME: 'selector2-example-com._domainkey.keys.example.net' },
  'selector2-example-com._domainkey.keys.example.net': { TXT: [`v=DKIM1; k=rsa; p=${KEY_B64}`] },
  // Answers written to break a page that trusts DNS data.
  'hostile.example': { TXT: [`v=spf1 include:${XSS}.example a:${XSS} -all`], MX: [`10 ${XSS}.example.`] },
  '_dmarc.hostile.example': { TXT: [`v=DMARC1; p=none; rua=mailto:${XSS}@example.com; ${XSS}=1`] },
  'selector1._domainkey.hostile.example': { TXT: [`v=DKIM1; k=rsa; p=${XSS}`] },
};
const TYPES = { TXT: 16, MX: 15, A: 1, AAAA: 28, CNAME: 5 };
const quoted = (v) => (v.match(/[\s\S]{1,255}/g) || ['']).map((s) => `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`).join(' ');
function answer(name, type) {
  const answers = [];
  let n = name.toLowerCase().replace(/\.$/, '');
  for (let depth = 0; depth < 5 && ZONE[n] && ZONE[n].CNAME; depth++) {
    answers.push({ name: `${n}.`, type: TYPES.CNAME, TTL: 300, data: `${ZONE[n].CNAME}.` });
    n = ZONE[n].CNAME;
  }
  if (!(n in ZONE)) return { Status: 3, Answer: answers.length ? answers : undefined };
  for (const d of ZONE[n][type] || []) answers.push({ name: `${n}.`, type: TYPES[type], TTL: 300, data: type === 'TXT' ? quoted(d) : d });
  return { Status: 0, AD: false, Answer: answers };
}

const { server, port } = await serve(DIR, 0);
const BASE = `http://127.0.0.1:${port}/`;
const chrome = await launchChrome();
await chrome.grant(BASE.slice(0, -1), ['clipboardReadWrite', 'clipboardSanitizedWrite']);

let passed = 0, failed = 0;
const checks = [];
const check = (name, fn) => checks.push({ name, fn });

/**
 * A fresh tab with storage cleared. doh: 'ok' answers from ZONE; 'cloudflare-down' fails Cloudflare
 * with HTTP 503 so the page falls back to Google; 'down' fails both.
 */
async function open({ url = BASE, width = 1280, height = 900, mobile = false, doh = 'ok', keepStorage = false, media = null } = {}) {
  const page = await chrome.newPage();
  page.doh = [];
  if (!keepStorage && url.startsWith('http')) await page.send('Storage.clearDataForOrigin', { origin: new URL(url).origin, storageTypes: 'all' });
  await page.viewport(width, height, mobile);
  if (media) await page.emulateMedia(media);
  await page.beforeLoad("window.__csp = []; document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(`${e.violatedDirective} ${e.blockedURI}`));");
  await page.send('Fetch.enable', { patterns: [{ urlPattern: 'https://cloudflare-dns.com/*' }, { urlPattern: 'https://dns.google/*' }] });
  page.on('Fetch.requestPaused', async (p) => {
    const u = new URL(p.request.url);
    page.doh.push({ url: p.request.url, method: p.request.method, headers: p.request.headers, body: p.request.postData });
    const down = doh === 'down' || (doh === 'cloudflare-down' && u.hostname === 'cloudflare-dns.com');
    const body = down ? 'unavailable' : JSON.stringify(answer(u.searchParams.get('name'), u.searchParams.get('type')));
    await page.send('Fetch.fulfillRequest', {
      requestId: p.requestId, responseCode: down ? 503 : 200,
      responseHeaders: [{ name: 'Content-Type', value: 'application/dns-json' }, { name: 'Access-Control-Allow-Origin', value: '*' }],
      body: Buffer.from(body).toString('base64'),
    }).catch(() => {});
  });
  await page.goto(url);
  await page.waitFor("window.MailForge && document.getElementById('spf-record').textContent.startsWith('v=spf1')");
  return page;
}
const js = (v) => JSON.stringify(v);
const setValue = (page, sel, value) => page.eval(`(() => { const el = document.querySelector(${js(sel)}); el.value = ${js(value)}; el.dispatchEvent(new Event('input', { bubbles: true })); el.dispatchEvent(new Event('change', { bubbles: true })); })()`);
const click = (page, sel) => page.eval(`(() => { const el = document.querySelector(${js(sel)}); if (!el) throw new Error('no ' + ${js(sel)}); el.click(); })()`);
const text = (page, sel) => page.eval(`(document.querySelector(${js(sel)}) || {}).textContent || ''`);
const key = async (page, k, code, vk, modifiers = 0) => {
  await page.send('Input.dispatchKeyEvent', { type: 'keyDown', key: k, code, windowsVirtualKeyCode: vk, modifiers });
  await page.send('Input.dispatchKeyEvent', { type: 'keyUp', key: k, code, windowsVirtualKeyCode: vk, modifiers });
};
/** Problems the page reported: exceptions, console errors, failed loads and CSP violations. */
async function clean(page) {
  const csp = await page.eval('window.__csp');
  assert.deepEqual([...page.problems, ...csp.map((c) => `CSP: ${c}`)], []);
}

// ---- Loading ----

check('the page loads with no errors, shows v0.1.0 and makes no request beyond its own files', async (page) => {
  assert.equal(await page.eval('document.title'), 'MailForge v0.1.0 - SPF, DKIM & DMARC Builder and Validator | RadMage Labs');
  assert.equal(await text(page, '#core-version'), '0.1.0');
  assert.match(await text(page, '.tagline'), /^v0\.1\.0 · /);
  assert.equal(await text(page, '#spf-record'), 'v=spf1 mx ~all');
  assert.equal(await page.eval("document.querySelectorAll('[role=tab]').length"), 5);
  await sleep(300);
  const outside = page.requests.filter((u) => !u.startsWith(BASE) && !u.startsWith('data:'));
  assert.deepEqual(outside, [], 'no outside requests on load');
  assert.deepEqual(page.doh, [], 'no DNS lookups until asked');
  await clean(page);
});

check('opened straight from disk (file://), the page runs under its CSP', async () => {
  const page = await open({ url: pathToFileURL(join(DIR, 'index.html')).href });
  await click(page, '[data-preset="include:_spf.google.com"]');
  assert.equal(await text(page, '#spf-record'), 'v=spf1 mx include:_spf.google.com ~all');
  await clean(page);
  await page.close();
});

// ---- SPF ----

check('SPF: presets and pasted values go in before all, auto-detected as ip4, ip6 or include', async (page) => {
  await click(page, '[data-preset="include:spf.protection.outlook.com"]');
  await setValue(page, '#spf-add-value', '192.0.2.10, 2001:db8::/48 _spf.example.net');
  await click(page, '#spf-add');
  assert.equal(await text(page, '#spf-record'), 'v=spf1 mx include:spf.protection.outlook.com ip4:192.0.2.10 ip6:2001:db8::/48 include:_spf.example.net ~all');
  assert.match(await text(page, '#spf-stats'), /direct lookups 3\/10/);
  assert.match(await text(page, '#spf-output'), /1 TXT record at example\.com/);
  await click(page, '#spf-reset-none');
  assert.equal(await text(page, '#spf-record'), 'v=spf1 -all');
  await clean(page);
});

check('SPF: two pasted records are an error and the merged proposal loads into the builder', async (page) => {
  await setValue(page, '#spf-import', 'v=spf1 include:a.example.com -all\nv=spf1 ip4:192.0.2.1 include:a.example.com ~all');
  await click(page, '[data-import="spf"]');
  assert.match(await text(page, '#spf-import-result .finding.error'), /2 SPF records/);
  await click(page, '#spf-import-result [data-apply="spf"]');
  assert.equal(await text(page, '#spf-record'), 'v=spf1 include:a.example.com ip4:192.0.2.1 -all');
  await clean(page);
});

check('SPF: moving and removing terms changes the order the record is evaluated in', async (page) => {
  await page.eval("document.querySelector('#spf-terms [data-row=\"1\"] [data-move=\"-1\"]').click()");
  assert.equal(await text(page, '#spf-record'), 'v=spf1 ~all mx');
  assert.match(await text(page, '#spf-findings'), /never evaluated/);
  await page.eval("document.querySelector('#spf-terms [data-row=\"1\"] [data-remove]').click()");
  assert.equal(await text(page, '#spf-record'), 'v=spf1 ~all');
  await clean(page);
});

check('SPF: a broken record is never loaded as-is, only through the labeled repair', async (page) => {
  await setValue(page, '#spf-import', 'v=spf1 ip4:192.0.2.0/25 ip4:192.0.2.128/25 +all');
  await click(page, '[data-import="spf"]');
  const result = await text(page, '#spf-import-result');
  assert.match(result, /lets any server pass/);
  assert.match(result, /merge/);
  await click(page, '#spf-import-result [data-apply="spf"]');
  assert.equal(await text(page, '#spf-record'), 'v=spf1 ip4:192.0.2.0/24 +all', 'the repair merges ranges and never changes the policy');
  await clean(page);
});

// ---- DKIM ----

check('DKIM: a PEM public key becomes one record of two strings, and a private key is refused', async (page) => {
  await click(page, '#tab-dkim');
  await setValue(page, '#dkim-selector', 'selector1');
  await setValue(page, '#dkim-import', KEY_PEM);
  await click(page, '[data-import="dkim"]');
  assert.match(await text(page, '#dkim-import-result'), /Built a record from the public key/);
  await click(page, '#dkim-import-result [data-load="dkim"]');
  assert.equal(await text(page, '#dkim-record'), `v=DKIM1; k=rsa; p=${KEY_B64}`);
  assert.match(await text(page, '#dkim-stats'), /RSA 2048-bit/);
  assert.match(await text(page, '#dkim-output'), /1 TXT record at selector1\._domainkey\.example\.com · \d+ bytes · 2 strings, all in this one record/);
  await setValue(page, '#dkim-import', PRIVATE_PEM);
  await click(page, '[data-import="dkim"]');
  assert.match(await text(page, '#dkim-import-result'), /This is a PRIVATE key/);
  await setValue(page, '#dkim-p', PRIVATE_PEM);
  assert.match(await text(page, '#dkim-findings'), /This is a PRIVATE key/);
  assert.match(await text(page, '#dkim-output'), /No output for a private key/);
  await sleep(400);
  const stored = await page.eval("localStorage.getItem('mailforge_state') || ''");
  assert.ok(stored.includes('selector1'), 'the rest of the work is saved');
  assert.doesNotMatch(stored, /PRIVATE ?KEY|MII[A-Za-z0-9+/]{40}/, 'the private key is never stored');
  await clean(page);
});

// ---- DMARC ----

check('DMARC: the form builds the record and explains it; RFC 9989 tags are recognized on import', async (page) => {
  await click(page, '#tab-dmarc');
  await click(page, 'input[name="dmarc-p"][value="reject"]');
  await setValue(page, '#dmarc-rua', 'dmarc@example.com');
  await setValue(page, '#dmarc-adkim', 's');
  assert.equal(await text(page, '#dmarc-record'), 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s');
  assert.match(await text(page, '#dmarc-explain'), /p=reject: mail that fails DMARC should be refused/);
  await setValue(page, '#dmarc-import', 'v=DMARC1; p=quarantine; t=y; rua=mailto:d@example.com');
  await click(page, '[data-import="dmarc"]');
  const result = await text(page, '#dmarc-import-result');
  assert.match(result, /t=y: test mode/);
  assert.doesNotMatch(result, /Unknown tag/);
  await click(page, '#dmarc-import-result [data-load="dmarc"]');
  assert.equal(await text(page, '#dmarc-record'), 'v=DMARC1; p=quarantine; rua=mailto:d@example.com; t=y');
  await clean(page);
});

check('DMARC: a record receivers ignore today (v= not first) cannot be loaded as-is', async (page) => {
  await click(page, '#tab-dmarc');
  await setValue(page, '#dmarc-import', 'p=reject; v=DMARC1');
  await click(page, '[data-import="dmarc"]');
  assert.equal(await page.eval("document.querySelector('#dmarc-import-result [data-load]').disabled"), true);
  assert.match(await text(page, '#dmarc-import-result'), /fix.*Moved v=DMARC1 to the start/);
  await clean(page);
});

// ---- DNS output and copying ----

check('every output format renders, and Copy puts exactly the shown text on the clipboard', async (page) => {
  await page.send('Page.bringToFront');
  for (const fmt of ['zone', 'cloudflare', 'route53', 'route53Json', 'plain']) {
    await click(page, `#spf-output [data-format="${fmt}"]`);
    assert.equal(await page.eval(`document.querySelector('#spf-output [data-format="${fmt}"]').getAttribute('aria-pressed')`), 'true');
  }
  await click(page, '#spf-output [data-format="zone"]');
  await click(page, '#spf-output [data-copy]');
  await page.waitFor("document.getElementById('toast').classList.contains('visible')");
  assert.equal(await page.eval('navigator.clipboard.readText()'), 'example.com. 3600 IN TXT "v=spf1 mx ~all"');
  await click(page, '#spf-output [data-format="route53Json"]');
  await click(page, '#spf-output [data-copy]');
  const copied = JSON.parse(await page.eval('navigator.clipboard.readText()'));
  assert.equal(copied.Changes[0].ResourceRecordSet.ResourceRecords[0].Value, '"v=spf1 mx ~all"');
  await clean(page);
});

// ---- Inspect DNS ----

check('Inspect: follows the SPF tree, checks DMARC report authorization and DKIM keys, including a CNAME', async (page) => {
  await setValue(page, '#domain', 'example.com');
  await click(page, '#tab-inspect');
  await setValue(page, '#selectors', 'selector1, selector2, missing1');
  await click(page, '#inspect-run');
  await page.waitFor("document.querySelector('#inspect-results .tree') !== null");
  const out = await text(page, '#inspect-results');
  assert.match(out, /3\/10 lookups · 0\/2 void/);
  assert.match(out, /reports\.example\.net accepts your rua reports/);
  assert.match(out, /2 of 3 selectors found/);
  assert.match(out, /CNAME → selector2-example-com\._domainkey\.keys\.example\.net/);
  assert.match(out, /No key at: missing1/);
  assert.equal(await page.eval("[...document.querySelectorAll('#inspect-results .tag')].filter((t) => t.textContent === 'RSA 2048').length"), 2);
  assert.ok(page.doh.every((r) => r.url.startsWith('https://cloudflare-dns.com/')), 'Cloudflare answers, so Google is never asked');
  await clean(page);
});

check('DNS lookups send only the name and type: GET, no body, no referrer, never the records typed in', async (page) => {
  await setValue(page, '#spf-import', 'v=spf1 ip4:203.0.113.77 -all');
  await click(page, '[data-import="spf"]');
  await setValue(page, '#domain', 'example.com');
  await click(page, '[data-fetch="spf"]');
  await page.waitFor("document.getElementById('spf-import-result').textContent.includes('Fetched from')");
  await click(page, '#tab-inspect');
  await click(page, '#inspect-run');
  await page.waitFor("document.querySelector('#inspect-results .tree') !== null");
  assert.ok(page.doh.length > 5);
  for (const r of page.doh) {
    assert.equal(r.method, 'GET');
    assert.equal(r.body, undefined);
    assert.match(r.url, /^https:\/\/cloudflare-dns\.com\/dns-query\?name=[A-Za-z0-9._%-]+&type=(TXT|MX|A|AAAA)$/);
    assert.ok(!Object.keys(r.headers).some((h) => /^referer$/i.test(h)), `no Referer on ${r.url}`);
    assert.ok(!r.url.includes('203.0.113.77'));
  }
  assert.equal(await page.eval("document.getElementById('spf-import').value"), 'v=spf1 include:_spf.example.net mx -all');
  await clean(page);
});

check('when Cloudflare fails the lookups fall back to Google, and when both fail the page says so', async () => {
  const page = await open({ doh: 'cloudflare-down' });
  await setValue(page, '#domain', 'example.com');
  await click(page, '#tab-inspect');
  await click(page, '#inspect-run');
  await page.waitFor("document.querySelector('#inspect-results .tree') !== null");
  assert.match(await text(page, '#inspect-results'), /via Google/);
  await page.close();
  const down = await open({ doh: 'down' });
  await setValue(down, '#domain', 'example.com');
  await click(down, '#tab-inspect');
  await click(down, '#inspect-run');
  await down.waitFor("!document.getElementById('inspect-run').disabled && document.getElementById('inspect-results').textContent.includes('Lookup failed')");
  assert.match(await text(down, '#inspect-results'), /Cloudflare: HTTP 503; Google: HTTP 503/);
  assert.deepEqual(down.problems.filter((p) => !/\b503\b|failed:/.test(p)), [], 'no page errors beyond the refused lookups');
  await down.close();
});

check('Inspect refuses an invalid domain without looking anything up', async (page) => {
  await setValue(page, '#domain', 'not a domain');
  await click(page, '#tab-inspect');
  await click(page, '#inspect-run');
  assert.match(await text(page, '#inspect-results'), /The domain contains a space/);
  assert.deepEqual(page.doh, []);
});

// ---- Untrusted input ----

check('hostile DNS answers are shown as text, never as markup', async (page) => {
  await setValue(page, '#domain', 'hostile.example');
  await click(page, '#tab-inspect');
  await setValue(page, '#selectors', 'selector1');
  await click(page, '#inspect-run');
  await page.waitFor("document.querySelector('#inspect-results .tree') !== null");
  for (const kind of ['spf', 'dmarc']) {
    await click(page, `#tab-${kind}`);
    await click(page, `[data-fetch="${kind}"]`);
    await page.waitFor(`document.getElementById('${kind}-import-result').textContent.includes('Fetched from')`);
  }
  assert.equal(await page.eval("document.querySelectorAll('[data-xss], img').length"), 0);
  assert.ok((await text(page, '#tab-panels')).includes('data-xss=1'), 'the payload is displayed as text');
  await clean(page);
});

check('hostile typed input is shown as text, never as markup', async (page) => {
  await setValue(page, '#domain', XSS);
  await setValue(page, '#spf-add-value', XSS);
  await click(page, '#spf-add');
  await setValue(page, '#spf-import', `v=spf1 include:${XSS} -all`);
  await click(page, '[data-import="spf"]');
  await click(page, '#tab-dkim');
  await setValue(page, '#dkim-selector', XSS);
  await setValue(page, '#dkim-n', XSS);
  await setValue(page, '#dkim-p', XSS);
  await setValue(page, '#dkim-import', `v=DKIM1; ${XSS}=1; p=${XSS}`);
  await click(page, '[data-import="dkim"]');
  await click(page, '#tab-dmarc');
  await setValue(page, '#dmarc-rua', XSS);
  await setValue(page, '#dmarc-import', `v=DMARC1; p=none; rua=mailto:${XSS}`);
  await click(page, '[data-import="dmarc"]');
  for (const f of ['zone', 'cloudflare', 'route53', 'route53Json', 'plain']) await click(page, `#dmarc-output [data-format="${f}"]`);
  await click(page, '#tab-inspect');
  await setValue(page, '#selectors', XSS);
  await click(page, '#inspect-run');
  await sleep(300);
  assert.equal(await page.eval("document.querySelectorAll('[data-xss], img').length"), 0);
  await page.reload();
  await page.waitFor("window.MailForge && document.getElementById('spf-record').textContent.startsWith('v=spf1')");
  assert.equal(await page.eval("document.querySelectorAll('[data-xss], img').length"), 0, 'restored state is still text');
  await clean(page);
});

// ---- Navigation, themes, layout, accessibility ----

check('tabs: arrow keys, Home and End move between tabs; the address keeps the tab', async (page) => {
  await page.eval("document.getElementById('tab-spf').focus()");
  await key(page, 'ArrowRight', 'ArrowRight', 39);
  assert.equal(await page.eval('document.activeElement.id'), 'tab-dkim');
  assert.equal(await page.eval("document.getElementById('panel-dkim').hidden"), false);
  assert.equal(await page.eval('location.hash'), '#dkim');
  await key(page, 'End', 'End', 35);
  assert.equal(await page.eval('document.activeElement.id'), 'tab-help');
  await key(page, 'Home', 'Home', 36);
  assert.equal(await page.eval('document.activeElement.id'), 'tab-spf');
  await key(page, 'ArrowLeft', 'ArrowLeft', 37);
  assert.equal(await page.eval('document.activeElement.id'), 'tab-help');
  await clean(page);
});

check('a direct link to a tab opens it, and a reload keeps the work and the tab', async () => {
  const page = await open({ url: `${BASE}#dmarc` });
  assert.equal(await page.eval("document.getElementById('panel-dmarc').hidden"), false);
  await setValue(page, '#domain', 'example.org');
  await click(page, 'input[name="dmarc-p"][value="quarantine"]');
  await sleep(400);
  await page.reload();
  await page.waitFor("window.MailForge && document.getElementById('dmarc-record').textContent.includes('quarantine')");
  assert.equal(await page.eval("document.getElementById('domain').value"), 'example.org');
  assert.equal(await page.eval("document.getElementById('panel-dmarc').hidden"), false);
  await clean(page);
  await page.close();
});

check('Tab moves focus through the page and every stop shows a focus outline', async (page) => {
  const seen = [];
  for (let i = 0; i < 30; i++) {
    await key(page, 'Tab', 'Tab', 9);
    const s = await page.eval("(() => { const el = document.activeElement; const cs = getComputedStyle(el); return { id: [...document.querySelectorAll('*')].indexOf(el) + ' ' + el.tagName + ' ' + (el.id || el.textContent.trim().slice(0, 30)), visible: el.classList.contains('skip') || (cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) > 0) }; })()");
    seen.push(s);
  }
  assert.deepEqual(seen.filter((s) => !s.visible), []);
  assert.ok(new Set(seen.map((s) => s.id)).size > 20, 'focus moves');
});

check('themes: system follows the OS, the toggle cycles light, dark and system and is remembered', async () => {
  const page = await open({ media: [{ name: 'prefers-color-scheme', value: 'dark' }] });
  const bg = () => page.eval('getComputedStyle(document.body).backgroundColor');
  assert.equal(await bg(), 'rgb(16, 19, 17)');
  await click(page, '#theme-toggle');
  assert.equal(await page.eval('document.documentElement.dataset.theme'), 'light');
  assert.equal(await bg(), 'rgb(245, 244, 239)');
  await click(page, '#theme-toggle');
  assert.equal(await bg(), 'rgb(16, 19, 17)');
  await page.emulateMedia([{ name: 'prefers-color-scheme', value: 'light' }]);
  assert.equal(await bg(), 'rgb(16, 19, 17)', 'an explicit dark choice beats the OS');
  await click(page, '#theme-toggle');
  assert.equal(await page.eval("document.documentElement.hasAttribute('data-theme')"), false);
  assert.equal(await bg(), 'rgb(245, 244, 239)');
  await click(page, '#theme-toggle');
  await page.reload();
  await page.waitFor('window.MailForge');
  assert.equal(await page.eval('document.documentElement.dataset.theme'), 'light');
  await clean(page);
  await page.close();
});

check('text and severity colors meet WCAG AA contrast (4.5:1) in both themes', async (page) => {
  for (const theme of ['light', 'dark']) {
    await page.eval(`document.documentElement.setAttribute('data-theme', '${theme}')`);
    const bad = await page.eval(`(() => {
      const v = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
      const lum = (h) => { const c = [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16) / 255).map((x) => (x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4)); return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]; };
      const ratio = (a, b) => { const x = lum(v(a)), y = lum(v(b)); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
      const pairs = [];
      for (const fg of ['--text', '--muted', '--accent', '--bad', '--warn', '--good', '--info']) for (const bg of ['--bg', '--surface', '--surface-raised']) pairs.push([fg, bg]);
      pairs.push(['--accent-ink', '--accent'], ['--on-sev', '--bad'], ['--on-sev', '--warn'], ['--on-sev', '--good']);
      return pairs.map(([a, b]) => [a, b, ratio(a, b)]).filter((p) => p[2] < 4.5).map((p) => p[0] + ' on ' + p[1] + ' ' + p[2].toFixed(2));
    })()`);
    assert.deepEqual(bad, [], theme);
  }
});

check('every control has an accessible name; ids are unique; one h1; tabs point at their panels', async (page) => {
  await setValue(page, '#domain', 'example.com');
  for (const t of ['dkim', 'dmarc', 'inspect', 'help', 'spf']) await click(page, `#tab-${t}`);
  const issues = await page.eval(`(() => {
    const out = [];
    for (const el of document.querySelectorAll('input, select, textarea')) {
      const lab = (el.id && document.querySelector('label[for="' + el.id + '"]')) || el.closest('label');
      const name = el.getAttribute('aria-label') || (lab && lab.textContent.trim());
      if (!name) out.push('no label: ' + (el.id || el.name || el.outerHTML.slice(0, 60)));
    }
    for (const el of document.querySelectorAll('button, a[href]')) if (!(el.getAttribute('aria-label') || el.textContent).trim()) out.push('no name: ' + el.outerHTML.slice(0, 80));
    const ids = [...document.querySelectorAll('[id]')].map((e) => e.id);
    for (const id of ids) if (ids.indexOf(id) !== ids.lastIndexOf(id)) out.push('duplicate id ' + id);
    if (document.querySelectorAll('h1').length !== 1) out.push('h1 count');
    if (document.documentElement.lang !== 'en') out.push('lang');
    for (const t of document.querySelectorAll('[role=tab]')) {
      const panel = document.getElementById(t.getAttribute('aria-controls'));
      if (!panel || panel.getAttribute('role') !== 'tabpanel' || panel.getAttribute('aria-labelledby') !== t.id) out.push('tab ' + t.id);
    }
    for (const a of document.querySelectorAll('a[target=_blank]')) if (!/noopener/.test(a.rel) || !/noreferrer/.test(a.rel)) out.push('rel ' + a.href);
    for (const a of document.querySelectorAll('a[href]')) if (!/^(https:|#)/.test(a.getAttribute('href'))) out.push('href ' + a.getAttribute('href'));
    return [...new Set(out)];
  })()`);
  assert.deepEqual(issues, []);
});

check('at phone width (390 px) no tab scrolls sideways', async () => {
  const page = await open({ width: 390, height: 844, mobile: true });
  assert.equal(await page.eval('innerWidth'), 390);
  await setValue(page, '#domain', 'example.com');
  await setValue(page, '#dkim-p', KEY_B64);
  for (const t of ['spf', 'dkim', 'dmarc', 'inspect', 'help']) {
    await click(page, `#tab-${t}`);
    if (t === 'inspect') { await setValue(page, '#selectors', 'selector1'); await click(page, '#inspect-run'); await page.waitFor("document.querySelector('#inspect-results .tree') !== null"); }
    for (const f of ['zone', 'route53Json']) if (['spf', 'dkim', 'dmarc'].includes(t)) await click(page, `#${t}-output [data-format="${f}"]`);
    const w = await page.eval('[document.documentElement.scrollWidth, innerWidth]');
    assert.ok(w[0] <= w[1], `${t}: page is ${w[0]} px wide in a ${w[1]} px window`);
  }
  await clean(page);
  await page.close();
});

// ---- Run ----

for (const c of checks) {
  if (ONLY && !c.name.includes(ONLY)) continue;
  // A check written as async () => opens its own tabs; a second tab on the same origin would
  // share (and overwrite) its saved state.
  const page = c.fn.length ? await open() : { close: async () => {} };
  try {
    await Promise.race([c.fn(page), sleep(30000).then(() => { throw new Error('timed out after 30 s'); })]);
    passed++;
    console.log(`ok   ${c.name}`);
  } catch (e) {
    failed++;
    console.error(`FAIL ${c.name}\n  ${String(e.stack || e.message).split('\n').slice(0, 6).join('\n  ')}`);
  } finally {
    await page.close().catch(() => {});
  }
}
await chrome.close();
server.close();
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
