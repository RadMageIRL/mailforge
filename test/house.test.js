// Release checks for the page, the repository and everything it would publish: versions, the
// Content Security Policy, network calls, links, metadata, house style, and a scan for data that must
// never ship (private addresses, real domains, mailboxes, keys, secrets, workstation paths).
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync, existsSync, readdirSync, statSync } = require('node:fs');
const { join, relative } = require('node:path');
const { execFileSync } = require('node:child_process');
const MF = require('../mailforge-core.js');

const ROOT = join(__dirname, '..');
const file = p => readFileSync(join(ROOT, p), 'utf8');
const html = file('index.html');
const app = file('app.js');
const core = file('mailforge-core.js');
const VERSION = '0.1.0';
const CANON = 'https://radmagelabs.com/mailforge/';
const REPO = 'https://github.com/RadMageIRL/mailforge';

// Every file that is (or would be) committed: tracked plus untracked-but-not-ignored, so local notes
// excluded through .git/info/exclude are left out and a new file is checked before it is added.
function projectFiles() {
  try {
    const out = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], { cwd: ROOT, encoding: 'utf8' });
    const top = execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd: ROOT, encoding: 'utf8' }).trim();
    if (relative(top, ROOT) === '') return out.split('\0').filter(Boolean).filter(f => existsSync(join(ROOT, f)));
  } catch { /* not a git checkout: walk the folder instead */ }
  const walk = (dir, acc = []) => {
    for (const name of readdirSync(dir)) {
      if (['.git', 'local', 'dist', 'node_modules', 'docs'].includes(name)) continue;
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p, acc); else acc.push(relative(ROOT, p).replace(/\\/g, '/'));
    }
    return acc;
  };
  return walk(ROOT).filter(f => !/\.md$/.test(f) || /^(README|CHANGELOG)\.md$/.test(f));
}
const FILES = projectFiles();
const TEXT = FILES.filter(f => !/\.(png|ico|webp)$/.test(f));

// ---- versions ----

test('the version is the same in the core, title, header, JSON-LD, asset links, README and CHANGELOG', () => {
  assert.equal(MF.version, VERSION);
  assert.ok(html.includes(`<title>MailForge v${VERSION} - `));
  assert.ok(html.includes(`<span class="tagline">v${VERSION} · `));
  assert.equal(JSON.parse(/<script type="application\/ld\+json">([^<]+)<\/script>/.exec(html)[1]).softwareVersion, VERSION);
  const assets = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map(m => m[1]);
  assert.deepEqual(assets, [`mailforge-core.js?v=${VERSION}`, `app.js?v=${VERSION}`]);
  assert.match(file('README.md'), new RegExp(`^# MailForge v${VERSION.replace(/\./g, '\\.')}\\n`));
  const log = file('CHANGELOG.md');
  assert.ok(log.startsWith(`# Changelog\n\n## v${VERSION} (`), 'the newest changelog entry is this version');
  assert.match(log.split('\n')[2], /^## v\d+\.\d+\.\d+ \(\d{4}-\d{2}-\d{2}\)$/);
});

// ---- security ----

test('the CSP allows only this site\'s scripts and the two DNS-over-HTTPS providers', () => {
  const csp = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
  assert.equal(csp, "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src https://cloudflare-dns.com https://dns.google; base-uri 'none'; form-action 'none'");
  assert.ok(html.includes('<meta name="referrer" content="no-referrer">'));
  const inline = [...html.matchAll(/<script(?![^>]*\bsrc=)([^>]*)>/g)].map(m => m[1].trim());
  assert.deepEqual(inline, ['type="application/ld+json"'], 'the only inline script is the JSON-LD data block');
  for (const [name, src] of [['index.html', html], ['app.js', app]]) assert.ok(!/<[^>]+\son[a-z]+\s*=/i.test(src), `${name}: no inline event handler attributes`);
});

test('the DNS providers in the CSP are exactly the ones the resolver calls, over HTTPS GET', () => {
  const hosts = [...core.matchAll(/url: \(n, t\) => `(https:\/\/[^/]+)\//g)].map(m => m[1]);
  assert.deepEqual(hosts, ['https://cloudflare-dns.com', 'https://dns.google']);
  const connect = /connect-src ([^;]+);/.exec(html)[1].split(' ');
  assert.deepEqual(connect, hosts);
  assert.ok(core.includes('${encodeURIComponent(n)}&type=${t}'), 'names are URL-encoded');
});

test('the page code makes no other network calls and runs no generated code', () => {
  const fetches = [...app.matchAll(/\bfetch\(/g)].length;
  assert.equal(fetches, 1, 'one fetch, inside the resolver');
  assert.match(app, /MF\.makeResolver\(\(url, init\) => fetch\(url, init\)/);
  assert.ok(!/\bfetch\(/.test(core), 'the core is given its fetch and never calls the network itself');
  for (const [name, src] of [['app.js', app], ['mailforge-core.js', core]]) {
    assert.ok(!/XMLHttpRequest|WebSocket|sendBeacon|EventSource|import\(|\beval\(|new Function|document\.write|setTimeout\(['"`]/.test(src), name);
  }
  assert.ok(!/\b(?:document|window)\.[A-Za-z_$]|innerHTML|localStorage/.test(core), 'the core has no DOM or storage access');
  assert.ok(!/console\.(log|info|debug|warn|error)/.test(app + core), 'nothing is logged to the console');
});

test('external links open safely and go to known addresses only', () => {
  const allowed = /^https:\/\/(www\.rfc-editor\.org\/rfc\/rfc\d+(#[\w.-]+)?|radmagelabs\.com\/|github\.com\/RadMageIRL\/mailforge(\/issues)?|www\.gnu\.org\/licenses\/)$/;
  const anchors = [...html.matchAll(/<a\b[^>]*>/g)].map(m => m[0]).filter(a => !/href="#/.test(a));
  assert.ok(anchors.length >= 15);
  for (const a of anchors) {
    const href = /href="([^"]+)"/.exec(a)[1];
    assert.match(href, allowed, href);
    if (href !== 'https://radmagelabs.com/') assert.ok(a.includes('target="_blank" rel="noopener noreferrer"'), a);
  }
  assert.ok(app.includes('target="_blank" rel="noopener noreferrer"'), 'reference links rendered by the page');
  assert.ok(!/rel="noopener"/.test(html + app));
  for (const href of Object.values(MF.RFC)) assert.match(href, /^https:\/\/www\.rfc-editor\.org\/rfc\/rfc\d+$/);
});

test('a pasted private key is refused and kept out of storage', () => {
  assert.ok(MF.looksLikePrivateKey('-----BEGIN RSA PRIVATE KEY-----\nAAAA'));
  assert.ok(MF.looksLikePrivateKey('-----BEGINPRIVATEKEY-----AAAA'), 'with the spaces removed, as the p= field does');
  assert.ok(MF.looksLikePrivateKey('-----BEGIN OPENSSH PRIVATE KEY-----'));
  assert.ok(!MF.looksLikePrivateKey('-----BEGIN PUBLIC KEY-----\nAAAA'));
  assert.equal(MF.normalizeDkimInput('-----BEGIN EC PRIVATE KEY-----\nAAAA').error, MF.PRIVATE_KEY_ERROR);
  assert.match(app, /const scrub = v => \(MF\.looksLikePrivateKey\(v\) \? '' : v\);/);
  assert.match(app, /safeSet\(STATE_KEY, JSON\.stringify\(storable\(\)\)\)/, 'state is saved only through storable()');
  assert.equal([...app.matchAll(/safeSet\(STATE_KEY/g)].length, 1);
});

// ---- metadata ----

test('search and sharing metadata: canonical, Open Graph and JSON-LD agree on radmagelabs.com/mailforge/', () => {
  const meta = prop => (new RegExp(`<meta (?:property|name)="${prop}" content="([^"]*)">`).exec(html) || [])[1];
  assert.ok(html.includes(`<link rel="canonical" href="${CANON}">`));
  assert.equal(meta('og:url'), CANON);
  assert.equal(meta('og:image'), 'https://radmagelabs.com/assets/og/mailforge.png');
  assert.deepEqual([meta('og:image:width'), meta('og:image:height')], ['1200', '630']);
  assert.equal(meta('twitter:card'), 'summary_large_image');
  assert.equal(meta('og:site_name'), 'RadMage Labs');
  for (const p of ['og:title', 'og:description', 'og:image:alt', 'description']) assert.ok(meta(p), p);
  assert.ok(meta('description').length <= 160, `description is ${meta('description').length} characters`);
  assert.ok(/<title>[^<]{20,90}<\/title>/.test(html));
  const ld = JSON.parse(/<script type="application\/ld\+json">([^<]+)<\/script>/.exec(html)[1]);
  assert.equal(ld['@type'], 'WebApplication');
  assert.equal(ld.url, CANON);
  assert.equal(ld.sameAs, REPO);
  assert.equal(ld.image, meta('og:image'));
  assert.equal(ld.license, 'https://www.gnu.org/licenses/gpl-3.0.html');
  assert.equal((html.match(/<h1>/g) || []).length, 1);
  assert.equal((html.match(/<h2 class="sr-only">/g) || []).length, 5, 'each tab panel has a heading');
});

test('the favicon is an inline SVG (no request) that parses', () => {
  const href = /<link rel="icon" type="image\/svg\+xml" href="data:image\/svg\+xml,([^"]+)">/.exec(html)[1];
  assert.match(decodeURIComponent(href), /^<svg xmlns='http:\/\/www\.w3\.org\/2000\/svg' viewBox='0 0 64 64'>[\s\S]*<\/svg>$/);
});

// ---- repository ----

test('release files: GPL-3.0 LICENSE, .nojekyll, and a CI workflow that runs every check', () => {
  assert.match(file('LICENSE'), /^\s+GNU GENERAL PUBLIC LICENSE\n\s+Version 3, 29 June 2007\n/);
  for (const f of ['index.html', 'app.js', 'mailforge-core.js']) assert.ok(file(f).includes('SPDX-License-Identifier: GPL-3.0-or-later'), f);
  assert.ok(existsSync(join(ROOT, '.nojekyll')));
  const wf = file('.github/workflows/test.yml');
  for (const cmd of ['node --test', 'node tools/build.mjs --verify', 'node tools/smoke.mjs']) assert.ok(wf.includes(cmd), cmd);
  assert.match(wf, /os: \[ubuntu-latest, windows-latest\]/);
});

test('no package.json, no dependencies, no third-party code', () => {
  assert.equal(existsSync(join(ROOT, 'package.json')), false);
  assert.equal(existsSync(join(ROOT, 'node_modules')), false);
  for (const f of FILES.filter(x => /\.(m?js)$/.test(x))) {
    for (const m of file(f).matchAll(/(?:require\(|from )'([^']+)'/g)) assert.match(m[1], /^(node:|\.{1,2}\/)/, `${f} imports ${m[1]}`);
  }
});

test('only README.md and CHANGELOG.md are published as Markdown', () => {
  assert.deepEqual(FILES.filter(f => f.endsWith('.md')).sort(), ['CHANGELOG.md', 'README.md']);
  assert.ok(!FILES.includes('test.txt'));
});

test('README links point at real files', () => {
  for (const m of file('README.md').matchAll(/\]\(((?!https?:)[^)#]+)\)/g)) assert.ok(existsSync(join(ROOT, m[1])), m[1]);
});

test('no em dashes and only LF line endings in any project file', () => {
  const EM = String.fromCharCode(0x2014);
  assert.deepEqual(TEXT.filter(f => file(f).includes(EM)), []);
  assert.deepEqual(TEXT.filter(f => readFileSync(join(ROOT, f)).includes(13)), []);
});

// ---- data that must never ship ----

// Documentation ranges, the any and loopback addresses, and Cloudflare's public resolver (named in
// its DNS-over-HTTPS documentation link).
const DOC_V4 = /^(192\.0\.2\.|192\.0\.02\.|198\.51\.100\.|203\.0\.113\.|0\.0\.0\.0$|127\.0\.0\.1$|1\.1\.1\.1$)/;
test('every IPv4 address in the project is a documentation address (RFC 5737) or a public resolver', () => {
  const bad = [];
  for (const f of TEXT) {
    const src = file(f);
    for (const m of src.matchAll(/(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])/g)) {
      // RFC section numbers such as §3.6.2.2 are not addresses.
      if (/(§|section-|ref\('\w+', ')$/.test(src.slice(Math.max(0, m.index - 16), m.index))) continue;
      if (!DOC_V4.test(m[1])) bad.push(`${f}: ${m[1]}`);
    }
  }
  assert.deepEqual(bad.filter(b => !/LICENSE/.test(b)), []);
});

test('every IPv6 address in the project is a documentation address (RFC 3849)', () => {
  // Any run of hex digits and colons with at least two colons is a candidate; it counts as an
  // address when the core's own parser accepts it. "ip6:" is split off first so its colon does not
  // join the address, and a run that continues into a word (::before) is not a candidate.
  const doc = n => (n >> 96n) === 0x20010db8n || n === 0n || n === 1n || (n >> 32n) === 0xffffn;
  const bad = [];
  for (const f of TEXT.filter(x => x !== 'LICENSE')) {
    const src = file(f).replace(/ip6:/gi, 'ip6 ');
    for (const m of src.matchAll(/(?<![\w:.])[0-9a-f]*:[0-9a-f:]*:[0-9a-f:]*(?:\d+\.\d+\.\d+\.\d+)?(?![\w.:])/gi)) {
      const n = MF.parseIPv6(m[0].replace(/\/\d+$/, ''));
      if (n !== null && !doc(n)) bad.push(`${f}: ${m[0]}`);
    }
  }
  assert.deepEqual(bad, []);
});

// Domains the project may name: reserved examples (RFC 2606), its own homes, the standards it
// cites, and the public provider names its presets and help use.
const KNOWN_DOMAINS = [
  'example.com', 'example.net', 'example.org', 'example', 'test', 'invalid',
  'radmagelabs.com', 'github.com', 'radmageirl.github.io', 'rfc-editor.org', 'gnu.org', 'fsf.org', 'w3.org', 'schema.org',
  'cloudflare-dns.com', 'dns.google', 'spf.protection.outlook.com', '_spf.google.com', 'mailgun.org', 'sendgrid.net',
  'barracudanetworks.com', 'developers.cloudflare.com', 'developers.google.com',
];
const TLDS = 'com|net|org|io|dev|app|co|us|uk|de|au|ca|in|info|biz|me|ai|edu|gov|mil|cloud|email|google|tech|xyz|online|site|local|corp|lan|internal|home';
test('every domain name in the project is reserved for examples or a public site the page names', () => {
  const re = new RegExp(`(?<![\\w.@/-])((?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\\.)+(?:${TLDS}))(?![\\w.-]*[a-z0-9])`, 'gi');
  // The core's short list of two-label public suffixes (co.uk and the like) is data, not a domain.
  const suffixes = new Set(/MULTI_SUFFIX = new Set\(\[([^\]]+)\]\)/.exec(core)[1].match(/[a-z.]+/g));
  const bad = new Set();
  for (const f of TEXT.filter(x => x !== 'LICENSE')) {
    for (const m of file(f).matchAll(re)) {
      const d = m[1].toLowerCase().replace(/^www\./, '');
      if (/\.(js|mjs|css|html|png|md|json|yml|txt)$/.test(d) || suffixes.has(d) || d === 'chrome.app') continue;
      if (!KNOWN_DOMAINS.some(k => d === k || d.endsWith(`.${k}`))) bad.add(`${f}: ${d}`);
    }
  }
  assert.deepEqual([...bad], []);
});

test('every email address in the project is at a reserved example domain', () => {
  const bad = [];
  for (const f of TEXT.filter(x => x !== 'LICENSE')) {
    for (const m of file(f).matchAll(/[\w.+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)/gi)) {
      const d = m[1].toLowerCase();
      if (!/(^|\.)example(\.(com|net|org))?$/.test(d)) bad.push(`${f}: ${m[0]}`);
    }
  }
  assert.deepEqual(bad, []);
});

test('no keys, tokens, credentials or workstation paths', () => {
  const rules = [
    [/-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/]{40,}/, 'a PEM private key'],
    [/[A-Za-z0-9+/]{64,}={0,2}/, 'a long base64 blob (a key or token)'],
    [/\bAKIA[0-9A-Z]{16}\b/, 'an AWS access key'],
    [/\bgh[pousr]_[A-Za-z0-9]{30,}/, 'a GitHub token'],
    [/\bxox[abprs]-[A-Za-z0-9-]{10,}/, 'a Slack token'],
    [/\bBearer\s+[A-Za-z0-9._-]{20,}/, 'an authorization header'],
    [/(api[_-]?key|secret|passw(or)?d|token)\s*[:=]\s*['"][^'"\s]{8,}['"]/i, 'a credential assignment'],
    [/[A-Za-z]:[\\/]+Users[\\/]+[A-Za-z]/i, 'a Windows user folder'],
    [/\/(Users|home)\/[a-z][\w.-]*\//, 'a home folder'],
  ];
  const bad = [];
  for (const f of TEXT.filter(x => x !== 'LICENSE')) {
    const src = file(f).replace('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', '');
    for (const [re, what] of rules) if (re.test(src)) bad.push(`${f}: ${what}`);
  }
  assert.deepEqual(bad, []);
});

// A list of names that must never appear (employers, hostnames, people) is kept outside the
// repository, so publishing the check never publishes the names. CI runs without it.
test('none of the locally listed private terms appear in a project file', { skip: !existsSync(join(ROOT, 'local', 'sensitive-terms.txt')) && 'no local term list' }, () => {
  const terms = file('local/sensitive-terms.txt').split(/\r?\n/).map(s => s.trim().toLowerCase()).filter(s => s && !s.startsWith('#'));
  assert.ok(terms.length > 3);
  const bad = [];
  for (const f of TEXT) { const src = file(f).toLowerCase(); for (const t of terms) if (src.includes(t)) bad.push(`${f}: term ${terms.indexOf(t) + 1}`); }
  assert.deepEqual(bad, []);
});
