// MailForge core tests. Run from the repository folder:  node --test
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const MF = require('../mailforge-core.js');

const codes = r => r.findings.map(f => f.code);
const sevOf = (r, code) => (r.findings.find(f => f.code === code) || {}).sev;
const hasError = r => r.findings.some(f => f.sev === 'error');
const spkiB64 = key => key.export({ type: 'spki', format: 'der' }).toString('base64');
const rsa = bits => crypto.generateKeyPairSync('rsa', { modulusLength: bits }).publicKey;

// ---------- DNS length boundaries ----------
test('TXT strings split at exactly 255 bytes', () => {
  assert.deepEqual(MF.splitTxt(''), ['']);
  assert.equal(MF.splitTxt('a'.repeat(255)).length, 1);
  const two = MF.splitTxt('a'.repeat(256));
  assert.deepEqual(two.map(s => s.length), [255, 1]);
  assert.deepEqual(MF.splitTxt('a'.repeat(510)).map(s => s.length), [255, 255]);
  assert.deepEqual(MF.splitTxt('a'.repeat(511)).map(s => s.length), [255, 255, 1]);
});
test('splitting counts UTF-8 bytes and never cuts a character', () => {
  const v = 'a'.repeat(254) + 'é' + 'b';
  const parts = MF.splitTxt(v);
  assert.deepEqual(parts, ['a'.repeat(254), 'éb']);
  for (const p of parts) assert.ok(MF.byteLen(p) <= 255);
  assert.equal(parts.join(''), v);
});
test('presentation format escapes quotes and backslashes, not counted against the 255 bytes', () => {
  const f = MF.formatTxt('a"b\\c');
  assert.equal(f.presentation, '"a\\"b\\\\c"');
  const long = MF.formatTxt('"'.repeat(255));
  assert.equal(long.strings.length, 1);
});
test('parses quoted strings, escapes, zone lines and BIND output', () => {
  const z = MF.parseTxtPresentation('example.com. 3600 IN TXT "v=spf1 " "-all"');
  assert.equal(z.value, 'v=spf1 -all');
  assert.equal(z.name, 'example.com.');
  assert.equal(z.ttl, 3600);
  assert.deepEqual(MF.parseTxtPresentation('"a\\"b" "\\065\\\\"').strings, ['a"b', 'A\\']);
  const bind = MF.parseTxtPresentation('mail._domainkey IN TXT ( "v=DKIM1; k=rsa; "\n  "p=MIIB" )  ; ----- DKIM key mail for example.com');
  assert.equal(bind.value, 'v=DKIM1; k=rsa; p=MIIB');
  assert.equal(bind.name, 'mail._domainkey');
  assert.equal(MF.parseTxtPresentation('v=spf1 include:_spf.google.com ~all').value, 'v=spf1 include:_spf.google.com ~all');
});
test('flags an oversized quoted string and an unterminated quote', () => {
  assert.ok(MF.parseTxtPresentation(`"${'x'.repeat(256)}"`).warnings.some(w => /256 bytes/.test(w)));
  assert.ok(MF.parseTxtPresentation('"v=spf1 -all').warnings.some(w => /closing quote/.test(w)));
});
test('domain name limits', () => {
  assert.equal(MF.checkDomain('example.com'), null);
  assert.equal(MF.checkDomain('_spf.example.com'), null);
  assert.match(MF.checkDomain(`${'a'.repeat(64)}.com`), /63/);
  assert.equal(MF.checkDomain(`${'a'.repeat(63)}.com`), null);
  assert.match(MF.checkDomain(`${'a.'.repeat(126)}com`), /253/);
  assert.match(MF.checkDomain('exa mple.example'), /space/);
  assert.match(MF.checkDomain('bücher.example'), /punycode/);
  assert.match(MF.checkDomain('localhost'), /two labels/);
  assert.match(MF.checkDomain('192.0.2.1'), /numeric/);
});
test('DNS output formats keep one record with several strings', () => {
  const value = `v=DKIM1; k=rsa; p=${'A'.repeat(380)}`;
  const o = MF.dnsOutput({ zone: 'example.com', host: 's1._domainkey.example.com', value });
  assert.equal(o.relative, 's1._domainkey');
  assert.equal(o.strings.length, 2);
  assert.match(o.formats.zone, /^s1\._domainkey\.example\.com\. 3600 IN TXT "v=DKIM1[^"]+" "A+"$/);
  const r53 = JSON.parse(o.formats.route53Json);
  assert.equal(r53.Changes[0].ResourceRecordSet.ResourceRecords.length, 1);
  assert.equal(MF.parseTxtPresentation(r53.Changes[0].ResourceRecordSet.ResourceRecords[0].Value).value, value);
  assert.equal(MF.dnsOutput({ zone: 'example.com', host: 'example.com', value: 'v=spf1 -all' }).relative, '@');
  assert.equal(MF.dnsOutput({ zone: 'example.com', host: 'example.com', value: 'v=spf1 -all' }).formats.cloudflare.content, 'v=spf1 -all');
});

// ---------- IP handling ----------
test('IPv4 and IPv6 parsing and formatting', () => {
  assert.equal(MF.parseIPv4('192.0.2.1'), 0xc0000201n);
  assert.equal(MF.parseIPv4('192.0.2.256'), null);
  assert.equal(MF.parseIPv4('192.0.02.1'), null);
  assert.equal(MF.parseIPv4('192.0.2'), null);
  assert.equal(MF.formatIPv6(MF.parseIPv6('2001:DB8:0:0:0:0:0:1')), '2001:db8::1');
  assert.equal(MF.formatIPv6(MF.parseIPv6('::ffff:192.0.2.1')), '::ffff:c000:201');
  assert.equal(MF.formatIPv6(MF.parseIPv6('::')), '::');
  assert.equal(MF.parseIPv6('2001:db8::1::2'), null);
  assert.equal(MF.parseIPv6('2001:db8:1:2:3:4:5:6:7'), null);
  assert.equal(MF.parseIPv6('12345::1'), null);
});
test('CIDR merging produces the exact same address set', () => {
  const b = (ip, prefix) => ({ ip: MF.parseIPv4(ip), prefix, bits: 32 });
  const m = MF.mergeCidrs([b('192.0.2.0', 25), b('192.0.2.128', 25)], 32);
  assert.deepEqual(m.map(x => [MF.formatIPv4(x.ip), x.prefix]), [['192.0.2.0', 24]]);
  const m2 = MF.mergeCidrs([b('198.51.100.0', 26), b('198.51.100.64', 26), b('198.51.100.128', 26)], 32);
  assert.deepEqual(m2.map(x => [MF.formatIPv4(x.ip), x.prefix]), [['198.51.100.0', 25], ['198.51.100.128', 26]]);
});

// ---------- SPF ----------
test('a clean SPF record passes', () => {
  const r = MF.analyzeSpf('v=spf1 ip4:192.0.2.0/24 include:_spf.google.com -all');
  assert.equal(hasError(r), false);
  assert.equal(r.lookups, 1);
  assert.ok(codes(r).includes('spf-fail-all'));
});
test('malformed SPF input is reported, not thrown', () => {
  for (const bad of ['', 'hello', 'v=spf2 -all', 'v=spf1-all', 'spf1 -all', '"v=spf1 -all"', '   ', '\u0000']) {
    const r = MF.analyzeSpf(bad);
    assert.ok(hasError(r), `expected an error for ${JSON.stringify(bad)}`);
  }
  const cases = {
    'v=spf1 ip4:192.0.2.300 -all': /0–255/,
    'v=spf1 ip4:192.0.2.0/33 -all': /out of range/,
    'v=spf1 ip4:192.0.02.1 -all': /leading zero/,
    'v=spf1 ip4:2001:db8::1 -all': /use ip6/,
    'v=spf1 ip6:192.0.2.1 -all': /use ip4/,
    'v=spf1 ip6:2001:db8::/129 -all': /out of range/,
    'v=spf1 inlcude:example.com -all': /did you mean include/,
    'v=spf1 include=example.com -all': /needs ":"/,
    'v=spf1 include: -all': /needs a domain/,
    'v=spf1 include:example -all': /two labels/,
    'v=spf1 a:/24 -all': /empty domain/,
    'v=spf1 mx/33 -all': /0–32/,
    'v=spf1 all=1': /needs ":"|takes no value/,
    'v=spf1 exists:%{z}.example.com -all': /unknown macro/,
    'v=spf1 exists:%{c}.example.com -all': /only allowed in exp/
  };
  for (const [rec, re] of Object.entries(cases)) {
    const r = MF.analyzeSpf(rec);
    assert.ok(r.findings.some(f => f.sev === 'error' && re.test(f.detail + f.title)), `${rec} → ${JSON.stringify(r.findings.map(f => f.detail))}`);
  }
});
test('SPF qualifier on all', () => {
  assert.equal(sevOf(MF.analyzeSpf('v=spf1 +all'), 'spf-pass-all'), 'error');
  assert.equal(sevOf(MF.analyzeSpf('v=spf1 all'), 'spf-pass-all'), 'error');
  assert.equal(sevOf(MF.analyzeSpf('v=spf1 ?all'), 'spf-neutral-all'), 'warn');
  assert.equal(sevOf(MF.analyzeSpf('v=spf1 mx'), 'spf-no-all'), 'warn');
  assert.equal(sevOf(MF.analyzeSpf('v=spf1 mx -all ip4:192.0.2.1'), 'spf-after-all'), 'warn');
  assert.equal(sevOf(MF.analyzeSpf('v=spf1 -all redirect=_spf.example.com'), 'spf-redirect-ignored'), 'warn');
  assert.equal(sevOf(MF.analyzeSpf('v=spf1 ip4:0.0.0.0/0 -all'), 'spf-ip-all'), 'error');
  assert.equal(sevOf(MF.analyzeSpf('v=spf1 redirect=a.example.com redirect=b.example.com'), 'spf-dup-mod'), 'error');
});
test('SPF lookup counting: 10 is allowed, 11 is a permerror', () => {
  const inc = n => Array.from({ length: n }, (_, i) => `include:s${i}.example.com`).join(' ');
  const ten = MF.analyzeSpf(`v=spf1 ${inc(10)} -all`);
  assert.equal(ten.lookups, 10);
  assert.notEqual(sevOf(ten, 'spf-lookups'), 'error');
  const eleven = MF.analyzeSpf(`v=spf1 ${inc(11)} -all`);
  assert.equal(eleven.lookups, 11);
  assert.equal(sevOf(eleven, 'spf-lookups'), 'error');
});
test('SPF lookups: which terms count', () => {
  assert.equal(MF.analyzeSpf('v=spf1 a mx ptr exists:%{i}.x.example.com include:a.example.com ip4:192.0.2.1 ip6:2001:db8::1 -all').lookups, 5);
  assert.equal(MF.analyzeSpf('v=spf1 redirect=_spf.example.com').lookups, 1);
  assert.equal(MF.analyzeSpf('v=spf1 -all redirect=_spf.example.com').lookups, 0, 'redirect with all is never followed');
  assert.equal(MF.analyzeSpf('v=spf1 -all include:a.example.com').lookups, 0, 'terms after all are never evaluated');
});
test('SPF length thresholds', () => {
  const ips = n => Array.from({ length: n }, (_, i) => `ip4:198.51.100.${i}`).join(' ');
  const mid = MF.analyzeSpf(`v=spf1 ${ips(16)} -all`);
  assert.ok(mid.bytes > 255 && mid.bytes <= 450, String(mid.bytes));
  assert.equal(sevOf(mid, 'spf-strings'), 'info');
  const big = MF.analyzeSpf(`v=spf1 ${ips(30)} -all`);
  assert.ok(big.bytes > 450);
  assert.equal(sevOf(big, 'spf-length'), 'warn');
});
test('SPF strings joined without a space are caught', () => {
  const r = MF.analyzeSpf('v=spf1 include:a.example.cominclude:b.example.com -all', { strings: ['v=spf1 include:a.example.com', 'include:b.example.com -all'] });
  assert.equal(sevOf(r, 'spf-join'), 'error');
  const ok = MF.analyzeSpf('v=spf1 include:a.example.com include:b.example.com -all', { strings: ['v=spf1 include:a.example.com ', 'include:b.example.com -all'] });
  assert.equal(sevOf(ok, 'spf-join'), undefined);
  const mid = MF.analyzeSpf('v=spf1 ip4:192.0.2.1 -all', { strings: ['v=spf1 ip4:192.0', '.2.1 -all'] });
  assert.equal(sevOf(mid, 'spf-join'), undefined, 'a split inside a term is fine');
});
test('non-ASCII in SPF is an error', () => {
  assert.equal(sevOf(MF.analyzeSpf('v=spf1 include:_spf.example.com\u00a0-all'), 'spf-ascii'), 'error');
});

// ---------- SPF repair ----------
test('repair removes duplicates and covered ranges, and only those', () => {
  const r = MF.repairSpf('v=spf1 ip4:192.0.2.0/24 include:a.example.com ip4:192.0.2.7 include:A.example.com. ~all');
  assert.equal(r.value, 'v=spf1 ip4:192.0.2.0/24 include:a.example.com ~all');
  assert.ok(r.changes.every(c => ['dead', 'cosmetic', 'merge'].includes(c.kind)));
});
test('repair merges adjacent ranges with the same qualifier', () => {
  assert.equal(MF.repairSpf('v=spf1 ip4:192.0.2.0/25 ip4:192.0.2.128/25 -all').value, 'v=spf1 ip4:192.0.2.0/24 -all');
  assert.equal(MF.repairSpf('v=spf1 ip6:2001:db8::/33 ip6:2001:db8:8000::/33 -all').value, 'v=spf1 ip6:2001:db8::/32 -all');
});
test('repair never merges across a different qualifier or another mechanism', () => {
  const q = 'v=spf1 ip4:192.0.2.0/25 -ip4:192.0.2.128/25 ~all';
  assert.equal(MF.repairSpf(q).value, q);
  const between = 'v=spf1 ip4:192.0.2.0/25 include:a.example.com ip4:192.0.2.128/25 -all';
  assert.equal(MF.repairSpf(between).value, between);
});
test('repair keeps the all qualifier and never weakens the policy', () => {
  for (const rec of ['v=spf1 mx -all', 'v=spf1 mx ~all', 'v=spf1 mx ?all', 'v=spf1 mx +all']) {
    const out = MF.repairSpf(rec).value;
    assert.equal(out.split(' ').pop(), rec.split(' ').pop());
  }
});
test('repair normalizes host bits and drops /32 without changing coverage', () => {
  const r = MF.repairSpf('v=spf1 ip4:192.0.2.10/24 ip4:198.51.100.1/32 -all');
  assert.equal(r.value, 'v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.1 -all');
});
test('repair removes terms after all and an ignored redirect', () => {
  assert.equal(MF.repairSpf('v=spf1 mx -all include:x.example.com').value, 'v=spf1 mx -all');
  assert.equal(MF.repairSpf('v=spf1 mx -all redirect=_spf.example.com').value, 'v=spf1 mx -all');
  assert.equal(MF.repairSpf('v=spf1 mx exp=explain.example.com -all').value, 'v=spf1 mx exp=explain.example.com -all');
});
test('repair blocks what it cannot fix and keeps the bad term verbatim', () => {
  const r = MF.repairSpf('v=spf1 ip4:192.0.2.300 -all');
  assert.equal(r.blocked.length, 1);
  assert.ok(r.value.includes('ip4:192.0.2.300'));
  assert.equal(MF.repairSpf('not spf').value, null);
});
test('repair is idempotent', () => {
  for (const rec of ['v=spf1 ip4:192.0.2.0/25 ip4:192.0.2.128/25 a a mx ~all', 'V=SPF1  include:a.example.com   -all', 'v=spf1 ip4:198.51.100.0/24 ip4:198.51.100.128/25 -all']) {
    const once = MF.repairSpf(rec).value;
    const twice = MF.repairSpf(once);
    assert.equal(twice.value, once);
    assert.equal(twice.changed, false);
  }
});
test('merging two SPF records yields one record and flags review', () => {
  const m = MF.mergeSpfRecords(['v=spf1 include:a.example.com -all', 'v=spf1 ip4:192.0.2.1 include:a.example.com ~all']);
  assert.equal(m.value, 'v=spf1 include:a.example.com ip4:192.0.2.1 -all');
  assert.equal(m.needsReview, true);
  assert.equal(m.notes.length, 1);
  assert.equal((m.value.match(/v=spf1/g) || []).length, 1);
  assert.equal(MF.mergeSpfRecords(['v=spf1 redirect=x.example.com', 'v=spf1 -all']).value, null);
});

// ---------- round trips ----------
test('SPF parse → serialize round trip', () => {
  for (const rec of ['v=spf1 -all', 'v=spf1 a mx/24 a:mail.example.com/28//64 ptr:example.com ip4:192.0.2.0/24 ip6:2001:db8::/32 include:_spf.example.com exists:%{ir}.%{l1r+-}._spf.%{d} ?all', 'v=spf1 redirect=_spf.example.com', 'v=spf1 include:a.example.com exp=why.example.com ~all']) {
    const p = MF.parseSpf(rec);
    const back = ['v=spf1', ...p.terms.map(MF.termString)].join(' ');
    assert.equal(back, rec);
    assert.deepEqual(MF.parseSpf(back).terms.map(t => t.raw), p.terms.map(t => t.raw));
  }
});
test('TXT split → quote → parse round trip', () => {
  for (const v of ['v=spf1 -all', 'x'.repeat(1000), 'quote " and \\ backslash ' + 'y'.repeat(300)]) {
    const f = MF.formatTxt(v);
    const back = MF.parseTxtPresentation(f.presentation);
    assert.equal(back.value, v);
    assert.deepEqual(back.strings, f.strings);
  }
});
test('DMARC build → analyze → repair round trip', () => {
  const rec = MF.buildDmarc({ p: 'reject', sp: 'quarantine', pct: 100, rua: 'dmarc@example.com', adkim: 's' });
  assert.equal(rec, 'v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com; adkim=s');
  const r = MF.repairDmarc(rec);
  assert.equal(r.value, rec);
  assert.equal(r.changed, false);
  assert.ok(MF.compareRecords('dmarc', rec, 'v=DMARC1;adkim=s;  rua=mailto:DMARC@example.com; sp=quarantine; p=REJECT').same);
});

// ---------- DKIM ----------
test('DKIM RSA 2048 key splits into ≤255-byte strings in one record and survives the round trip', () => {
  const p = spkiB64(rsa(2048));
  const rec = MF.buildDkim({ p });
  const r = MF.analyzeDkim(rec, { selector: 'selector1' });
  assert.equal(r.key.bits, 2048);
  assert.equal(hasError(r), false);
  const out = MF.dnsOutput({ zone: 'example.com', host: 'selector1._domainkey.example.com', value: rec });
  assert.ok(out.strings.length >= 2);
  for (const s of out.strings) assert.ok(MF.byteLen(s) <= 255);
  assert.equal(out.strings.join(''), rec);
  assert.equal(MF.parseTxtPresentation(out.formats.zone).value, rec);
  assert.equal(MF.parseDkim(MF.parseTxtPresentation(out.presentation).value).map.p, p);
});
test('DKIM RSA 4096 key needs at least 3 strings', () => {
  const rec = MF.buildDkim({ p: spkiB64(rsa(4096)) });
  assert.ok(MF.splitTxt(rec).length >= 3);
  assert.equal(MF.analyzeDkim(rec).key.bits, 4096);
});
test('DKIM key strength', () => {
  assert.equal(sevOf(MF.analyzeDkim(MF.buildDkim({ p: spkiB64(rsa(1024)) })), 'dkim-1024'), 'warn');
  assert.equal(sevOf(MF.analyzeDkim(MF.buildDkim({ p: spkiB64(rsa(512)) })), 'dkim-weak'), 'error');
});
test('PKCS#1 RSA keys are converted to SPKI without changing the key', () => {
  const key = rsa(2048);
  const pkcs1 = key.export({ type: 'pkcs1', format: 'der' }).toString('base64');
  const r = MF.analyzeDkim(`v=DKIM1; k=rsa; p=${pkcs1}`);
  assert.equal(sevOf(r, 'dkim-pkcs1'), 'warn');
  const fixed = MF.repairDkim(`v=DKIM1; k=rsa; p=${pkcs1}`);
  assert.equal(MF.parseDkim(fixed.value).map.p, spkiB64(key));
  const pem = key.export({ type: 'pkcs1', format: 'pem' });
  assert.equal(MF.parseDkim(MF.normalizeDkimInput(pem).value).map.p, spkiB64(key));
});
test('Ed25519: raw key accepted, SPKI form extracted, k= fixed', () => {
  const key = crypto.generateKeyPairSync('ed25519').publicKey;
  const spki = key.export({ type: 'spki', format: 'der' });
  const raw = spki.subarray(spki.length - 32).toString('base64');
  const good = MF.analyzeDkim(`v=DKIM1; k=ed25519; p=${raw}`);
  assert.equal(hasError(good), false);
  assert.equal(good.key.type, 'ed25519');
  const wrapped = `v=DKIM1; p=${spki.toString('base64')}`;
  assert.ok(codes(MF.analyzeDkim(wrapped)).includes('dkim-ed-spki'));
  assert.ok(codes(MF.analyzeDkim(wrapped)).includes('dkim-k-mismatch'));
  assert.equal(MF.repairDkim(wrapped).value, `v=DKIM1; k=ed25519; p=${raw}`);
  assert.equal(MF.normalizeDkimInput(key.export({ type: 'spki', format: 'pem' })).value, `v=DKIM1; k=ed25519; p=${raw}`);
});
test('malformed DKIM input is reported', () => {
  const p = spkiB64(rsa(1024));
  const cases = {
    '': 'dkim-empty',
    'v=DKIM1; k=rsa': 'dkim-no-p',
    'v=DKIM1; p=abc$def': 'dkim-key',
    'v=DKIM1; p=YWJj': 'dkim-key',
    [`v=DKIM1; p=${p.slice(0, -10)}`]: 'dkim-key',
    [`v=DKIM1; p=${p.slice(0, 20)}-${p.slice(21)}`]: 'dkim-key',
    [`k=rsa; v=DKIM1; p=${p}`]: 'dkim-v-order',
    [`v=DKIM2; p=${p}`]: 'dkim-v',
    [`v=DKIM1; k=dsa; p=${p}`]: 'dkim-k',
    [`v=DKIM1; h=sha1; p=${p}`]: 'dkim-sha1',
    [`v=DKIM1; p=${p}; p=${p}`]: 'dkim-dup',
    [`v=DKIM1; P=${p}`]: 'dkim-case',
    [`v=DKIM1; s=web; p=${p}`]: 'dkim-s',
    [`v=DKIM1; p=${p}; garbage`]: 'dkim-syntax'
  };
  for (const [rec, code] of Object.entries(cases)) assert.equal(sevOf(MF.analyzeDkim(rec), code), 'error', `${rec.slice(0, 40)} → ${code}`);
  assert.equal(sevOf(MF.analyzeDkim(`v=DKIM1; t=y; p=${p}`), 'dkim-testing'), 'warn');
  assert.equal(sevOf(MF.analyzeDkim('v=DKIM1; p='), 'dkim-revoked'), 'warn');
  assert.ok(codes(MF.analyzeDkim(`v=DKIM1; p=${p}`, { selector: 'bad_sel' })).includes('dkim-selector'));
  assert.ok(codes(MF.analyzeDkim(`v=DKIM1; p=${p}`, { selector: 's1._domainkey' })).includes('dkim-selector'));
});
test('private keys are refused', () => {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
  assert.match(MF.normalizeDkimInput(privateKey.export({ type: 'pkcs8', format: 'pem' })).error, /PRIVATE key/);
  assert.match(MF.normalizeDkimInput(privateKey.export({ type: 'pkcs1', format: 'pem' })).error, /PRIVATE key/);
});
test('DKIM input from BIND / opendkim output keeps the selector', () => {
  const p = spkiB64(rsa(2048));
  const bind = `mail._domainkey\tIN\tTXT\t( "v=DKIM1; h=sha256; k=rsa; "\n\t  "p=${p.slice(0, 200)}"\n\t  "${p.slice(200)}" )  ; ----- DKIM key mail for example.com`;
  const n = MF.normalizeDkimInput(bind);
  assert.equal(n.selector, 'mail');
  assert.equal(MF.parseDkim(n.value).map.p, p);
  assert.equal(hasError(MF.analyzeDkim(n.value)), false);
});
test('DKIM repair is idempotent and blocks sha1-only', () => {
  const p = spkiB64(rsa(1024));
  const once = MF.repairDkim(`k=rsa; v=DKIM1; p=${p.slice(0, 50)} ${p.slice(50)}`);
  assert.equal(once.value, `v=DKIM1; k=rsa; p=${p}`);
  assert.equal(MF.repairDkim(once.value).changed, false);
  assert.equal(MF.repairDkim(`v=DKIM1; h=sha1; p=${p}`).blocked.length, 1);
});

// ---------- DMARC ----------
test('malformed DMARC input is reported', () => {
  const cases = {
    'p=reject; v=DMARC1': 'dmarc-version',
    'v=DMARC2; p=none': 'dmarc-version',
    'v=DMARC1; p=block': 'dmarc-p',
    'v=DMARC1': 'dmarc-no-p',
    'v=DMARC1; p=none; pct=101': 'dmarc-pct',
    'v=DMARC1; p=none; pct=abc': 'dmarc-pct',
    'v=DMARC1; p=none; rua=dmarc@example.com': 'dmarc-rua',
    'v=DMARC1; p=none; rua=mailto:not-an-address': 'dmarc-rua',
    'v=DMARC1; p=none; p=reject': 'dmarc-dup',
    'v=DMARC1; p=none; adkim=x': 'dmarc-adkim',
    'v=DMARC1; p=none; fo=2': 'dmarc-fo',
    'v=DMARC1; p=none, rua=mailto:a@example.com': 'dmarc-p',
    'v=DMARC1; p=none; junk': 'dmarc-syntax'
  };
  for (const [rec, code] of Object.entries(cases)) assert.equal(sevOf(MF.analyzeDmarc(rec), code), 'error', `${rec} → ${code}: ${JSON.stringify(codes(MF.analyzeDmarc(rec)))}`);
});
test('DMARC policy risks', () => {
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=none; rua=mailto:d@example.com'), 'dmarc-none'), 'warn');
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com'), 'dmarc-sp-weak'), 'warn');
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=reject'), 'dmarc-no-rua'), 'warn');
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; rua=mailto:d@example.com'), 'dmarc-no-p'), 'warn');
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:x@reports.example.net', { domain: 'example.com' }), 'dmarc-external'), 'info');
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:x@mail.example.com', { domain: 'example.com' }), 'dmarc-external'), undefined);
});
test('DMARC repair: safe changes only, policies never touched', () => {
  const r = MF.repairDmarc('rua=mailto:d@example.com ,  mailto:e@example.com; P=Reject; v=DMARC1;');
  assert.equal(r.value, 'v=DMARC1; p=reject; rua=mailto:d@example.com,mailto:e@example.com');
  assert.ok(r.changes.some(c => c.kind === 'fix' && /Moved v=DMARC1/.test(c.text)));
  const missingP = MF.repairDmarc('v=DMARC1; rua=mailto:d@example.com');
  assert.equal(missingP.value, 'v=DMARC1; p=none; rua=mailto:d@example.com');
  assert.equal(MF.repairDmarc('v=DMARC1').blocked.length, 1, 'no rua: adding p= is left to the user');
  assert.ok(MF.repairDmarc('v=DMARC1; p=reject; p=none').blocked.length >= 1);
  assert.ok(MF.repairDmarc('v=DMARC1; p=block').value.includes('p=block'));
  for (const pol of ['none', 'quarantine', 'reject']) assert.match(MF.repairDmarc(`v=DMARC1; sp=none; p=${pol}; pct=50`).value, new RegExp(`p=${pol}; sp=none; pct=50`));
});
test('DMARC tags from RFC 9989: t, psd and np are checked, removed tags are noted', () => {
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=quarantine; t=y; rua=mailto:d@example.com'), 'dmarc-t'), 'warn');
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=none; t=y; rua=mailto:d@example.com'), 'dmarc-t'), undefined, 't=y changes nothing for p=none');
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=quarantine; t=maybe'), 'dmarc-t'), 'error');
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=reject; psd=y'), 'dmarc-psd'), 'warn');
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=reject; psd=n'), 'dmarc-psd'), 'info');
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=reject; psd=x'), 'dmarc-psd'), 'error');
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=reject; np=reject'), 'dmarc-np'), 'info');
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=reject; np=block'), 'dmarc-np'), 'error');
  const old = MF.analyzeDmarc('v=DMARC1; p=none; rf=afrf; ri=3600; rua=mailto:d@example.com');
  assert.equal(old.findings.filter(f => f.code === 'dmarc-removed').length, 2);
  assert.ok(!codes(MF.analyzeDmarc('v=DMARC1; p=none; t=n; psd=u')).includes('dmarc-unknown'), 't and psd are known tags');
  assert.match(MF.analyzeDmarc('v=DMARC1; p=reject; pct=50').findings.find(f => f.code === 'dmarc-pct').detail, /RFC 9989/);
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:d@example.com'), 'dmarc-reject-lists'), 'info');
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=quarantine; rua=mailto:d@example.com'), 'dmarc-reject-lists'), undefined);
});
test('DMARC repair blocks invalid np, t and psd values and lower-cases valid ones', () => {
  for (const bad of ['v=DMARC1; p=none; np=block', 'v=DMARC1; p=none; t=maybe', 'v=DMARC1; p=none; psd=x']) assert.ok(MF.repairDmarc(bad).blocked.length >= 1, bad);
  assert.equal(MF.repairDmarc('v=DMARC1; p=reject; t=Y; psd=N').value, 'v=DMARC1; p=reject; t=y; psd=n');
  assert.ok(MF.compareRecords('dmarc', 'v=DMARC1; p=reject; t=n; psd=u', 'v=DMARC1; p=reject').same, 'RFC 9989 defaults are not differences');
});
test('external report note names the authorization record for the policy domain', () => {
  const f = MF.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:x@reports.example.net', { domain: 'mail.example.com' }).findings.find(x => x.code === 'dmarc-external');
  assert.equal(f.sev, 'info');
  assert.match(f.detail, /mail\.example\.com\._report\._dmarc\.reports\.example\.net/);
  assert.equal(f.ref, 'https://www.rfc-editor.org/rfc/rfc9990#section-4');
});
test('references to RFC appendices use the appendix anchor', () => {
  const f = MF.analyzeDmarc('v=DMARC1; p=none; ri=3600').findings.find(x => x.code === 'dmarc-removed');
  assert.equal(f.ref, 'https://www.rfc-editor.org/rfc/rfc9989#appendix-C.5.2');
});
test('DMARC repair is idempotent', () => {
  const once = MF.repairDmarc('p=quarantine;v=DMARC1;;rua=mailto:a@example.com;  ').value;
  assert.equal(MF.repairDmarc(once).changed, false);
});

// ---------- comparison ----------
test('compare ignores formatting but not meaning', () => {
  assert.ok(MF.compareRecords('spf', 'v=spf1 +mx  include:A.example.com -all', 'v=spf1 mx include:a.example.com -all').same);
  const d = MF.compareRecords('spf', 'v=spf1 mx -all', 'v=spf1 mx ~all');
  assert.equal(d.same, false);
  assert.deepEqual(d.onlyPublished, ['-all']);
  assert.equal(MF.compareRecords('spf', 'v=spf1 a mx -all', 'v=spf1 mx a -all').orderDiffers, true);
  assert.ok(MF.compareRecords('dmarc', 'v=DMARC1; p=none; pct=100; adkim=r; rua=mailto:a@example.com', 'v=DMARC1; p=none; rua=mailto:a@example.com').same, 'defaults are not differences');
  assert.equal(MF.compareRecords('dmarc', 'v=DMARC1; p=none; pct=50', 'v=DMARC1; p=none').same, false);
  assert.ok(MF.compareRecords('dkim', 'p=ABCD', 'v=DKIM1; k=rsa; p=AB CD').same);
  assert.equal(MF.compareRecords('dkim', 'v=DKIM1; k=ed25519; p=ABCD', 'v=DKIM1; p=ABCD').same, false);
});

// ---------- SPF tree walk (mock DNS) ----------
function mockResolver(zone) {
  return async (name, type) => {
    const n = name.toLowerCase();
    if (zone.fail && zone.fail.includes(n)) return { status: 'ERROR', answers: [], error: 'boom' };
    const recs = (zone[n] || {})[type];
    if (!(n in zone)) return { status: 'NXDOMAIN', answers: [] };
    const answers = (recs || []).map(data => ({ name: n, type, ttl: 300, data: type === 'TXT' ? MF.formatTxt(data).presentation : data }));
    return { status: 'NOERROR', answers };
  };
}
test('walk counts lookups through nested includes', async () => {
  const zone = {
    'example.com': { TXT: ['v=spf1 include:a.example.net include:b.example.net mx -all'], MX: ['10 mx1.example.com.'] },
    'a.example.net': { TXT: ['v=spf1 include:c.example.net ip4:192.0.2.0/24 ~all'] },
    'b.example.net': { TXT: ['v=spf1 a:host.example.net ~all'] },
    'c.example.net': { TXT: ['v=spf1 ip4:198.51.100.0/24 ~all'] },
    'host.example.net': { A: ['192.0.2.5'] }
  };
  const w = await MF.walkSpf('example.com', mockResolver(zone));
  assert.equal(w.lookups, 5);
  assert.equal(w.voids, 0);
  assert.equal(sevOf(w, 'spf-tree-lookups'), 'ok');
});
test('walk flags more than 10 lookups across includes', async () => {
  const zone = { 'example.com': { TXT: ['v=spf1 include:p1.example.net include:p2.example.net -all'] } };
  for (const p of ['p1', 'p2']) zone[`${p}.example.net`] = { TXT: [`v=spf1 ${[1, 2, 3, 4, 5].map(i => `include:${p}-${i}.example.net`).join(' ')} ~all`] };
  for (const p of ['p1', 'p2']) for (let i = 1; i <= 5; i++) zone[`${p}-${i}.example.net`] = { TXT: ['v=spf1 ip4:192.0.2.1 ~all'] };
  const w = await MF.walkSpf('example.com', mockResolver(zone));
  assert.equal(w.lookups, 12);
  assert.equal(sevOf(w, 'spf-tree-lookups'), 'error');
});
test('walk counts void lookups and flags more than two', async () => {
  const zone = {
    'example.com': { TXT: ['v=spf1 a:gone1.example.com mx:nomx.example.com include:missing.example.net -all'] },
    'gone1.example.com': {},
    'nomx.example.com': { TXT: ['unrelated'] }
  };
  const w = await MF.walkSpf('example.com', mockResolver(zone));
  assert.equal(w.voids, 3);
  assert.equal(sevOf(w, 'spf-voids'), 'error');
  const inc = w.root.children.find(c => c.kind === 'include');
  assert.match(inc.error, /does not exist/);
});
test('walk detects include loops and stops', async () => {
  const zone = { 'example.com': { TXT: ['v=spf1 include:a.example.net -all'] }, 'a.example.net': { TXT: ['v=spf1 include:example.com ~all'] } };
  const w = await MF.walkSpf('example.com', mockResolver(zone));
  assert.equal(sevOf(w, 'spf-loop'), 'error');
});
test('walk follows redirect only without all, skips macros, reports failures', async () => {
  const zone = {
    'example.com': { TXT: ['v=spf1 exists:%{i}._spf.example.com include:down.example.net redirect=_spf.example.com'] },
    '_spf.example.com': { TXT: ['v=spf1 ip4:192.0.2.0/24 -all'] },
    fail: ['down.example.net']
  };
  const w = await MF.walkSpf('example.com', mockResolver(zone));
  assert.equal(w.lookups, 3);
  assert.ok(w.root.children.some(c => c.kind === 'redirect' && c.record === 'v=spf1 ip4:192.0.2.0/24 -all'));
  assert.ok(w.root.children.some(c => /macro/.test(c.note || '')));
  assert.equal(sevOf(w, 'spf-temp'), 'warn');
});
test('include of a domain with several SPF records is reported', async () => {
  const zone = { 'example.com': { TXT: ['v=spf1 include:two.example.net -all'] }, 'two.example.net': { TXT: ['v=spf1 -all', 'v=spf1 ~all'] } };
  const w = await MF.walkSpf('example.com', mockResolver(zone));
  assert.match(w.root.children[0].error, /2 SPF records/);
});
test('inspect: multiple SPF records at the root, DMARC external report authorization', async () => {
  const zone = {
    'example.com': { TXT: ['v=spf1 -all', 'v=spf1 mx ~all', 'google-site-verification=abc'] },
    '_dmarc.example.com': { TXT: ['v=DMARC1; p=reject; rua=mailto:a@reports.example.net,mailto:b@nope.example.org'] },
    'example.com._report._dmarc.reports.example.net': { TXT: ['v=DMARC1'] }
  };
  const resolve = mockResolver(zone);
  const spf = await MF.inspectSpf('example.com', resolve);
  assert.equal(sevOf(spf, 'spf-multiple'), 'error');
  assert.equal(spf.otherTxt, 1);
  const dmarc = await MF.inspectDmarc('example.com', resolve);
  assert.equal(dmarc.external.length, 2);
  assert.ok(dmarc.findings.some(f => f.code === 'dmarc-ext-ok' && /reports\.example\.net/.test(f.title)));
  assert.ok(dmarc.findings.some(f => f.code === 'dmarc-ext-missing' && /nope\.example\.org/.test(f.title)));
});
test('inspect: each external report domain is checked once per tag', async () => {
  const zone = {
    '_dmarc.example.com': { TXT: ['v=DMARC1; p=none; rua=mailto:a@reports.example.net,mailto:b@reports.example.net; ruf=mailto:c@reports.example.net'] },
    'example.com._report._dmarc.reports.example.net': { TXT: ['v=DMARC1'] }
  };
  const d = await MF.inspectDmarc('example.com', mockResolver(zone));
  assert.deepEqual(d.external.map(x => x.tag), ['rua', 'ruf']);
});
test('inspect: DMARC falls back to the organizational domain', async () => {
  const zone = { '_dmarc.example.com': { TXT: ['v=DMARC1; p=quarantine; rua=mailto:d@example.com'] } };
  const d = await MF.inspectDmarc('mail.example.com', mockResolver(zone));
  assert.equal(d.inherited, true);
  assert.equal(d.host, '_dmarc.example.com');
});
test('inspect: DKIM missing selector and present key', async () => {
  const p = spkiB64(rsa(2048));
  const zone = { 'selector1._domainkey.example.com': { TXT: [`v=DKIM1; k=rsa; p=${p}`] } };
  const r = mockResolver(zone);
  const hit = await MF.inspectDkim('example.com', 'selector1', r);
  assert.equal(hit.analysis.key.bits, 2048);
  assert.ok(hit.strings.length >= 2);
  assert.equal((await MF.inspectDkim('example.com', 'nope', r)).missing, true);
});

test('inspect: failed lookups come back as errors with empty findings, never throw', async () => {
  const down = MF.makeResolver(async () => ({ ok: false, status: 503, json: async () => ({}) }));
  assert.match((await MF.inspectSpf('example.com', down)).error, /HTTP 503/);
  assert.match((await MF.inspectDmarc('example.com', down)).error, /HTTP 503/);
  const k = await MF.inspectDkim('example.com', 'selector1', down);
  assert.match(k.error, /HTTP 503/);
  assert.deepEqual(k.findings, []);
  assert.equal(k.selector, 'selector1');
});

// ---------- DoH client ----------
test('DoH resolver parses Cloudflare answers and falls back to Google', async () => {
  const calls = [];
  const fetchImpl = async url => {
    calls.push(url);
    if (url.startsWith('https://cloudflare-dns.com')) throw new TypeError('Failed to fetch');
    return { ok: true, json: async () => ({ Status: 0, AD: true, Answer: [{ name: 'example.com.', type: 16, TTL: 120, data: 'v=spf1 -all' }] }) };
  };
  const resolve = MF.makeResolver(fetchImpl);
  const r = await resolve('example.com', 'TXT');
  assert.equal(r.provider, 'Google');
  assert.equal(calls.length, 2);
  assert.deepEqual(MF.txtRecords(r).map(x => x.value), ['v=spf1 -all']);
  assert.equal(MF.txtRecords(r)[0].boundariesUnknown, true);
  await resolve('EXAMPLE.com', 'TXT');
  assert.equal(calls.length, 2, 'cached');
});
test('DoH resolver gives up on a provider that does not answer within the timeout', async () => {
  const hang = (url, init) => new Promise((_, reject) => init.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' }))));
  const r = await MF.makeResolver(hang, { timeoutMs: 30 })('example.com', 'TXT');
  assert.equal(r.status, 'ERROR');
  assert.match(r.error, /Cloudflare: timed out; Google: timed out/);
});
test('DoH resolver: quoted multi-string data, NXDOMAIN, total failure', async () => {
  const ok = MF.makeResolver(async () => ({ ok: true, json: async () => ({ Status: 0, Answer: [{ name: 'x.example.com.', type: 16, TTL: 60, data: '"v=DKIM1; p=AB" "CD"' }] }) }));
  assert.equal(MF.txtRecords(await ok('x.example.com', 'TXT'))[0].value, 'v=DKIM1; p=ABCD');
  const nx = MF.makeResolver(async () => ({ ok: true, json: async () => ({ Status: 3 }) }));
  assert.equal((await nx('nope.example.com', 'TXT')).status, 'NXDOMAIN');
  const down = MF.makeResolver(async () => { throw new TypeError('Failed to fetch'); });
  const r = await down('example.com', 'TXT');
  assert.equal(r.status, 'ERROR');
  assert.match(r.error, /Cloudflare.*Google/);
});

// ---------- boundaries: each limit tested on both sides ----------
// An RSA public key of exactly `bits` bits, built by hand (sizes OpenSSL will not generate).
function rsaOfBits(bits, exponent = 65537) {
  const n = Buffer.alloc(Math.ceil(bits / 8), 0xff);
  n[0] = 0xff >> (n.length * 8 - bits);
  const int = b => { const v = b[0] & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b; return Buffer.concat([Buffer.from([0x02]), derLen(v.length), v]); };
  const derLen = l => (l < 128 ? Buffer.from([l]) : l < 256 ? Buffer.from([0x81, l]) : Buffer.from([0x82, l >> 8, l & 255]));
  const e = Buffer.from(exponent.toString(16).padStart(6, '0'), 'hex');
  const body = Buffer.concat([int(n), int(e)]);
  return MF.bytesToB64(MF.pkcs1ToSpki(Buffer.concat([Buffer.from([0x30]), derLen(body.length), body])));
}
test('boundary: RSA key sizes 1023/1024, 2047/2048 and 4096/4097 bits', () => {
  const sev = bits => { const r = MF.analyzeDkim(`v=DKIM1; p=${rsaOfBits(bits)}`); assert.equal(r.key.bits, bits); return r.findings.filter(f => /^dkim-(weak|1024|huge|rsa)$/.test(f.code)).map(f => `${f.code}:${f.sev}`); };
  assert.deepEqual(sev(1023), ['dkim-weak:error']);
  assert.deepEqual(sev(1024), ['dkim-1024:warn']);
  assert.deepEqual(sev(2047), ['dkim-1024:warn']);
  assert.deepEqual(sev(2048), ['dkim-rsa:ok']);
  assert.deepEqual(sev(4096), ['dkim-rsa:ok']);
  assert.deepEqual(sev(4097), ['dkim-huge:warn']);
  assert.equal(sevOf(MF.analyzeDkim(`v=DKIM1; p=${rsaOfBits(2048, 1)}`), 'dkim-exponent'), 'error');
  assert.equal(sevOf(MF.analyzeDkim(`v=DKIM1; p=${rsaOfBits(2048, 3)}`), 'dkim-exponent'), undefined);
});
test('boundary: SPF direct lookups 7 is a note, 8 a warning, 10 still allowed, 11 an error', () => {
  const rec = n => `v=spf1 ${Array.from({ length: n }, (_, i) => `include:s${i}.example.com`).join(' ')} -all`;
  assert.equal(sevOf(MF.analyzeSpf(rec(7)), 'spf-lookups'), 'info');
  assert.equal(sevOf(MF.analyzeSpf(rec(8)), 'spf-lookups'), 'warn');
  assert.equal(sevOf(MF.analyzeSpf(rec(10)), 'spf-lookups'), 'warn');
  assert.equal(sevOf(MF.analyzeSpf(rec(11)), 'spf-lookups'), 'error');
});
test('boundary: SPF of 255/256 bytes (one or two strings) and 450/451 bytes (length warning)', () => {
  const rec = bytes => `v=spf1 x=${'a'.repeat(bytes - 14)} -all`;
  for (const b of [255, 256, 450, 451]) assert.equal(MF.byteLen(rec(b)), b);
  assert.equal(sevOf(MF.analyzeSpf(rec(255)), 'spf-strings'), undefined);
  assert.equal(sevOf(MF.analyzeSpf(rec(256)), 'spf-strings'), 'info');
  assert.equal(sevOf(MF.analyzeSpf(rec(450)), 'spf-length'), undefined);
  assert.equal(sevOf(MF.analyzeSpf(rec(451)), 'spf-length'), 'warn');
});
test('boundary: domain names of 253/254 characters', () => {
  const name = len => `${'a'.repeat(len - 192)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(63)}`;
  assert.equal(name(253).length, 253);
  assert.equal(MF.checkDomain(name(253)), null);
  assert.match(MF.checkDomain(name(254)), /253/);
});
test('boundary: very broad SPF ranges, ip4 /7 and /8, ip6 /23 and /24', () => {
  assert.equal(sevOf(MF.analyzeSpf('v=spf1 ip4:0.0.0.0/7 -all'), 'spf-ip-broad'), 'warn');
  assert.equal(sevOf(MF.analyzeSpf('v=spf1 ip4:0.0.0.0/8 -all'), 'spf-ip-broad'), undefined);
  assert.equal(sevOf(MF.analyzeSpf('v=spf1 ip6:::/23 -all'), 'spf-ip-broad'), 'warn');
  assert.equal(sevOf(MF.analyzeSpf('v=spf1 ip6:::/24 -all'), 'spf-ip-broad'), undefined);
});
test('boundary: DMARC pct 99/100/101 and sp equal to p', () => {
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=reject; pct=99'), 'dmarc-pct'), 'info');
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=reject; pct=100'), 'dmarc-pct'), undefined, 'pct=100 is valid and needs no note');
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=reject; pct=101'), 'dmarc-pct'), 'error');
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=quarantine; sp=quarantine'), 'dmarc-sp-weak'), undefined);
  assert.equal(sevOf(MF.analyzeDmarc('v=DMARC1; p=quarantine; sp=none'), 'dmarc-sp-weak'), 'warn');
});
test('boundary: the SPF tree at 8, 9, 10 and 11 lookups', async () => {
  const tree = n => {
    const zone = { 'example.com': { TXT: [`v=spf1 ${Array.from({ length: n }, (_, i) => `include:s${i}.example.net`).join(' ')} -all`] } };
    for (let i = 0; i < n; i++) zone[`s${i}.example.net`] = { TXT: ['v=spf1 ip4:192.0.2.1 ~all'] };
    return MF.walkSpf('example.com', mockResolver(zone));
  };
  assert.equal(sevOf(await tree(8), 'spf-tree-lookups'), 'ok');
  assert.equal(sevOf(await tree(9), 'spf-tree-lookups'), 'warn');
  assert.equal(sevOf(await tree(10), 'spf-tree-lookups'), 'warn');
  assert.equal(sevOf(await tree(11), 'spf-tree-lookups'), 'error');
});
test('boundary: two void lookups warn, three are an error; 10 MX hosts are allowed, 11 are not', async () => {
  const voids = n => MF.walkSpf('example.com', mockResolver({ 'example.com': { TXT: [`v=spf1 ${Array.from({ length: n }, (_, i) => `a:gone${i}.example.com`).join(' ')} -all`] } }));
  assert.equal(sevOf(await voids(2), 'spf-voids'), 'warn');
  assert.equal(sevOf(await voids(3), 'spf-voids'), 'error');
  const mx = async n => {
    const w = await MF.walkSpf('example.com', mockResolver({ 'example.com': { TXT: ['v=spf1 mx -all'], MX: Array.from({ length: n }, (_, i) => `10 mx${i}.example.com.`) } }));
    return w.root.children[0].error;
  };
  assert.equal(await mx(10), undefined);
  assert.match(await mx(11), /more than 10 MX hosts/);
});
