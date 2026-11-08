/*
  MailForge core: SPF, DKIM and DMARC parsing, validation, safe repair, DNS output and
  DNS-over-HTTPS inspection. No DOM access, so the page and the Node tests share this file.

  SPDX-License-Identifier: GPL-3.0-or-later
*/
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.MailForge = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const utf8 = new TextEncoder();
  const byteLen = s => utf8.encode(s).length;
  const F = (sev, code, title, detail = '', extra = {}) => ({ sev, code, title, detail, ...extra });
  const RFC = {
    spf: 'https://www.rfc-editor.org/rfc/rfc7208',
    dkim: 'https://www.rfc-editor.org/rfc/rfc6376',
    dkimCrypto: 'https://www.rfc-editor.org/rfc/rfc8301',
    ed25519: 'https://www.rfc-editor.org/rfc/rfc8463',
    dmarc: 'https://www.rfc-editor.org/rfc/rfc7489',
    // RFC 9989 replaced RFC 7489 in May 2026; RFC 9990 took over its aggregate reports.
    dmarcbis: 'https://www.rfc-editor.org/rfc/rfc9989',
    dmarcReports: 'https://www.rfc-editor.org/rfc/rfc9990',
    dns: 'https://www.rfc-editor.org/rfc/rfc1035',
    doh: 'https://www.rfc-editor.org/rfc/rfc8484'
  };
  const ref = (doc, section) => `${RFC[doc]}${section ? `#${/^[A-Z]/.test(section) ? 'appendix' : 'section'}-${section}` : ''}`;

  // ---------- TXT strings ----------
  // One TXT record holds one or more character-strings of at most 255 bytes each (RFC 1035 §3.3).
  // SPF (RFC 7208 §3.3) and DKIM (RFC 6376 §3.6.2.2) join the strings with nothing in between.
  const TXT_STRING_MAX = 255;

  function splitTxt(value, max = TXT_STRING_MAX) {
    const out = [];
    let cur = '', curBytes = 0;
    for (const ch of String(value)) {
      const b = byteLen(ch);
      if (curBytes + b > max) { out.push(cur); cur = ''; curBytes = 0; }
      cur += ch; curBytes += b;
    }
    if (cur || !out.length) out.push(cur);
    return out;
  }
  function quoteTxtString(s) { return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`; }
  function formatTxt(value) {
    const strings = splitTxt(value);
    return { strings, presentation: strings.map(quoteTxtString).join(' '), bytes: byteLen(value) };
  }

  // Reads a TXT value as people paste it: a bare value, one or more "quoted" strings, a zone-file
  // line (name ttl IN TXT ...), or BIND output with ( ) and ; comments. Bare text with no quotes is
  // taken as one value, because that is what people mean, even though a zone file would split it.
  function parseTxtPresentation(input) {
    let s = String(input ?? '').trim();
    const warnings = [];
    let name = null, ttl = null;
    const zone = s.match(/^((?:[^\s"();]+\s+){0,4}?)TXT\s+/i);
    if (zone) {
      for (const tok of zone[1].split(/\s+/).filter(Boolean)) {
        if (/^\d+$/.test(tok)) ttl = Number(tok);
        else if (!/^(IN|CH|HS)$/i.test(tok)) name = tok;
      }
      s = s.slice(zone[0].length);
    }
    if (!s.includes('"')) {
      const bare = s.replace(/^\(\s*|\s*\)$/g, '').trim();
      return { strings: bare ? [bare] : [], value: bare, quoted: false, name, ttl, warnings };
    }
    const strings = [];
    let i = 0;
    while (i < s.length) {
      const c = s[i];
      if (/\s/.test(c) || c === '(' || c === ')') { i++; continue; }
      if (c === ';') { while (i < s.length && s[i] !== '\n') i++; continue; }
      if (c === '"') {
        i++;
        const bytes = [];
        let closed = false;
        while (i < s.length) {
          const ch = s[i];
          if (ch === '\\') {
            const d = s.slice(i + 1, i + 4);
            if (/^\d{3}$/.test(d)) {
              if (Number(d) > 255) warnings.push(`\\${d} is not a valid byte escape`);
              bytes.push(Number(d) & 255); i += 4; continue;
            }
            if (i + 1 < s.length) { const cp = String.fromCodePoint(s.codePointAt(i + 1)); bytes.push(...utf8.encode(cp)); i += 1 + cp.length; continue; }
            i++; continue;
          }
          if (ch === '"') { closed = true; i++; break; }
          const cp = String.fromCodePoint(s.codePointAt(i));
          bytes.push(...utf8.encode(cp)); i += cp.length;
        }
        if (!closed) warnings.push('A quoted string is missing its closing quote.');
        if (bytes.length > TXT_STRING_MAX) warnings.push(`One string is ${bytes.length} bytes; DNS allows at most 255 bytes per string, so servers will reject or truncate it.`);
        strings.push(new TextDecoder().decode(Uint8Array.from(bytes)));
        continue;
      }
      let j = i;
      while (j < s.length && !/[\s"();]/.test(s[j])) j++;
      strings.push(s.slice(i, j));
      warnings.push(`Text outside quotes ("${s.slice(i, j)}") is a separate string in zone-file syntax.`);
      i = j;
    }
    return { strings, value: strings.join(''), quoted: true, name, ttl, warnings };
  }

  // ---------- names ----------
  function checkDomain(d) {
    if (!d) return 'is empty';
    const name = String(d).replace(/\.$/, '');
    if (/[^\x21-\x7e]/.test(name)) return /\s/.test(name) ? 'contains a space' : 'contains non-ASCII characters (use the punycode xn-- form)';
    if (name.length > 253) return 'is longer than 253 characters';
    const labels = name.split('.');
    for (const label of labels) {
      if (!label) return 'has an empty label (two dots in a row, or a leading dot)';
      if (label.length > 63) return `has a label longer than 63 characters ("${label.slice(0, 16)}…")`;
      if (!/^[A-Za-z0-9_-]+$/.test(label)) return `has a label with characters not allowed in a host name ("${label}")`;
      if (/^-|-$/.test(label)) return `has a label that starts or ends with a hyphen ("${label}")`;
    }
    if (labels.length < 2) return 'needs at least two labels (example.com)';
    if (/^\d+$/.test(labels[labels.length - 1])) return 'ends in a numeric label (an IP address is not a domain)';
    return null;
  }
  const MULTI_SUFFIX = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'org.nz', 'co.jp', 'com.br', 'com.mx', 'co.za', 'com.cn', 'co.in', 'com.sg', 'com.hk', 'com.tr', 'co.kr']);
  // Approximation of the organizational domain. RFC 7489 used the Public Suffix List; RFC 9989 walks
  // the DNS tree for _dmarc records instead. Neither is done here.
  function orgDomain(d) {
    const l = String(d).toLowerCase().replace(/\.$/, '').split('.');
    if (l.length <= 2) return l.join('.');
    return MULTI_SUFFIX.has(l.slice(-2).join('.')) ? l.slice(-3).join('.') : l.slice(-2).join('.');
  }

  // ---------- IP addresses ----------
  function parseIPv4(s) {
    const parts = String(s).split('.');
    if (parts.length !== 4) return null;
    let n = 0n;
    for (const x of parts) {
      if (!/^(0|[1-9]\d{0,2})$/.test(x) || Number(x) > 255) return null;
      n = (n << 8n) | BigInt(x);
    }
    return n;
  }
  function ipv4Problem(s) {
    const parts = String(s).split('.');
    if (parts.length !== 4) return `"${s}" is not an IPv4 address (needs four numbers, like 192.0.2.10)`;
    if (parts.some(x => /^0\d+$/.test(x))) return `"${s}" has a leading zero; some resolvers read that as octal, so write it without`;
    return `"${s}" is not a valid IPv4 address (each part must be 0–255)`;
  }
  function parseIPv6(input) {
    let s = String(input);
    if (!/^[0-9A-Fa-f:.]+$/.test(s) || !s.includes(':')) return null;
    if (s.includes('.')) {
      const cut = s.lastIndexOf(':');
      const v4 = parseIPv4(s.slice(cut + 1));
      if (v4 === null) return null;
      s = `${s.slice(0, cut + 1)}${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
    }
    const halves = s.split('::');
    if (halves.length > 2) return null;
    const head = halves[0] ? halves[0].split(':') : [];
    const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    if (halves.length === 1 && head.length !== 8) return null;
    if (halves.length === 2 && head.length + tail.length > 7) return null;
    const groups = [...head, ...Array(halves.length === 2 ? 8 - head.length - tail.length : 0).fill('0'), ...tail];
    let n = 0n;
    for (const g of groups) {
      if (!/^[0-9A-Fa-f]{1,4}$/.test(g)) return null;
      n = (n << 16n) | BigInt(`0x${g}`);
    }
    return n;
  }
  function formatIPv4(n) { return [24n, 16n, 8n, 0n].map(sh => String((n >> sh) & 255n)).join('.'); }
  function formatIPv6(n) {
    const g = [];
    for (let i = 7; i >= 0; i--) g.push(((n >> BigInt(i * 16)) & 0xffffn).toString(16));
    let best = -1, bestLen = 1;
    for (let i = 0; i < 8;) {
      if (g[i] !== '0') { i++; continue; }
      let j = i; while (j < 8 && g[j] === '0') j++;
      if (j - i > bestLen) { best = i; bestLen = j - i; }
      i = j;
    }
    if (best < 0) return g.join(':');
    return `${g.slice(0, best).join(':')}::${g.slice(best + bestLen).join(':')}`;
  }
  const formatIp = (n, bits) => bits === 32 ? formatIPv4(n) : formatIPv6(n);
  const hostMask = (bits, prefix) => (1n << BigInt(bits - prefix)) - 1n;
  const networkOf = (ip, bits, prefix) => ip & ~hostMask(bits, prefix) & ((1n << BigInt(bits)) - 1n);

  function rangeToCidrs(start, end, bits) {
    const out = [];
    while (start <= end) {
      let p = bits;
      while (p > 0) {
        const block = 1n << BigInt(bits - (p - 1));
        if (start % block !== 0n || start + block - 1n > end) break;
        p--;
      }
      out.push({ ip: start, prefix: p, bits });
      start += 1n << BigInt(bits - p);
    }
    return out;
  }
  // Smallest set of CIDR blocks covering exactly the union of the input blocks.
  function mergeCidrs(blocks, bits) {
    const ranges = blocks.map(b => { const s = networkOf(b.ip, bits, b.prefix); return [s, s + hostMask(bits, b.prefix)]; }).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    const merged = [];
    for (const r of ranges) {
      const last = merged[merged.length - 1];
      if (last && r[0] <= last[1] + 1n) { if (r[1] > last[1]) last[1] = r[1]; }
      else merged.push([r[0], r[1]]);
    }
    return merged.flatMap(([s, e]) => rangeToCidrs(s, e, bits));
  }

  // ---------- SPF ----------
  const SPF_MECHS = ['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists'];
  const LOOKUP_MECHS = new Set(['include', 'a', 'mx', 'ptr', 'exists']);
  const QUALIFIER = { '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' };

  function editDistance(a, b) {
    const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
    for (let j = 1; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    return d[a.length][b.length];
  }
  function checkDomainSpec(spec, isExp = false) {
    if (!spec.includes('%')) return checkDomain(spec);
    const macro = /%(?:\{([A-Za-z])(\d*)(r?)([.\-+,/_=]*)\}|%|_|-)/g;
    let m;
    while ((m = macro.exec(spec))) {
      if (!m[1]) continue;
      const letter = m[1].toLowerCase();
      if (!'slodiphcrtv'.includes(letter)) return `uses an unknown macro letter %{${m[1]}}`;
      if ('crt'.includes(letter) && !isExp) return `uses %{${m[1]}}, which is only allowed in exp=`;
    }
    const rest = spec.replace(macro, 'x');
    if (rest.includes('%')) return 'has a malformed macro (valid forms: %{i}, %{d2}, %{ir}, %%, %_, %-)';
    if (/[^\x21-\x7e]/.test(rest)) return 'contains spaces or non-ASCII characters';
    return null;
  }

  function parseSpfTerm(raw) {
    const t = { raw, kind: 'mech', q: '', name: '', value: '', error: null };
    const mod = raw.match(/^([A-Za-z][A-Za-z0-9_.-]*)=(.*)$/);
    if (mod) {
      t.kind = 'mod'; t.name = mod[1].toLowerCase(); t.value = mod[2];
      if (SPF_MECHS.includes(t.name)) { t.error = `"${raw}" uses "=" where the ${t.name} mechanism needs ":" (${t.name}:${t.value})`; return t; }
      if (t.name === 'redirect' || t.name === 'exp') {
        if (!t.value) t.error = `${t.name}= needs a domain`;
        else { const e = checkDomainSpec(t.value, t.name === 'exp'); if (e) t.error = `${t.name}=${t.value}: the domain ${e}`; else t.domain = t.value; }
      } else if (!/^[\x21-\x7e]*$/.test(t.value)) t.error = `modifier ${t.name} has an invalid value`;
      return t;
    }
    const m = raw.match(/^([+\-~?]?)([A-Za-z][A-Za-z0-9]*)(.*)$/);
    if (!m) { t.error = `"${raw}" is not a valid SPF term`; return t; }
    t.q = m[1]; t.name = m[2].toLowerCase();
    const rest = m[3];
    t.value = rest.replace(/^:/, '');
    if (!SPF_MECHS.includes(t.name)) {
      const near = SPF_MECHS.concat('redirect').find(x => x.length > 2 && editDistance(x, t.name) <= 2);
      t.error = `unknown mechanism "${t.name}"${near ? ` (did you mean ${near}?)` : ''}`;
      return t;
    }
    const domainErr = d => { const e = checkDomainSpec(d); return e ? `${t.name}:${d}: the domain ${e}` : null; };
    switch (t.name) {
      case 'all':
        if (rest) t.error = `"all" takes no value ("${raw}")`;
        break;
      case 'include': case 'exists':
        if (!rest.startsWith(':') || rest.length < 2) { t.error = `${t.name} needs a domain (${t.name}:example.com)`; break; }
        t.domain = rest.slice(1); t.error = domainErr(t.domain);
        break;
      case 'a': case 'mx': {
        const mm = rest.match(/^(?::([^/]*))?(?:\/(\d+))?(?:\/\/(\d+))?$/);
        if (!mm) { t.error = `"${raw}" has a malformed domain or prefix length (forms: ${t.name}, ${t.name}:host, ${t.name}/24, ${t.name}:host/24//64)`; break; }
        if (mm[1] !== undefined) { t.domain = mm[1]; t.error = mm[1] ? domainErr(mm[1]) : `"${raw}" has an empty domain after ":"`; if (t.error) break; }
        if (mm[2] !== undefined) { t.cidr4 = Number(mm[2]); if (t.cidr4 > 32 || /^0\d/.test(mm[2])) { t.error = `"${raw}": IPv4 prefix length must be 0–32`; break; } }
        if (mm[3] !== undefined) { t.cidr6 = Number(mm[3]); if (t.cidr6 > 128 || /^0\d/.test(mm[3])) { t.error = `"${raw}": IPv6 prefix length must be 0–128`; break; } }
        break;
      }
      case 'ptr':
        if (rest) { if (!rest.startsWith(':') || rest.length < 2) t.error = `"${raw}" is malformed (ptr or ptr:example.com)`; else { t.domain = rest.slice(1); t.error = domainErr(t.domain); } }
        break;
      case 'ip4': case 'ip6': {
        const v6 = t.name === 'ip6';
        const mm = rest.match(/^:([^/]+)(?:\/(\d+))?$/);
        if (!mm) { t.error = `${t.name} needs an address (${v6 ? 'ip6:2001:db8::/32' : 'ip4:192.0.2.0/24'})`; break; }
        const ip = v6 ? parseIPv6(mm[1]) : parseIPv4(mm[1]);
        if (ip === null) {
          if (!v6 && parseIPv6(mm[1]) !== null) t.error = `"${mm[1]}" is an IPv6 address; use ip6:`;
          else if (v6 && parseIPv4(mm[1]) !== null) t.error = `"${mm[1]}" is an IPv4 address; use ip4:`;
          else t.error = v6 ? `"${mm[1]}" is not a valid IPv6 address` : ipv4Problem(mm[1]);
          break;
        }
        const bits = v6 ? 128 : 32;
        const prefix = mm[2] === undefined ? bits : Number(mm[2]);
        if (mm[2] !== undefined && (prefix > bits || /^0\d/.test(mm[2]))) { t.error = `"${raw}": prefix /${mm[2]} is out of range (0–${bits})`; break; }
        Object.assign(t, { ip, bits, prefix, addr: mm[1] });
        break;
      }
    }
    return t;
  }
  function parseSpf(input) {
    const value = String(input ?? '').trim();
    const out = { value, ok: false, version: null, terms: [], findings: [] };
    const vm = value.match(/^v=spf1(?=[ \t]|$)/i);
    if (!vm) {
      out.findings.push(F('error', 'spf-version', /^v=spf/i.test(value) ? 'Wrong or malformed SPF version' : 'Not an SPF record',
        'An SPF record must begin with exactly "v=spf1" followed by a space. Receivers ignore TXT records that do not.', { ref: ref('spf', '4.5') }));
      return out;
    }
    out.ok = true; out.version = vm[0];
    out.terms = value.slice(vm[0].length).split(/[ \t\r\n]+/).filter(Boolean).map(parseSpfTerm);
    return out;
  }
  function termString(t) {
    if (t.error) return t.raw;
    if (t.kind === 'mod') return `${t.name}=${t.value}`;
    let s = t.q + t.name;
    if (t.ip !== undefined) return `${s}:${formatIp(networkOf(t.ip, t.bits, t.prefix), t.bits)}${t.prefix < t.bits ? `/${t.prefix}` : ''}`;
    if (t.domain !== undefined) s += `:${t.domain}`;
    if (t.cidr4 !== undefined) s += `/${t.cidr4}`;
    if (t.cidr6 !== undefined) s += `//${t.cidr6}`;
    return s;
  }
  const lowerIfPlain = d => (d && !d.includes('%') ? d.toLowerCase().replace(/\.$/, '') : d || '');
  function termKey(t) {
    if (t.ip !== undefined) return `${t.name}:${networkOf(t.ip, t.bits, t.prefix)}/${t.prefix}`;
    return `${t.name}:${lowerIfPlain(t.domain)}/${t.cidr4 ?? ''}//${t.cidr6 ?? ''}`;
  }
  const covers = (o, t) => o.bits === t.bits && o.prefix <= t.prefix && networkOf(t.ip, t.bits, o.prefix) === networkOf(o.ip, o.bits, o.prefix);

  // Mechanisms that can never change the result: after the first "all", a repeat of an earlier
  // mechanism (it would see the same DNS answers), or an address range an earlier one already covers.
  function deadTerms(terms) {
    const dead = new Map(), seen = new Map(), ips = [];
    let allSeen = false;
    terms.forEach((t, i) => {
      if (t.kind !== 'mech' || t.error) return;
      if (allSeen) { dead.set(i, 'comes after "all", so it is never evaluated'); return; }
      if (t.name === 'all') { allSeen = true; return; }
      const key = termKey(t);
      if (seen.has(key)) { dead.set(i, `repeats ${terms[seen.get(key)].raw}, which is evaluated first`); return; }
      seen.set(key, i);
      if (t.ip !== undefined) {
        const cover = ips.find(o => covers(o, t));
        if (cover) { dead.set(i, `is already covered by the earlier ${cover.raw}`); return; }
        ips.push(t);
      }
    });
    return dead;
  }
  function spfJoinProblems(strings) {
    const out = [];
    const mech = /^[+\-~?]?(all\b|include:|a\b|a[:/]|mx\b|mx[:/]|ip4:|ip6:|exists:|ptr\b|redirect=|exp=)/i;
    for (let i = 1; i < strings.length; i++) {
      const a = strings[i - 1], b = strings[i];
      if (!a || !b || /\s$/.test(a) || /^\s/.test(b)) continue;
      const tail = a.split(/\s+/).pop(), head = b.split(/\s+/)[0];
      if (tail && mech.test(head) && /^[+\-~?]?([a-z0-9]+[:=/]|all$|a$|mx$|ptr$)/i.test(tail)) out.push(`${tail}${head}`);
    }
    return out;
  }

  function analyzeSpf(input, opts = {}) {
    const p = parseSpf(input);
    const f = p.findings;
    const res = { ...p, lookups: 0, lookupTerms: [], bytes: byteLen(p.value), dead: new Map() };
    if (!p.ok) return res;
    const value = p.value, terms = p.terms;
    if (/[^\x20-\x7e]/.test(value.replace(/[\t\r\n]/g, ' '))) f.push(F('error', 'spf-ascii', 'Contains non-ASCII characters', 'SPF records must be plain ASCII. Look for smart quotes, non-breaking spaces or accented letters pasted from a document.', { ref: ref('spf', '3') }));
    if (opts.strings && opts.strings.length > 1) {
      for (const joined of spfJoinProblems(opts.strings)) f.push(F('error', 'spf-join', 'Two terms run together across a string boundary', `The strings are joined with no space (RFC 7208 §3.3), producing "${joined}". End the first string with a space.`, { ref: ref('spf', '3.3') }));
    }
    for (const t of terms) if (t.error) f.push(F('error', 'spf-syntax', 'Invalid term', `${t.error}. A syntax error anywhere, even after "all", makes receivers return permerror for the whole record.`, { term: t.raw, ref: ref('spf', '4.6') }));
    const mods = name => terms.filter(t => t.kind === 'mod' && t.name === name);
    const redirects = mods('redirect'), exps = mods('exp');
    if (redirects.length > 1) f.push(F('error', 'spf-dup-mod', 'redirect= appears more than once', 'Each modifier may appear only once; receivers return permerror.', { ref: ref('spf', '6') }));
    if (exps.length > 1) f.push(F('error', 'spf-dup-mod', 'exp= appears more than once', 'Each modifier may appear only once; receivers return permerror.', { ref: ref('spf', '6') }));
    const allIdx = terms.findIndex(t => t.kind === 'mech' && t.name === 'all' && !t.error);
    const evaluated = allIdx >= 0 ? terms.slice(0, allIdx + 1) : terms;
    for (const t of evaluated) if (t.kind === 'mech' && !t.error && LOOKUP_MECHS.has(t.name)) { res.lookups++; res.lookupTerms.push(t.raw); }
    const redirectLive = allIdx < 0 && redirects.length === 1 && !redirects[0].error;
    if (redirectLive) { res.lookups++; res.lookupTerms.push(redirects[0].raw); }

    if (allIdx >= 0) {
      const all = terms[allIdx], q = all.q || '+';
      const after = terms.slice(allIdx + 1).filter(t => t.kind === 'mech');
      if (after.length) f.push(F('warn', 'spf-after-all', 'Mechanisms after "all" are never evaluated', `${after.map(t => t.raw).join(' ')}: "all" always matches, so evaluation stops there. Move them before ${all.raw} or remove them.`, { ref: ref('spf', '5.1') }));
      if (redirects.length) f.push(F('warn', 'spf-redirect-ignored', 'redirect= is ignored because the record has "all"', 'A redirect only applies when no mechanism matches, and "all" always matches.', { ref: ref('spf', '6.1') }));
      if (q === '+') f.push(F('error', 'spf-pass-all', `"${all.raw}" lets any server pass SPF`, 'Every IP address on the internet is authorized to send as this domain. Use ~all (softfail) or -all (fail).', { ref: ref('spf', '5.1') }));
      else if (q === '?') f.push(F('warn', 'spf-neutral-all', '"?all" gives no protection', 'Unlisted servers get a neutral result, which receivers treat like having no SPF at all. Use ~all or -all once the list of senders is complete.', { ref: ref('spf', '8.2') }));
      else if (q === '~') f.push(F('info', 'spf-softfail-all', 'Ends in ~all (softfail)', 'Unlisted servers soft-fail: usually accepted but marked. With an enforcing DMARC policy this is the common choice; -all is stricter.', { ref: ref('spf', '8.5') }));
      else f.push(F('ok', 'spf-fail-all', 'Ends in -all (fail)', 'Servers not listed fail SPF.', { ref: ref('spf', '8.4') }));
    } else if (redirectLive) {
      f.push(F('info', 'spf-redirect', `Policy is delegated to ${redirects[0].domain}`, 'When nothing else in this record matches, the result comes from that domain\'s SPF record, including its "all".', { ref: ref('spf', '6.1') }));
    } else {
      f.push(F('warn', 'spf-no-all', 'No "all" mechanism and no redirect', 'Servers not listed get a neutral result (the same as ?all): nothing is rejected or marked. End the record with ~all or -all.', { ref: ref('spf', '4.7') }));
    }

    if (res.lookups > 10) f.push(F('error', 'spf-lookups', `${res.lookups} DNS lookups: over the limit of 10`, `Receivers stop at 10 lookups and return permerror, so SPF fails for everyone. Counted: ${res.lookupTerms.join(' ')}.`, { ref: ref('spf', '4.6.4') }));
    else if (res.lookups >= 8) f.push(F('warn', 'spf-lookups', `${res.lookups} of 10 DNS lookups used by this record alone`, 'Each include also spends lookups inside the included record. Use Inspect to count the whole tree.', { ref: ref('spf', '4.6.4') }));
    else if (res.lookups) f.push(F('info', 'spf-lookups', `${res.lookups} of 10 DNS lookups used directly`, `Counted: ${res.lookupTerms.join(' ')}. Included records spend more of the same budget; Inspect counts the full tree.`, { ref: ref('spf', '4.6.4') }));

    for (const t of terms) {
      if (t.error || t.kind !== 'mech') continue;
      if (t.name === 'ptr') f.push(F('warn', 'spf-ptr', `${t.raw}: ptr is deprecated`, 'It is slow, unreliable, and some receivers ignore it. List the addresses with ip4/ip6 or use a or include instead.', { ref: ref('spf', '5.5'), term: t.raw }));
      if (t.ip !== undefined) {
        if (t.prefix === 0) f.push(F('error', 'spf-ip-all', `${t.raw} matches every ${t.bits === 32 ? 'IPv4' : 'IPv6'} address`, 'A /0 range authorizes the whole internet, the same as +all.', { term: t.raw }));
        else if ((t.bits === 32 && t.prefix < 8) || (t.bits === 128 && t.prefix < 24)) f.push(F('warn', 'spf-ip-broad', `${t.raw} is an extremely large range`, 'Authorize only the addresses that actually send your mail.', { term: t.raw }));
        if (networkOf(t.ip, t.bits, t.prefix) !== t.ip) f.push(F('warn', 'spf-ip-hostbits', `${t.raw} has host bits set`, `SPF compares only the first ${t.prefix} bits, so this matches ${termString(t).replace(/^[+\-~?]?ip[46]:/, '')}. Writing the network address avoids confusion.`, { term: t.raw }));
      }
      if (t.name === 'mx') f.push(F('info', 'spf-mx', `${t.raw} depends on your MX hosts`, 'It costs one lookup plus an address lookup per MX host, and receivers give permerror if there are more than 10 MX hosts. Inbound MX hosts (for example a filtering service) often do not send outbound mail.', { ref: ref('spf', '4.6.4'), term: t.raw }));
      if (t.domain && t.domain.includes('%')) f.push(F('info', 'spf-macro', `${t.raw} uses macros`, 'Macros are expanded per message, so MailForge cannot check where they point.', { ref: ref('spf', '7'), term: t.raw }));
    }
    for (const t of terms) if (t.kind === 'mod' && !t.error && !['redirect', 'exp'].includes(t.name)) f.push(F('info', 'spf-unknown-mod', `Unknown modifier ${t.name}=`, 'Receivers ignore modifiers they do not recognize.', { ref: ref('spf', '6'), term: t.raw }));
    res.dead = deadTerms(terms);
    for (const [i, why] of res.dead) if (i < allIdx || allIdx < 0) f.push(F('warn', 'spf-dead', `${terms[i].raw} has no effect`, `It ${why}.`, { term: terms[i].raw }));

    if (res.bytes > 450) f.push(F('warn', 'spf-length', `${res.bytes} bytes is long for SPF`, 'Keep the whole DNS answer under 512 bytes so it is not truncated over UDP (RFC 7208 §3.4). Remove unused entries, or move a group of senders to a subdomain and include it.', { ref: ref('spf', '3.4') }));
    else if (res.bytes > TXT_STRING_MAX) f.push(F('info', 'spf-strings', `${res.bytes} bytes: needs ${splitTxt(value).length} strings in one TXT record`, 'A single DNS string holds at most 255 bytes. MailForge\'s output splits it for you; receivers join the strings back together.', { ref: ref('spf', '3.3') }));
    if (!f.some(x => x.sev === 'error' || x.sev === 'warn')) f.push(F('ok', 'spf-syntax-ok', 'Syntax checks passed', 'This checks the text of the record only. It does not prove the listed servers are yours or that included records are healthy; use Inspect for those.'));
    return res;
  }

  function repairSpf(input) {
    const p = parseSpf(input);
    const changes = [], blocked = [];
    if (!p.ok) { blocked.push('This is not an SPF record. It must start with v=spf1.'); return { value: null, changes, blocked, changed: false }; }
    for (const t of p.terms) if (t.error) blocked.push(`Fix by hand: ${t.error}.`);
    const redirects = p.terms.filter(t => t.kind === 'mod' && t.name === 'redirect');
    if (redirects.length > 1) blocked.push('Keep only one redirect=; MailForge cannot tell which one you meant.');
    if (p.terms.filter(t => t.kind === 'mod' && t.name === 'exp').length > 1) blocked.push('Keep only one exp=.');
    if (p.version !== 'v=spf1') changes.push({ kind: 'cosmetic', text: `Wrote "${p.version}" as "v=spf1".` });
    let terms = p.terms.map(t => {
      const s = termString(t);
      if (s === t.raw) return t;
      changes.push({ kind: 'cosmetic', text: `Rewrote ${t.raw} as ${s} (same meaning${t.ip !== undefined && networkOf(t.ip, t.bits, t.prefix) !== t.ip ? ': SPF only compares the network bits' : ''}).` });
      return parseSpfTerm(s);
    });
    const dead = deadTerms(terms);
    if (dead.size) {
      for (const [i, why] of dead) changes.push({ kind: 'dead', text: `Removed ${terms[i].raw}: it ${why}.` });
      terms = terms.filter((_, i) => !dead.has(i));
    }
    const hasAll = terms.some(t => t.kind === 'mech' && t.name === 'all' && !t.error);
    if (hasAll && redirects.length === 1 && !redirects[0].error) {
      changes.push({ kind: 'dead', text: `Removed ${redirects[0].raw}: receivers ignore redirect when the record has "all".` });
      terms = terms.filter(t => !(t.kind === 'mod' && t.name === 'redirect'));
    }
    // Merge runs of consecutive address terms that share a qualifier. Inside such a run the order
    // cannot matter, and no other mechanism sits between them, so the result is identical.
    const out = [];
    for (let i = 0; i < terms.length;) {
      const t = terms[i];
      if (t.kind !== 'mech' || t.ip === undefined || t.error) { out.push(t); i++; continue; }
      const q = t.q || '+';
      let j = i;
      while (j < terms.length && terms[j].kind === 'mech' && terms[j].ip !== undefined && !terms[j].error && (terms[j].q || '+') === q) j++;
      const run = terms.slice(i, j);
      const merged = [...mergeCidrs(run.filter(x => x.bits === 32), 32), ...mergeCidrs(run.filter(x => x.bits === 128), 128)];
      if (run.length > 1 && merged.length < run.length) {
        const next = merged.map(b => parseSpfTerm(`${t.q}${b.bits === 32 ? 'ip4' : 'ip6'}:${formatIp(b.ip, b.bits)}${b.prefix < b.bits ? `/${b.prefix}` : ''}`));
        changes.push({ kind: 'merge', text: `Combined ${run.map(x => x.raw).join(' ')} into ${next.map(x => x.raw).join(' ')}; they cover exactly the same addresses.` });
        out.push(...next);
      } else out.push(...run);
      i = j;
    }
    const value = ['v=spf1', ...out.map(termString)].join(' ');
    if (!changes.length && value !== p.value) changes.push({ kind: 'cosmetic', text: 'Normalized spacing between terms.' });
    return { value, changes, blocked, changed: value !== p.value };
  }

  // Several SPF records at one name is a permerror. This proposes one record; it always needs review.
  function mergeSpfRecords(values) {
    const parsed = values.map(parseSpf);
    const notes = [], blocked = [];
    if (parsed.some(p => !p.ok)) blocked.push('One of the inputs is not an SPF record.');
    if (parsed.some(p => p.terms.some(t => t.kind === 'mod' && t.name === 'redirect'))) blocked.push('One record uses redirect=. Merge these by hand: a redirect cannot be combined mechanically.');
    if (blocked.length) return { value: null, notes, blocked };
    const alls = parsed.map(p => p.terms.find(t => t.kind === 'mech' && t.name === 'all' && !t.error)).filter(Boolean);
    const mechs = parsed.flatMap(p => { const i = p.terms.findIndex(t => t.kind === 'mech' && t.name === 'all' && !t.error); return (i >= 0 ? p.terms.slice(0, i) : p.terms).filter(t => t.kind === 'mech'); });
    const exp = parsed.flatMap(p => p.terms.filter(t => t.kind === 'mod' && t.name === 'exp'));
    if (new Set(alls.map(a => a.q || '+')).size > 1) notes.push(`The records end differently (${alls.map(a => a.raw).join(' vs ')}). The proposal keeps ${alls[0].raw} from the first record. Decide which policy you want before publishing.`);
    if (exp.length > 1) notes.push('More than one exp= was found; only the first is kept.');
    const draft = ['v=spf1', ...mechs.map(t => t.raw), ...(exp[0] ? [exp[0].raw] : []), ...(alls[0] ? [alls[0].raw] : [])].join(' ');
    const fixed = repairSpf(draft);
    return { value: fixed.value, notes, blocked: fixed.blocked, changes: fixed.changes, needsReview: true };
  }

  // ---------- tag lists (DKIM, DMARC) ----------
  function parseTagList(value) {
    const tags = [], errors = [];
    const parts = String(value ?? '').split(';');
    for (const part of parts) {
      const s = part.trim();
      if (!s) continue;
      const m = s.match(/^([A-Za-z][A-Za-z0-9_]*)\s*=\s*([\s\S]*)$/);
      if (!m) { errors.push(`"${s}" is not a tag=value pair`); tags.push({ name: null, key: null, value: s, raw: s }); continue; }
      tags.push({ name: m[1], key: m[1].toLowerCase(), value: m[2].trim(), raw: s });
    }
    return { tags, errors };
  }
  function orderTags(tags, order, keyOf) {
    const rank = t => { const i = order.indexOf(keyOf(t)); return i < 0 ? order.length : i; };
    return tags.map((t, i) => ({ t, i })).sort((a, b) => rank(a.t) - rank(b.t) || a.i - b.i).map(x => x.t);
  }

  // ---------- DMARC ----------
  // t and psd were added by RFC 9989; pct, rf and ri are still read by RFC 7489 receivers.
  const DMARC_ORDER = ['v', 'p', 'sp', 'np', 'pct', 'rua', 'ruf', 'adkim', 'aspf', 'fo', 'rf', 'ri', 't', 'psd'];
  const DMARC_KNOWN = new Set(DMARC_ORDER);
  const POLICIES = ['none', 'quarantine', 'reject'];
  const STRENGTH = { none: 0, quarantine: 1, reject: 2 };

  function parseReportUris(v) {
    return String(v).split(',').map(s => s.trim()).filter(Boolean).map(uri => {
      const m = uri.match(/^mailto:([^!\s]+?)(?:!(\d+)([kmgt]?))?$/i);
      if (!m) return { uri, error: /^https?:/i.test(uri) ? 'only mailto: report addresses are widely supported' : 'is not a mailto: address (mailto:dmarc@example.com)' };
      const am = m[1].match(/^[^@\s]+@([^@\s]+)$/);
      if (!am) return { uri, error: 'is not a valid email address' };
      const de = checkDomain(am[1]);
      return { uri, addr: m[1], domain: am[1].toLowerCase(), error: de ? `has a domain that ${de}` : null };
    });
  }
  function parseDmarc(value) {
    const { tags, errors } = parseTagList(value);
    const map = {}, dups = [];
    for (const t of tags) if (t.key) { if (Object.prototype.hasOwnProperty.call(map, t.key)) dups.push(t); else map[t.key] = t.value; }
    return { value: String(value ?? '').trim(), tags, errors, map, dups };
  }
  function explainDmarc(map) {
    const lines = [];
    const p = (map.p || '').toLowerCase(), sp = (map.sp || '').toLowerCase();
    lines.push('A message passes DMARC when SPF passes for a domain aligned with the From address, or a DKIM signature from an aligned domain verifies.');
    if (p === 'none') lines.push('p=none: monitoring only. Receivers deliver failing mail as they normally would and send you reports.');
    if (p === 'quarantine') lines.push('p=quarantine: mail that fails DMARC should be treated as suspicious, usually delivered to junk or quarantined.');
    if (p === 'reject') lines.push('p=reject: mail that fails DMARC should be refused during delivery.');
    if (sp && POLICIES.includes(sp)) lines.push(`sp=${sp}: subdomains (such as mail.example.com) get ${sp} instead of the main policy.`);
    else if (p) lines.push(`Subdomains inherit p=${p} (no sp tag).`);
    const np = (map.np || '').toLowerCase();
    if (np && POLICIES.includes(np)) lines.push(`np=${np}: subdomains that do not exist in DNS get ${np} (RFC 9989; older receivers ignore np).`);
    if (map.pct !== undefined && map.pct !== '100') lines.push(`pct=${map.pct}: the policy applies to ${map.pct}% of failing mail; the rest is handled one step softer (RFC 7489 receivers only; RFC 9989 removed pct).`);
    if ((map.t || '').toLowerCase() === 'y') lines.push('t=y: test mode. Receivers that follow RFC 9989 apply one step softer than the policy; older receivers ignore t.');
    lines.push(`Alignment: DKIM ${map.adkim === 's' ? 'strict (d= must equal the From domain exactly)' : 'relaxed (d= may be a subdomain of the same organization)'}, SPF ${map.aspf === 's' ? 'strict (envelope domain must equal the From domain exactly)' : 'relaxed (envelope domain may be a subdomain of the same organization)'}.`);
    if (map.rua) lines.push(`Daily aggregate reports go to ${map.rua}.`);
    if (map.ruf) lines.push(`Failure reports (copies of failing messages' details) go to ${map.ruf}. Few providers send these.`);
    return lines;
  }
  function analyzeDmarc(value, opts = {}) {
    const p = parseDmarc(value), f = [], m = p.map;
    const domain = opts.domain ? String(opts.domain).toLowerCase().replace(/\.$/, '') : null;
    const first = p.tags[0];
    if (!p.value) { f.push(F('error', 'dmarc-empty', 'Empty record')); return { ...p, findings: f, explain: [] }; }
    if (!first || first.key !== 'v') f.push(F('error', 'dmarc-version', 'The record must start with v=DMARC1', 'Receivers discard a DMARC record whose first tag is not v=DMARC1, so no policy applies.', { ref: ref('dmarc', '6.3') }));
    else if (first.value !== 'DMARC1') f.push(first.value.toUpperCase() === 'DMARC1'
      ? F('warn', 'dmarc-version-case', `Write "v=DMARC1", not "v=${first.value}"`, 'Some receivers compare the version exactly.', { ref: ref('dmarc', '6.3') })
      : F('error', 'dmarc-version', `Unknown version "v=${first.value}"`, 'The only DMARC version is DMARC1.', { ref: ref('dmarc', '6.3') }));
    for (const e of p.errors) f.push(F('error', 'dmarc-syntax', 'Malformed part', `${e}. Separate tags with semicolons: v=DMARC1; p=none; rua=mailto:…`, { ref: ref('dmarc', '6.4') }));
    for (const d of p.dups) f.push(F('error', 'dmarc-dup', `Tag ${d.key}= appears more than once`, 'Receivers may reject the record or use either value. Keep one.', { ref: ref('dmarc', '6.3') }));
    const pol = (m.p || '').toLowerCase();
    const ruaList = m.rua ? parseReportUris(m.rua) : [];
    const ruaValid = ruaList.some(u => !u.error);
    if (m.p === undefined) {
      if (ruaValid) f.push(F('warn', 'dmarc-no-p', 'No p= tag', 'Because a valid rua is present, receivers treat this as p=none (RFC 7489 §6.6.3). Say so explicitly: add p=none.', { ref: ref('dmarc', '6.6.3') }));
      else f.push(F('error', 'dmarc-no-p', 'No p= tag', 'p is required. Without it (and without a valid rua) receivers ignore the record. Start with p=none.', { ref: ref('dmarc', '6.3') }));
    } else if (!POLICIES.includes(pol)) f.push(F('error', 'dmarc-p', `p=${m.p} is not a valid policy`, 'Use none, quarantine or reject.', { ref: ref('dmarc', '6.3') }));
    else {
      if (p.tags[1] && p.tags[1].key !== 'p' && first && first.key === 'v') f.push(F('info', 'dmarc-p-order', 'p= is not the second tag', 'The RFC grammar lists p right after v. Most receivers accept any order, but some strict parsers do not.', { ref: ref('dmarc', '6.4') }));
      if (pol === 'none') f.push(F('warn', 'dmarc-none', 'p=none: monitoring only', 'Spoofed mail is still delivered. Read the aggregate reports, fix your legitimate senders, then move to quarantine and reject.', { ref: ref('dmarc', '6.3') }));
      else f.push(F('ok', 'dmarc-enforce', `p=${pol}: enforcing`, pol === 'reject' ? 'Receivers are asked to refuse mail that fails DMARC.' : 'Receivers are asked to junk or quarantine mail that fails DMARC.'));
      if (pol === 'reject') f.push(F('info', 'dmarc-reject-lists', 'p=reject: mind mailing lists and forwarding', 'RFC 9989 says domains whose users post to mailing lists should not publish p=reject, because list mail then fails DMARC at many receivers. With p=reject, sign every message with DKIM: SPF alone fails when mail is forwarded.', { ref: ref('dmarcbis', '7.4') }));
    }
    if (m.sp !== undefined) {
      const sp = m.sp.toLowerCase();
      if (!POLICIES.includes(sp)) f.push(F('error', 'dmarc-sp', `sp=${m.sp} is not a valid policy`, 'Use none, quarantine or reject.', { ref: ref('dmarc', '6.3') }));
      else if (POLICIES.includes(pol) && STRENGTH[sp] < STRENGTH[pol]) f.push(F('warn', 'dmarc-sp-weak', `Subdomains are less protected (sp=${sp}, p=${pol})`, 'Attackers can spoof any subdomain (for example billing.yourdomain) with a weaker result. Keep sp at least as strict as p unless a subdomain really needs it.', { ref: ref('dmarc', '6.3') }));
    }
    if (m.np !== undefined) {
      if (!POLICIES.includes(m.np.toLowerCase())) f.push(F('error', 'dmarc-np', `np=${m.np} is not a valid policy`, 'Use none, quarantine or reject.', { ref: ref('dmarcbis', '4.7') }));
      else f.push(F('info', 'dmarc-np', 'np= sets the policy for subdomains that do not exist', 'Defined in RFC 9989 (and RFC 9091 before it). Receivers that only implement RFC 7489 ignore it.', { ref: ref('dmarcbis', '4.7') }));
    }
    if (m.pct !== undefined) {
      if (!/^\d{1,3}$/.test(m.pct) || Number(m.pct) > 100) f.push(F('error', 'dmarc-pct', `pct=${m.pct} is not a whole number from 0 to 100`, '', { ref: ref('dmarc', '6.3') }));
      else if (Number(m.pct) < 100 && pol !== 'none') f.push(F('info', 'dmarc-pct', `pct=${m.pct}: policy applies to ${m.pct}% of failing mail`, 'Useful while ramping up, but only with RFC 7489 receivers. RFC 9989, which replaced RFC 7489 in May 2026, removed pct (t=y is its test mode), and receivers apply pct inconsistently, so finish at 100.', { ref: ref('dmarcbis', 'C.5.2') }));
    }
    if (m.t !== undefined) {
      const t = m.t.toLowerCase();
      if (!['y', 'n'].includes(t)) f.push(F('error', 'dmarc-t', `t=${m.t} must be y or n`, '', { ref: ref('dmarcbis', '4.7') }));
      else if (t === 'y' && POLICIES.includes(pol) && pol !== 'none') f.push(F('warn', 'dmarc-t', 't=y: test mode', 'Receivers that follow RFC 9989 apply one step softer than the policy (quarantine becomes none, reject becomes quarantine). RFC 7489 receivers ignore t= and apply the policy as written. Remove t=y when testing is done.', { ref: ref('dmarcbis', '4.7') }));
    }
    if (m.psd !== undefined) {
      const v = m.psd.toLowerCase();
      if (!['y', 'n', 'u'].includes(v)) f.push(F('error', 'dmarc-psd', `psd=${m.psd} must be y, n or u`, '', { ref: ref('dmarcbis', '4.7') }));
      else if (v === 'y') f.push(F('warn', 'dmarc-psd', 'psd=y marks a public suffix domain', 'Only operators of public suffixes (such as a top-level domain registry) publish psd=y. On an ordinary domain it changes which domain receivers treat as the organizational domain. Remove it.', { ref: ref('dmarcbis', '4.7') }));
      else if (v === 'n') f.push(F('info', 'dmarc-psd', 'psd=n: this domain is its own organizational domain', 'An RFC 9989 tag; older receivers ignore it.', { ref: ref('dmarcbis', '4.7') }));
    }
    for (const tag of ['rf', 'ri']) if (m[tag] !== undefined) f.push(F('info', 'dmarc-removed', `${tag}= was removed in RFC 9989`, 'Receivers that follow RFC 9989 ignore it; RFC 7489 receivers still read it. Keeping it does no harm.', { ref: ref('dmarcbis', 'C.5.2') }));
    for (const [tag, list] of [['rua', ruaList], ['ruf', m.ruf ? parseReportUris(m.ruf) : []]]) {
      for (const u of list) {
        if (u.error) f.push(F('error', `dmarc-${tag}`, `${tag}: ${u.uri} ${u.error}`, '', { ref: ref('dmarc', '6.2') }));
        else if (domain && orgDomain(u.domain) !== orgDomain(domain)) f.push(F('info', 'dmarc-external', `${tag} goes to another domain (${u.domain})`, `Receivers only send reports there if ${u.domain} publishes a TXT record "v=DMARC1" at ${domain}._report._dmarc.${u.domain}. Reporting services set this up for their customers; Inspect checks it.`, { ref: ref('dmarcReports', '4') }));
      }
    }
    if (m.rua === undefined) f.push(F('warn', 'dmarc-no-rua', 'No rua= report address', 'Without aggregate reports you cannot see who sends as your domain, which makes moving to enforcement guesswork.', { ref: ref('dmarc', '7.2') }));
    if (m.ruf !== undefined) f.push(F('info', 'dmarc-ruf', 'ruf= requests failure reports', 'Few large providers send them, and they can contain parts of messages, so treat the mailbox as sensitive.', { ref: ref('dmarc', '7.3') }));
    for (const tag of ['adkim', 'aspf']) if (m[tag] !== undefined) {
      const v = m[tag].toLowerCase();
      if (!['r', 's'].includes(v)) f.push(F('error', `dmarc-${tag}`, `${tag}=${m[tag]} must be r or s`, '', { ref: ref('dmarc', '6.3') }));
      else if (v === 's') f.push(F('info', `dmarc-${tag}`, `${tag}=s (strict alignment)`, `The ${tag === 'adkim' ? 'DKIM d=' : 'SPF envelope'} domain must equal the From domain exactly; mail signed or sent from a subdomain will fail.`, { ref: ref('dmarc', '3.1') }));
    }
    if (m.fo !== undefined && !/^[01ds](\s*:\s*[01ds])*$/i.test(m.fo)) f.push(F('error', 'dmarc-fo', `fo=${m.fo} is invalid`, 'Use 0, 1, d or s, separated by colons.', { ref: ref('dmarc', '6.3') }));
    if (m.fo !== undefined && m.ruf === undefined) f.push(F('info', 'dmarc-fo', 'fo= has no effect without ruf=', '', { ref: ref('dmarc', '6.3') }));
    if (m.ri !== undefined && !/^\d+$/.test(m.ri)) f.push(F('error', 'dmarc-ri', `ri=${m.ri} must be a number of seconds`, '', { ref: ref('dmarc', '6.3') }));
    if (m.rf !== undefined && m.rf.toLowerCase() !== 'afrf') f.push(F('warn', 'dmarc-rf', `rf=${m.rf}: only afrf is defined`, '', { ref: ref('dmarc', '6.3') }));
    for (const t of p.tags) if (t.key && !DMARC_KNOWN.has(t.key)) f.push(F('info', 'dmarc-unknown', `Unknown tag ${t.name}=`, 'Receivers ignore tags they do not recognize. Check the spelling.', { ref: ref('dmarc', '6.3') }));
    if (/[^\x20-\x7e]/.test(p.value)) f.push(F('error', 'dmarc-ascii', 'Contains non-ASCII characters', 'Look for smart quotes or non-breaking spaces pasted from a document.'));
    return { ...p, findings: f, explain: explainDmarc(m) };
  }
  function repairDmarc(value, opts = {}) {
    const p = parseDmarc(value);
    const changes = [], blocked = [];
    if (!p.value) return { value: null, changes, blocked: ['The record is empty.'], changed: false };
    for (const e of p.errors) blocked.push(`Fix by hand: ${e}.`);
    let tags = [];
    const byKey = new Map();
    for (const t of p.tags) {
      if (!t.key) { tags.push(t); continue; }
      if (byKey.has(t.key)) {
        if (byKey.get(t.key).value.toLowerCase() === t.value.toLowerCase()) changes.push({ kind: 'cosmetic', text: `Removed the repeated ${t.raw}.` });
        else blocked.push(`${t.key}= appears twice with different values (${byKey.get(t.key).value} and ${t.value}). Choose one.`);
        continue;
      }
      byKey.set(t.key, t); tags.push(t);
    }
    const norm = { v: v => (v.toUpperCase() === 'DMARC1' ? 'DMARC1' : v), p: v => v.toLowerCase(), sp: v => v.toLowerCase(), np: v => v.toLowerCase(), t: v => v.toLowerCase(), psd: v => v.toLowerCase(), adkim: v => v.toLowerCase(), aspf: v => v.toLowerCase(), rf: v => v.toLowerCase(), fo: v => v.replace(/\s*:\s*/g, ':'), rua: v => v.split(',').map(s => s.trim()).filter(Boolean).join(','), ruf: v => v.split(',').map(s => s.trim()).filter(Boolean).join(',') };
    tags = tags.map(t => {
      if (!t.key) return t;
      const name = DMARC_KNOWN.has(t.key) ? t.key : t.name;
      const v = norm[t.key] ? norm[t.key](t.value) : t.value;
      if (name !== t.name || v !== t.value) changes.push({ kind: 'cosmetic', text: `Wrote ${t.raw} as ${name}=${v}.` });
      return { ...t, name, value: v };
    });
    const get = k => tags.find(t => t.key === k);
    for (const [k, ok] of [['p', v => POLICIES.includes(v)], ['sp', v => POLICIES.includes(v)], ['np', v => POLICIES.includes(v)], ['t', v => /^[yn]$/.test(v)], ['psd', v => /^[ynu]$/.test(v)], ['adkim', v => /^[rs]$/.test(v)], ['aspf', v => /^[rs]$/.test(v)], ['pct', v => /^\d{1,3}$/.test(v) && Number(v) <= 100]]) {
      const t = get(k);
      if (t && !ok(t.value)) blocked.push(`${k}=${t.value} is not valid, and MailForge will not guess what you meant.`);
    }
    if (!get('v')) {
      changes.push({ kind: 'fix', text: 'Added v=DMARC1 at the start. Receivers currently ignore this record; after the change its policy takes effect.' });
      tags.unshift({ key: 'v', name: 'v', value: 'DMARC1' });
    } else if (tags[0] !== get('v')) changes.push({ kind: 'fix', text: 'Moved v=DMARC1 to the start. Receivers currently ignore this record; after the change its policy takes effect.' });
    if (!get('p')) {
      const rua = get('rua');
      if (rua && parseReportUris(rua.value).some(u => !u.error)) { changes.push({ kind: 'fix', text: 'Added p=none. With a valid rua, receivers already treat a missing p as none, so behavior does not change.' }); tags.push({ key: 'p', name: 'p', value: 'none' }); }
      else blocked.push('Add a p= policy. Start with p=none if you are not sure every legitimate sender passes yet.');
    }
    const ordered = orderTags(tags, DMARC_ORDER, t => t.key);
    if (ordered.some((t, i) => t !== tags[i]) && !changes.some(c => /Moved v=DMARC1/.test(c.text))) changes.push({ kind: 'cosmetic', text: 'Put the tags in the conventional order (v, p, sp, pct, rua, ruf, adkim, aspf…).' });
    const out = ordered.map(t => (t.key ? `${t.name}=${t.value}` : t.raw)).join('; ');
    if (!changes.length && out !== p.value) changes.push({ kind: 'cosmetic', text: 'Normalized spacing and separators.' });
    return { value: out, changes, blocked, changed: out !== p.value };
  }
  function buildDmarc(o) {
    const tags = [['v', 'DMARC1'], ['p', o.p || 'none']];
    if (o.sp) tags.push(['sp', o.sp]);
    if (o.np) tags.push(['np', o.np]);
    if (o.pct !== undefined && o.pct !== '' && String(o.pct) !== '100') tags.push(['pct', String(o.pct)]);
    const list = v => (Array.isArray(v) ? v : String(v || '').split(/[,\s]+/)).map(s => s.trim()).filter(Boolean).map(s => (/^mailto:/i.test(s) ? s : `mailto:${s}`)).join(',');
    if (list(o.rua)) tags.push(['rua', list(o.rua)]);
    if (list(o.ruf)) tags.push(['ruf', list(o.ruf)]);
    if (o.adkim === 's') tags.push(['adkim', 's']);
    if (o.aspf === 's') tags.push(['aspf', 's']);
    if (o.fo && o.fo !== '0') tags.push(['fo', o.fo]);
    if (o.ri && String(o.ri) !== '86400') tags.push(['ri', String(o.ri)]);
    for (const [k, v] of o.extra || []) tags.push([k, v]);
    return tags.map(([k, v]) => `${k}=${v}`).join('; ');
  }

  // ---------- base64 / DER ----------
  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  function b64ToBytes(s) {
    const clean = String(s).replace(/\s+/g, '');
    if (!clean) return { bytes: new Uint8Array(0) };
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) return { error: /[-_]/.test(clean) ? 'uses URL-safe base64 (- or _); DKIM needs standard base64 (+ and /)' : 'contains characters that are not base64' };
    if (clean.includes('=') ? clean.length % 4 !== 0 : clean.length % 4 === 1) return { error: 'has the wrong length for base64; a character was probably lost or added when copying' };
    const out = [];
    let buf = 0, bits = 0;
    for (const c of clean.replace(/=+$/, '')) {
      buf = ((buf << 6) | B64.indexOf(c)) & 0xffffff; bits += 6;
      if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 255); }
    }
    return { bytes: Uint8Array.from(out) };
  }
  function bytesToB64(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 3) {
      const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
      s += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + (i + 1 < bytes.length ? B64[(n >> 6) & 63] : '=') + (i + 2 < bytes.length ? B64[n & 63] : '=');
    }
    return s;
  }
  function derRead(b, pos) {
    if (pos + 2 > b.length) throw new Error('truncated');
    const tag = b[pos];
    let len = b[pos + 1], off = pos + 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n < 1 || n > 4) throw new Error('bad length');
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + b[off + i];
      off += n;
    }
    if (off + len > b.length) throw new Error('truncated');
    return { tag, start: off, end: off + len };
  }
  const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
  const OID_RSA = '2a864886f70d010101', OID_ED25519 = '2b6570';
  function parseRsaPublicKey(b, at = 0) {
    const seq = derRead(b, at);
    if (seq.tag !== 0x30) throw new Error('not a sequence');
    const n = derRead(b, seq.start), e = derRead(b, n.end);
    if (n.tag !== 0x02 || e.tag !== 0x02 || e.end !== seq.end) throw new Error('not an RSA key');
    let i = n.start;
    while (i < n.end && b[i] === 0) i++;
    const bits = i < n.end ? (n.end - i - 1) * 8 + (32 - Math.clz32(b[i])) : 0;
    let exp = 0n;
    for (let j = e.start; j < e.end; j++) exp = (exp << 8n) | BigInt(b[j]);
    return { bits, exponent: exp, end: seq.end };
  }
  function parseSpki(b) {
    const seq = derRead(b, 0);
    if (seq.tag !== 0x30 || seq.end !== b.length) throw new Error('not SPKI');
    const alg = derRead(b, seq.start);
    if (alg.tag !== 0x30) throw new Error('not SPKI');
    const oid = derRead(b, alg.start);
    if (oid.tag !== 0x06) throw new Error('not SPKI');
    const bitstr = derRead(b, alg.end);
    if (bitstr.tag !== 0x03 || b[bitstr.start] !== 0 || bitstr.end !== seq.end) throw new Error('not SPKI');
    return { oid: hex(b.subarray(oid.start, oid.end)), key: b.subarray(bitstr.start + 1, bitstr.end) };
  }
  function derLen(n) { if (n < 128) return [n]; const out = []; while (n) { out.unshift(n & 255); n >>= 8; } return [0x80 | out.length, ...out]; }
  function pkcs1ToSpki(pkcs1) {
    const alg = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
    const bit = [0x03, ...derLen(pkcs1.length + 1), 0x00, ...pkcs1];
    return Uint8Array.from([0x30, ...derLen(alg.length + bit.length), ...alg, ...bit]);
  }
  // Identifies what a p= value holds. DKIM RSA keys are published as SubjectPublicKeyInfo;
  // Ed25519 keys (RFC 8463) as the raw 32-byte key.
  function inspectKey(p) {
    const d = b64ToBytes(p);
    if (d.error) return { error: `The key ${d.error}.` };
    const b = d.bytes;
    if (!b.length) return { revoked: true };
    try {
      const spki = parseSpki(b);
      if (spki.oid === OID_RSA) { const k = parseRsaPublicKey(spki.key); if (k.end !== spki.key.length) throw new Error('trailing'); return { type: 'rsa', format: 'spki', bits: k.bits, exponent: k.exponent, bytes: b }; }
      if (spki.oid === OID_ED25519) return spki.key.length === 32 ? { type: 'ed25519', format: 'spki', raw: spki.key, bytes: b } : { error: 'The Ed25519 key has the wrong length.' };
      return { error: 'The key uses an algorithm DKIM does not support (only RSA and Ed25519).' };
    } catch { /* not SPKI */ }
    try { const k = parseRsaPublicKey(b); if (k.end === b.length) return { type: 'rsa', format: 'pkcs1', bits: k.bits, exponent: k.exponent, bytes: b }; } catch { /* not PKCS#1 */ }
    if (b.length === 32) return { type: 'ed25519', format: 'raw', raw: b, bytes: b };
    return { error: 'The key decodes, but it is not an RSA or Ed25519 public key. It may have been cut off while copying.' };
  }

  // ---------- DKIM ----------
  const DKIM_ORDER = ['v', 'k', 'h', 's', 't', 'n', 'p'];
  const DKIM_KNOWN = new Set(DKIM_ORDER);
  function parseDkim(value) {
    const { tags, errors } = parseTagList(value);
    const map = {}, dups = [];
    for (const t of tags) if (t.name) { if (Object.prototype.hasOwnProperty.call(map, t.name)) dups.push(t); else map[t.name] = t.value; }
    return { value: String(value ?? '').trim(), tags, errors, map, dups };
  }
  function checkSelector(sel) {
    if (!sel) return 'is empty';
    if (/\._domainkey/i.test(sel)) return 'should not include "._domainkey" (enter just the selector, such as selector1)';
    for (const label of sel.split('.')) {
      if (!label) return 'has an empty label';
      if (label.length > 63) return 'has a label longer than 63 characters';
      if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label)) return `has a label with characters a selector cannot use ("${label}")`;
    }
    return null;
  }
  function analyzeDkim(value, opts = {}) {
    const p = parseDkim(value), f = [], m = p.map;
    const res = { ...p, findings: f, key: null };
    if (!p.value) { f.push(F('error', 'dkim-empty', 'Empty record')); return res; }
    if (opts.selector !== undefined) { const e = checkSelector(opts.selector); if (e) f.push(F('error', 'dkim-selector', `Selector ${e}`, 'The record lives at <selector>._domainkey.<domain>.', { ref: ref('dkim', '3.1') })); }
    for (const e of p.errors) f.push(F('error', 'dkim-syntax', 'Malformed part', `${e}. Tags are separated by semicolons: v=DKIM1; k=rsa; p=…`, { ref: ref('dkim', '3.2') }));
    for (const d of p.dups) f.push(F('error', 'dkim-dup', `Tag ${d.name}= appears more than once`, 'RFC 6376 makes a record with duplicate tags invalid; verifiers ignore the whole key.', { ref: ref('dkim', '3.2') }));
    for (const t of p.tags) if (t.name && t.name !== t.key && DKIM_KNOWN.has(t.key)) f.push(F('error', 'dkim-case', `Tag "${t.name}" must be lower case`, 'DKIM tag names are case-sensitive, so verifiers do not recognize it.', { ref: ref('dkim', '3.2') }));
    if (m.v !== undefined) {
      if (p.tags[0].name !== 'v') f.push(F('error', 'dkim-v-order', 'v= must be the first tag', 'RFC 6376 requires v=, when present, to come first; verifiers may discard the key.', { ref: ref('dkim', '3.6.1') }));
      if (m.v !== 'DKIM1') f.push(F('error', 'dkim-v', `v=${m.v} must be exactly DKIM1`, 'Verifiers discard key records with any other version.', { ref: ref('dkim', '3.6.1') }));
    }
    const k = (m.k || 'rsa').toLowerCase();
    if (m.k !== undefined && !['rsa', 'ed25519'].includes(m.k)) f.push(F('error', 'dkim-k', `k=${m.k} is not a supported key type`, 'Use k=rsa or k=ed25519 (lower case).', { ref: ref('dkim', '3.6.1') }));
    if (m.h !== undefined) {
      const hs = m.h.split(':').map(s => s.trim().toLowerCase()).filter(Boolean);
      if (hs.length && hs.every(h => h === 'sha1')) f.push(F('error', 'dkim-sha1', 'h=sha1 only', 'RFC 8301 forbids SHA-1 for DKIM, so modern verifiers reject every signature this key allows. Sign with SHA-256 and remove h= (or set h=sha256).', { ref: ref('dkimCrypto', '3.1') }));
      else if (hs.includes('sha1')) f.push(F('warn', 'dkim-sha1', 'h= still allows sha1', 'If your signer uses SHA-256 (it should), remove sha1 from h=.', { ref: ref('dkimCrypto', '3.1') }));
      for (const h of hs) if (!['sha1', 'sha256'].includes(h)) f.push(F('warn', 'dkim-h', `Unknown hash "${h}" in h=`, 'Only sha256 (and the deprecated sha1) are defined.', { ref: ref('dkim', '3.6.1') }));
    }
    if (m.t !== undefined) {
      const flags = m.t.split(':').map(s => s.trim().toLowerCase());
      if (flags.includes('y')) f.push(F('warn', 'dkim-testing', 't=y: testing mode', 'Verifiers must treat signed and unsigned mail the same, so DKIM gives no protection. Remove it once signing works.', { ref: ref('dkim', '3.6.1') }));
      if (flags.includes('s')) f.push(F('info', 'dkim-t-s', 't=s: strict', 'Signatures using this key must have d= exactly equal to the signing domain (no subdomains).', { ref: ref('dkim', '3.6.1') }));
    }
    if (m.s !== undefined && !m.s.split(':').map(s => s.trim()).some(s => s === '*' || s === 'email')) f.push(F('error', 'dkim-s', `s=${m.s} excludes email`, 'The key cannot be used to verify email. Use s=email, s=*, or remove s=.', { ref: ref('dkim', '3.6.1') }));
    for (const t of p.tags) if (t.name && !DKIM_KNOWN.has(t.key)) f.push(F('info', 'dkim-unknown', `Unknown tag ${t.name}=`, 'Verifiers ignore unknown tags.', { ref: ref('dkim', '3.6.1') }));
    if (m.p === undefined) f.push(F('error', 'dkim-no-p', 'No p= (public key) tag', 'The public key is required.', { ref: ref('dkim', '3.6.1') }));
    else {
      const key = inspectKey(m.p);
      res.key = key;
      if (key.error) f.push(F('error', 'dkim-key', 'The public key is not valid', key.error, { ref: ref('dkim', '3.6.1') }));
      else if (key.revoked) f.push(F('warn', 'dkim-revoked', 'Empty p=: this key is revoked', 'Signatures made with this selector will fail. That is intended when retiring a key.', { ref: ref('dkim', '3.6.1') }));
      else {
        if (/\s/.test(m.p)) f.push(F('info', 'dkim-p-space', 'The key contains spaces or line breaks', 'Verifiers ignore them, but some DNS panels do not. Publish it without.', { ref: ref('dkim', '3.6.1') }));
        if (key.type === 'rsa') {
          if (k === 'ed25519') f.push(F('error', 'dkim-k-mismatch', 'k=ed25519, but the key is RSA', 'Set k=rsa (or remove k=, since rsa is the default).', { ref: ref('dkim', '3.6.1') }));
          if (key.format === 'pkcs1') f.push(F('warn', 'dkim-pkcs1', 'The key is in PKCS#1 form (MIIBCg…)', 'DKIM keys are normally published as SubjectPublicKeyInfo (MIIBIj…). Some verifiers reject PKCS#1. The repair converts it without changing the key.', { ref: ref('dkim', '3.6.1') }));
          if (key.bits < 1024) f.push(F('error', 'dkim-weak', `RSA ${key.bits}-bit key`, 'RFC 8301 requires verifiers to reject keys shorter than 1024 bits. Generate a 2048-bit key.', { ref: ref('dkimCrypto', '3.2') }));
          else if (key.bits < 2048) f.push(F('warn', 'dkim-1024', `RSA ${key.bits}-bit key`, 'Still accepted, but 2048 bits is the current recommendation. Rotate to a 2048-bit key on a new selector.', { ref: ref('dkimCrypto', '3.2') }));
          else if (key.bits > 4096) f.push(F('warn', 'dkim-huge', `RSA ${key.bits}-bit key`, 'Verifiers only have to support keys up to 4096 bits.', { ref: ref('dkimCrypto', '3.2') }));
          else f.push(F('ok', 'dkim-rsa', `RSA ${key.bits}-bit public key`, 'Key length is within the recommended range.'));
          if (key.exponent < 3n || key.exponent % 2n === 0n) f.push(F('error', 'dkim-exponent', `Unusual RSA exponent (${key.exponent})`, 'This is not a usable RSA public key.'));
        } else {
          if (k !== 'ed25519') f.push(F('error', 'dkim-k-mismatch', 'The key is Ed25519, but k= is missing or rsa', 'Set k=ed25519. Without it verifiers treat the key as RSA and every signature fails.', { ref: ref('ed25519', '4') }));
          if (key.format === 'spki') f.push(F('error', 'dkim-ed-spki', 'Ed25519 key published in SPKI form (MCowBQYDK2Vw…)', 'RFC 8463 publishes the raw 32-byte key. The repair extracts it without changing the key.', { ref: ref('ed25519', '4') }));
          f.push(F('info', 'dkim-ed25519', 'Ed25519 key', 'Not every receiver verifies Ed25519 yet. RFC 8463 recommends also signing with an RSA key on a second selector.', { ref: ref('ed25519', '4') }));
        }
      }
    }
    if (/[^\x20-\x7e]/.test(p.value.replace(/[\t\r\n]/g, ' '))) f.push(F('error', 'dkim-ascii', 'Contains non-ASCII characters', 'Look for smart quotes or non-breaking spaces pasted from a document.'));
    const bytes = byteLen(p.value);
    if (bytes > TXT_STRING_MAX) f.push(F('info', 'dkim-strings', `${bytes} bytes: needs ${splitTxt(p.value).length} strings in one TXT record`, 'DNS strings hold 255 bytes at most. Publish all the strings together in ONE TXT record; verifiers join them with nothing in between. Two separate TXT records would break the key.', { ref: ref('dkim', '3.6.2.2') }));
    if (!f.some(x => x.sev === 'error' || x.sev === 'warn')) f.push(F('ok', 'dkim-ok', 'Syntax and key format checks passed', 'This does not prove your mail server signs with the matching private key; send a test message and check the DKIM result.'));
    return res;
  }
  function repairDkim(value) {
    const p = parseDkim(value);
    const changes = [], blocked = [];
    if (!p.value) return { value: null, changes, blocked: ['The record is empty.'], changed: false };
    for (const e of p.errors) blocked.push(`Fix by hand: ${e}.`);
    let tags = [];
    const seen = new Map();
    for (const t of p.tags) {
      if (!t.name) { tags.push(t); continue; }
      const name = DKIM_KNOWN.has(t.key) ? t.key : t.name;
      if (name !== t.name) changes.push({ kind: 'fix', text: `Wrote tag ${t.name}= as ${name}= (DKIM tag names are case-sensitive, so verifiers did not see it).` });
      if (seen.has(name)) {
        if (seen.get(name).value === t.value) changes.push({ kind: 'cosmetic', text: `Removed the repeated ${name}= tag.` });
        else blocked.push(`${name}= appears twice with different values. Keep the right one.`);
        continue;
      }
      const nt = { ...t, name };
      seen.set(name, nt); tags.push(nt);
    }
    const get = n => tags.find(t => t.name === n);
    const pt = get('p');
    if (!pt) blocked.push('There is no p= public key to publish.');
    else {
      const stripped = pt.value.replace(/\s+/g, '');
      if (stripped !== pt.value) { changes.push({ kind: 'cosmetic', text: 'Removed spaces and line breaks from the key.' }); pt.value = stripped; }
      const key = inspectKey(pt.value);
      if (key.error) blocked.push(`${key.error} Get the public key again from your mail system.`);
      else if (!key.revoked) {
        if (key.type === 'rsa' && key.format === 'pkcs1') { pt.value = bytesToB64(pkcs1ToSpki(key.bytes)); changes.push({ kind: 'fix', text: 'Converted the RSA key from PKCS#1 to SubjectPublicKeyInfo. Same key, standard wrapping.' }); }
        if (key.type === 'ed25519' && key.format === 'spki') { pt.value = bytesToB64(key.raw); changes.push({ kind: 'fix', text: 'Extracted the raw 32-byte Ed25519 key from its SPKI wrapping, as RFC 8463 requires. Same key.' }); }
        const kt = get('k');
        if (key.type === 'ed25519' && (!kt || kt.value !== 'ed25519')) {
          if (kt) kt.value = 'ed25519'; else tags.push({ name: 'k', key: 'k', value: 'ed25519' });
          changes.push({ kind: 'fix', text: 'Set k=ed25519 to match the key. Without it verifiers read the key as RSA.' });
        } else if (key.type === 'rsa' && kt && kt.value !== 'rsa') { kt.value = 'rsa'; changes.push({ kind: 'fix', text: 'Set k=rsa to match the key.' }); }
      }
    }
    const vt = get('v');
    if (vt && vt.value !== 'DKIM1') { if (vt.value.toUpperCase() === 'DKIM1') { vt.value = 'DKIM1'; changes.push({ kind: 'fix', text: 'Wrote the version as v=DKIM1 (it is case-sensitive).' }); } else blocked.push(`v=${vt.value} is not a DKIM version. Remove it or set v=DKIM1.`); }
    const ht = get('h');
    if (ht && ht.value.split(':').map(s => s.trim().toLowerCase()).every(h => h === 'sha1')) blocked.push('h=sha1 cannot be fixed in DNS alone: the signer must switch to SHA-256 first, then set h=sha256 or remove h=.');
    const ordered = orderTags(tags, DKIM_ORDER, t => t.name);
    if (vt && tags[0] !== vt) changes.push({ kind: 'fix', text: 'Moved v=DKIM1 to the start, where RFC 6376 requires it.' });
    else if (ordered.some((t, i) => t !== tags[i])) changes.push({ kind: 'cosmetic', text: 'Put the tags in the conventional order (v, k, h, s, t, n, p).' });
    const out = ordered.map(t => (t.name ? `${t.name}=${t.value}` : t.raw)).join('; ');
    if (!changes.length && out !== p.value) changes.push({ kind: 'cosmetic', text: 'Normalized spacing and separators.' });
    return { value: out, changes, blocked, changed: out !== p.value };
  }
  function buildDkim(o) {
    const tags = [['v', 'DKIM1'], ['k', o.k || 'rsa']];
    if (o.h) tags.push(['h', o.h]);
    if (o.s && o.s !== '*') tags.push(['s', o.s]);
    if (o.t) tags.push(['t', o.t]);
    if (o.n) tags.push(['n', o.n]);
    for (const [k, v] of o.extra || []) tags.push([k, v]);
    tags.push(['p', String(o.p || '').replace(/\s+/g, '')]);
    return tags.map(([k, v]) => `${k}=${v}`).join('; ');
  }
  // True for anything holding a PEM private key header, even with its spaces removed (as pasting it
  // into the p= field does), so the page can refuse it and never store it.
  const looksLikePrivateKey = text => /-----BEGIN ?[A-Z ]*PRIVATE ?KEY/i.test(String(text ?? ''));
  const PRIVATE_KEY_ERROR = 'This is a PRIVATE key. It must never be published or pasted into tools. Paste the public key (BEGIN PUBLIC KEY) or the DNS record instead. If this key was shared anywhere, generate a new one.';
  // Accepts a DKIM TXT record, a zone line, BIND/opendkim output, a PEM public key or a bare key.
  function normalizeDkimInput(text) {
    const s = String(text ?? '').trim();
    if (looksLikePrivateKey(s)) return { error: PRIVATE_KEY_ERROR };
    const pem = s.match(/-----BEGIN (RSA )?PUBLIC KEY-----([\s\S]*?)-----END \1?PUBLIC KEY-----/);
    const fromKey = (b64, format) => {
      const key = inspectKey(b64);
      if (key.error) return { error: key.error };
      if (key.type === 'rsa') return { value: `v=DKIM1; k=rsa; p=${bytesToB64(key.format === 'pkcs1' ? pkcs1ToSpki(key.bytes) : key.bytes)}`, from: format, converted: key.format === 'pkcs1' };
      return { value: `v=DKIM1; k=ed25519; p=${bytesToB64(key.raw)}`, from: format, converted: key.format === 'spki' };
    };
    if (pem) return fromKey(pem[2], pem[1] ? 'pem-pkcs1' : 'pem');
    const txt = parseTxtPresentation(s);
    const value = txt.value.trim();
    let selector = null;
    if (txt.name) { const mm = txt.name.match(/^(.+?)\._domainkey(?:\.|$)/i); if (mm) selector = mm[1]; }
    if (/(^|;)\s*p\s*=/.test(value) || /^v\s*=\s*DKIM1/i.test(value)) return { value, from: 'record', selector, strings: txt.strings, warnings: txt.warnings };
    if (/^[A-Za-z0-9+/=\s]{40,}$/.test(value)) return { ...fromKey(value, 'base64'), selector };
    return { value, from: 'record', selector, strings: txt.strings, warnings: txt.warnings };
  }

  // ---------- DNS output ----------
  function dnsOutput({ zone, host, value, ttl = 3600 }) {
    const z = String(zone || '').toLowerCase().replace(/\.$/, '');
    const fqdn = String(host).toLowerCase().replace(/\.$/, '');
    const relative = fqdn === z ? '@' : z && fqdn.endsWith(`.${z}`) ? fqdn.slice(0, -(z.length + 1)) : fqdn;
    const { strings, presentation, bytes } = formatTxt(value);
    return {
      fqdn, relative, type: 'TXT', ttl, value, strings, presentation, bytes,
      formats: {
        zone: `${fqdn}. ${ttl} IN TXT ${presentation}`,
        cloudflare: { name: relative, content: strings.length > 1 ? presentation : value },
        route53: { name: relative === '@' ? '' : relative, value: presentation },
        route53Json: JSON.stringify({ Comment: `MailForge: TXT for ${fqdn}`, Changes: [{ Action: 'UPSERT', ResourceRecordSet: { Name: `${fqdn}.`, Type: 'TXT', TTL: ttl, ResourceRecords: [{ Value: presentation }] } }] }, null, 2),
        plain: value
      }
    };
  }

  // ---------- comparison ----------
  function canonical(kind, value) {
    if (kind === 'spf') { const p = parseSpf(value); return p.ok ? p.terms.map(t => (t.error ? t.raw : termString(t).replace(/^\+/, '').toLowerCase())) : null; }
    const p = kind === 'dmarc' ? parseDmarc(value) : parseDkim(value);
    const lowerVals = kind === 'dmarc' ? new Set(['p', 'sp', 'np', 'adkim', 'aspf', 'rf', 't', 'psd']) : new Set();
    // Tags that only restate the default carry no meaning, so they do not count as a difference.
    const defaults = kind === 'dmarc' ? new Set(['pct=100', 'adkim=r', 'aspf=r', 'ri=86400', 'fo=0', 'rf=afrf', 't=n', 'psd=u']) : new Set(['v=DKIM1', 'k=rsa', 's=*']);
    return p.tags.filter(t => t.key).map(t => {
      const k = kind === 'dmarc' ? t.key : t.name;
      let v = t.value;
      if (lowerVals.has(k)) v = v.toLowerCase();
      if (k === 'p' && kind === 'dkim') v = v.replace(/\s+/g, '');
      if (k === 'rua' || k === 'ruf') v = v.split(',').map(s => s.trim().toLowerCase()).join(',');
      if (k === 'fo' || k === 't' || k === 'h') v = v.split(':').map(s => s.trim().toLowerCase()).sort().join(':');
      return `${k}=${v}`;
    }).filter(x => !defaults.has(x));
  }
  function compareRecords(kind, published, built) {
    const a = canonical(kind, published), b = canonical(kind, built);
    if (!a || !b) return { same: false, onlyPublished: [], onlyBuilt: [], orderDiffers: false, unparsable: true };
    const same = kind === 'spf' ? a.join(' ') === b.join(' ') : [...a].sort().join(';') === [...b].sort().join(';');
    const onlyPublished = a.filter(x => !b.includes(x)), onlyBuilt = b.filter(x => !a.includes(x));
    return { same, onlyPublished, onlyBuilt, orderDiffers: !same && !onlyPublished.length && !onlyBuilt.length };
  }

  // ---------- DNS over HTTPS ----------
  const DOH = {
    cloudflare: { label: 'Cloudflare', url: (n, t) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}`, headers: { accept: 'application/dns-json' } },
    google: { label: 'Google', url: (n, t) => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}`, headers: { accept: 'application/dns-json' } }
  };
  const RCODE = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' };
  const RRTYPE = { 1: 'A', 5: 'CNAME', 15: 'MX', 16: 'TXT', 28: 'AAAA' };
  function makeResolver(fetchImpl, { order = ['cloudflare', 'google'], timeoutMs = 8000 } = {}) {
    const cache = new Map();
    const resolve = (name, type) => {
      const key = `${type} ${String(name).toLowerCase()}`;
      if (!cache.has(key)) cache.set(key, (async () => {
        const errors = [];
        for (const id of order) {
          const prov = DOH[id];
          const ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
          const timer = ctrl ? setTimeout(() => ctrl.abort(), timeoutMs) : null;
          try {
            const res = await fetchImpl(prov.url(name, type), { headers: prov.headers, signal: ctrl?.signal, cache: 'no-store' });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const j = await res.json();
            const status = RCODE[j.Status] || `RCODE ${j.Status}`;
            if (status === 'SERVFAIL' && id !== order[order.length - 1]) { errors.push(`${prov.label}: SERVFAIL`); continue; }
            const answers = (j.Answer || []).map(a => ({ name: String(a.name).replace(/\.$/, ''), type: RRTYPE[a.type] || String(a.type), ttl: a.TTL, data: a.data }));
            return { status, answers, provider: prov.label, dnssec: !!j.AD };
          } catch (e) {
            errors.push(`${prov.label}: ${e && e.name === 'AbortError' ? 'timed out' : (e && e.message) || 'request failed'}`);
          } finally { if (timer) clearTimeout(timer); }
        }
        return { status: 'ERROR', answers: [], error: `Lookup failed (${errors.join('; ')}). A browser extension, firewall or offline network may be blocking DNS-over-HTTPS.` };
      })());
      return cache.get(key);
    };
    resolve.clear = () => cache.clear();
    return resolve;
  }
  function txtRecords(result) {
    return (result.answers || []).filter(a => a.type === 'TXT').map(a => {
      const d = String(a.data ?? '');
      if (d.startsWith('"')) { const t = parseTxtPresentation(d); return { value: t.value, strings: t.strings, ttl: a.ttl }; }
      return { value: d, strings: [d], ttl: a.ttl, boundariesUnknown: true };
    });
  }
  const cnameChain = result => (result.answers || []).filter(a => a.type === 'CNAME').map(a => ({ from: a.name, to: String(a.data).replace(/\.$/, '') }));
  const failed = r => ['ERROR', 'SERVFAIL', 'REFUSED', 'SKIPPED'].includes(r.status) || /^RCODE/.test(r.status);

  // Follows the SPF tree the way a receiver would for a sender that matches nothing (the worst case,
  // and the one spoofed mail hits), counting DNS-querying terms against the 10-lookup and 2-void limits.
  async function walkSpf(domain, resolve, { maxQueries = 80 } = {}) {
    const st = { lookups: 0, voids: 0, queries: 0, stopped: false, loop: false, temp: false };
    const q = async (name, type) => {
      if (++st.queries > maxQueries) { st.stopped = true; return { status: 'SKIPPED', answers: [] }; }
      return resolve(name, type);
    };
    async function visit(dom, path, via) {
      const node = { domain: dom, via, record: null, strings: null, children: [], lookups: 0, error: null, analysis: null };
      const r = await q(dom, 'TXT');
      node.status = r.status; node.provider = r.provider;
      if (failed(r)) { node.error = r.status === 'SKIPPED' ? 'not checked: query limit reached' : `lookup failed (${r.error || r.status})`; node.temp = true; st.temp = true; return node; }
      const spf = txtRecords(r).filter(x => /^v=spf1(\s|$)/i.test(x.value));
      if (via && (r.status === 'NXDOMAIN' || !r.answers.some(a => a.type === 'TXT'))) { st.voids++; node.void = true; }
      if (!spf.length) { node.error = r.status === 'NXDOMAIN' ? 'domain does not exist' : 'no SPF record'; return node; }
      if (spf.length > 1) { node.error = `${spf.length} SPF records at this name: receivers return permerror`; node.multiple = spf.map(x => x.value); return node; }
      node.record = spf[0].value; node.strings = spf[0].strings;
      node.analysis = analyzeSpf(node.record, { strings: spf[0].boundariesUnknown ? null : spf[0].strings });
      const terms = node.analysis.terms;
      const allIdx = terms.findIndex(t => t.kind === 'mech' && t.name === 'all' && !t.error);
      for (const t of allIdx >= 0 ? terms.slice(0, allIdx + 1) : terms) {
        if (t.kind !== 'mech' || t.error || !LOOKUP_MECHS.has(t.name)) continue;
        st.lookups++; node.lookups++;
        const target = t.domain || dom;
        const child = { term: t.raw, kind: t.name, domain: target, children: [] };
        if (target.includes('%')) { child.note = 'uses a macro, which depends on the message; not followed'; node.children.push(child); continue; }
        if (t.name === 'include') {
          if (path.includes(target.toLowerCase())) { child.error = 'include loop: this domain is already being evaluated'; st.loop = true; node.children.push(child); continue; }
          const sub = await visit(target, [...path, target.toLowerCase()], t.raw);
          if (sub.error && !sub.temp) sub.error += ' (an include of a domain without a usable SPF record is a permerror)';
          node.children.push({ ...sub, term: t.raw, kind: 'include' });
        } else if (t.name === 'a') {
          const [a4, a6] = await Promise.all([q(target, 'A'), q(target, 'AAAA')]);
          const n4 = a4.answers.filter(x => x.type === 'A').length, n6 = a6.answers.filter(x => x.type === 'AAAA').length;
          if (failed(a4) && failed(a6)) { child.error = 'lookup failed'; st.temp = true; }
          else { child.detail = `${n4} IPv4, ${n6} IPv6 address${n4 + n6 === 1 ? '' : 'es'}`; if (!n4 && !n6) { st.voids++; child.void = true; } }
          node.children.push(child);
        } else if (t.name === 'mx') {
          const rm = await q(target, 'MX');
          if (failed(rm)) { child.error = 'lookup failed'; st.temp = true; }
          else {
            const hosts = rm.answers.filter(x => x.type === 'MX').map(x => String(x.data).split(/\s+/).pop().replace(/\.$/, ''));
            child.detail = hosts.length ? `${hosts.length} MX host${hosts.length === 1 ? '' : 's'}: ${hosts.join(', ')}` : 'no MX records';
            if (!hosts.length) { st.voids++; child.void = true; }
            if (hosts.length > 10) child.error = 'more than 10 MX hosts: receivers return permerror';
          }
          node.children.push(child);
        } else {
          child.note = t.name === 'ptr' ? 'depends on the connecting IP; not evaluated' : 'depends on the message; not evaluated';
          node.children.push(child);
        }
      }
      const redirect = allIdx < 0 ? terms.find(t => t.kind === 'mod' && t.name === 'redirect' && !t.error) : null;
      if (redirect) {
        st.lookups++; node.lookups++;
        if (redirect.domain.includes('%')) node.children.push({ term: redirect.raw, kind: 'redirect', domain: redirect.domain, note: 'uses a macro; not followed', children: [] });
        else if (path.includes(redirect.domain.toLowerCase())) { node.children.push({ term: redirect.raw, kind: 'redirect', domain: redirect.domain, error: 'redirect loop', children: [] }); st.loop = true; }
        else node.children.push({ ...(await visit(redirect.domain, [...path, redirect.domain.toLowerCase()], redirect.raw)), term: redirect.raw, kind: 'redirect' });
      }
      return node;
    }
    const root = await visit(domain, [String(domain).toLowerCase()], null);
    const f = [];
    if (st.lookups > 10) f.push(F('error', 'spf-tree-lookups', `${st.lookups} DNS lookups in total: over the limit of 10`, 'Receivers stop at 10 and return permerror, so SPF fails for all your mail, including legitimate mail. Remove includes you no longer use, or move some senders to a subdomain.', { ref: ref('spf', '4.6.4') }));
    else if (root.record) f.push(F(st.lookups >= 9 ? 'warn' : 'ok', 'spf-tree-lookups', `${st.lookups} of 10 DNS lookups in total`, st.lookups >= 9 ? 'One more include from a provider and SPF breaks. Providers sometimes add lookups to their own records without warning.' : 'Counted across every include and redirect.', { ref: ref('spf', '4.6.4') }));
    if (st.voids > 2) f.push(F('error', 'spf-voids', `${st.voids} void lookups: over the limit of 2`, 'Lookups that return no records count toward a separate limit of 2; beyond it receivers may return permerror. Remove mechanisms that point at names with no records.', { ref: ref('spf', '4.6.4') }));
    else if (st.voids) f.push(F('warn', 'spf-voids', `${st.voids} void lookup${st.voids === 1 ? '' : 's'}`, 'A mechanism points at a name with no records. It authorizes nothing and counts toward the void limit of 2.', { ref: ref('spf', '4.6.4') }));
    if (st.loop) f.push(F('error', 'spf-loop', 'Include or redirect loop', 'A record includes itself, directly or through another record.', { ref: ref('spf', '5.2') }));
    if (st.stopped) f.push(F('warn', 'spf-stopped', `Stopped after ${maxQueries} queries`, 'The tree is unusually large; counts shown are a minimum.'));
    if (st.temp) f.push(F('warn', 'spf-temp', 'Some lookups failed', 'Those branches were not counted, so the totals may be low. Try again or switch DNS provider.'));
    return { root, lookups: st.lookups, voids: st.voids, queries: st.queries, findings: f };
  }

  async function inspectSpf(domain, resolve) {
    const r = await resolve(domain, 'TXT');
    if (failed(r)) return { error: r.error || r.status };
    const all = txtRecords(r), spf = all.filter(x => /^v=spf1(\s|$)/i.test(x.value));
    const out = { status: r.status, provider: r.provider, records: spf, otherTxt: all.length - spf.length, findings: [] };
    if (r.status === 'NXDOMAIN') out.findings.push(F('error', 'dns-nxdomain', `${domain} does not exist in DNS`));
    else if (!spf.length) out.findings.push(F('error', 'spf-none', 'No SPF record published', 'Receivers get "none" for SPF, so only DKIM can make your mail pass DMARC. Publish one SPF record listing your senders.', { ref: ref('spf', '4.5') }));
    else if (spf.length > 1) out.findings.push(F('error', 'spf-multiple', `${spf.length} SPF records published`, 'More than one SPF record at the same name is a permerror: SPF fails for every message. Merge them into one (the SPF tab can propose a merge).', { ref: ref('spf', '4.5') }));
    if (spf.length === 1) {
      out.record = spf[0].value;
      out.walk = await walkSpf(domain, resolve);
    }
    return out;
  }
  async function inspectDmarc(domain, resolve) {
    const d = String(domain).toLowerCase().replace(/\.$/, '');
    const look = async host => { const r = await resolve(host, 'TXT'); return { host, r, recs: failed(r) ? [] : txtRecords(r).filter(x => /^v\s*=\s*DMARC1/i.test(x.value)) }; };
    let hit = await look(`_dmarc.${d}`);
    if (failed(hit.r)) return { error: hit.r.error || hit.r.status, host: hit.host };
    const out = { host: hit.host, provider: hit.r.provider, findings: [], inherited: false };
    if (!hit.recs.length && orgDomain(d) !== d) {
      const org = await look(`_dmarc.${orgDomain(d)}`);
      if (!failed(org.r) && org.recs.length) { hit = org; out.inherited = true; out.host = org.host; out.findings.push(F('info', 'dmarc-org', `No record at _dmarc.${d}; the organizational domain's record applies`, `Mail from ${d} is covered by ${org.host} (its sp= tag, or p= if there is none). MailForge estimates the organizational domain from a short list of suffixes, not the full Public Suffix List or the RFC 9989 DNS tree walk.`, { ref: ref('dmarc', '6.6.3') })); }
    }
    if (!hit.recs.length) { out.findings.push(F('error', 'dmarc-none', 'No DMARC record published', 'Receivers apply no DMARC policy and send no reports. Start with v=DMARC1; p=none; rua=mailto:… and work toward reject.', { ref: ref('dmarc', '6.6.3') })); return out; }
    if (hit.recs.length > 1) { out.findings.push(F('error', 'dmarc-multiple', `${hit.recs.length} DMARC records published`, 'With more than one record, receivers apply no DMARC policy at all. Keep one.', { ref: ref('dmarc', '6.6.3') })); out.records = hit.recs; return out; }
    out.record = hit.recs[0].value;
    out.ttl = hit.recs[0].ttl;
    const policyDomain = hit.host.replace(/^_dmarc\./, '');
    out.analysis = analyzeDmarc(out.record, { domain: policyDomain });
    out.external = [];
    const m = out.analysis.map;
    for (const tag of ['rua', 'ruf']) {
      if (!m[tag]) continue;
      const checked = new Set();
      for (const u of parseReportUris(m[tag])) {
        if (u.error || orgDomain(u.domain) === orgDomain(policyDomain) || checked.has(u.domain)) continue;
        checked.add(u.domain);
        const host = `${policyDomain}._report._dmarc.${u.domain}`;
        const r = await resolve(host, 'TXT');
        const ok = !failed(r) && txtRecords(r).some(x => /^v\s*=\s*DMARC1/i.test(x.value));
        const wild = ok ? false : await (async () => { const w = await resolve(`*._report._dmarc.${u.domain}`, 'TXT'); return !failed(w) && txtRecords(w).some(x => /^v\s*=\s*DMARC1/i.test(x.value)); })();
        out.external.push({ tag, domain: u.domain, host, authorized: ok || wild, failed: failed(r) });
        if (failed(r)) out.findings.push(F('warn', 'dmarc-ext-check', `Could not check report authorization for ${u.domain}`, r.error || ''));
        else if (!ok && !wild) out.findings.push(F('warn', 'dmarc-ext-missing', `${u.domain} has not authorized your ${tag} reports`, `No "v=DMARC1" TXT record at ${host}. Receivers will not send ${tag} reports there until it exists. Reporting services usually create it when you add the domain in their portal.`, { ref: ref('dmarcReports', '4') }));
        else out.findings.push(F('ok', 'dmarc-ext-ok', `${u.domain} accepts your ${tag} reports`, `Found the authorization record at ${host}.`, { ref: ref('dmarcReports', '4') }));
      }
    }
    return out;
  }
  async function inspectDkim(domain, selector, resolve) {
    const host = `${selector}._domainkey.${String(domain).toLowerCase().replace(/\.$/, '')}`;
    const r = await resolve(host, 'TXT');
    if (failed(r)) return { host, selector, error: r.error || r.status, findings: [] };
    const out = { host, selector, cname: cnameChain(r), provider: r.provider, findings: [] };
    const recs = txtRecords(r);
    if (r.status === 'NXDOMAIN' || !recs.length) { out.missing = true; return out; }
    const keys = recs.filter(x => /(^|;)\s*p\s*=/.test(x.value) || /^v\s*=\s*DKIM1/i.test(x.value));
    if (!keys.length) { out.findings.push(F('error', 'dkim-not-key', 'TXT record found, but it is not a DKIM key', recs[0].value.slice(0, 120))); return out; }
    if (keys.length > 1) out.findings.push(F('warn', 'dkim-multiple', `${keys.length} key records at this selector`, 'Verifiers may pick either one. Publish exactly one key per selector.', { ref: ref('dkim', '3.6.2.2') }));
    out.record = keys[0].value; out.strings = keys[0].strings; out.ttl = keys[0].ttl;
    out.analysis = analyzeDkim(out.record, { selector });
    return out;
  }
  const COMMON_SELECTORS = ['selector1', 'selector2', 'google', 'default', 'k1', 'k2', 's1', 's2', 'mail', 'dkim', 'smtp', 'mx', 'pm', 'mandrill', 'krs', 'sig1'];

  return {
    version: '0.1.0', RFC, TXT_STRING_MAX, COMMON_SELECTORS, QUALIFIER, SPF_MECHS,
    byteLen, splitTxt, quoteTxtString, formatTxt, parseTxtPresentation,
    checkDomain, orgDomain, parseIPv4, parseIPv6, formatIPv4, formatIPv6, mergeCidrs, rangeToCidrs,
    parseSpfTerm, parseSpf, termString, deadTerms, analyzeSpf, repairSpf, mergeSpfRecords,
    parseTagList, parseReportUris, parseDmarc, analyzeDmarc, explainDmarc, repairDmarc, buildDmarc,
    b64ToBytes, bytesToB64, inspectKey, pkcs1ToSpki, parseDkim, checkSelector, analyzeDkim, repairDkim, buildDkim, looksLikePrivateKey, PRIVATE_KEY_ERROR, normalizeDkimInput,
    dnsOutput, compareRecords, makeResolver, txtRecords, walkSpf, inspectSpf, inspectDmarc, inspectDkim
  };
});
