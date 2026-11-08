/*
  MailForge page code: state, rendering and events. The checks live in mailforge-core.js.

  SPDX-License-Identifier: GPL-3.0-or-later
*/
(() => {
  'use strict';
  const MF = window.MailForge;
  const $ = id => document.getElementById(id);
  const THEME_KEY = 'mailforge_theme', STATE_KEY = 'mailforge_state', THEMES = ['system', 'light', 'dark'];
  const TABS = ['spf', 'dkim', 'dmarc', 'inspect', 'help'];
  let toastTimer = null;

  // ---------- helpers ----------
  function safeGet(key) { try { return localStorage.getItem(key); } catch { return null; } }
  function safeSet(key, value) { try { localStorage.setItem(key, value); return true; } catch { return false; } }
  function esc(value) { return String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
  function flash(message, duration = 2400) { const t = $('toast'); t.textContent = message; t.classList.add('visible'); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('visible'), duration); }
  function copy(text, what = 'Copied') { navigator.clipboard.writeText(text).then(() => flash(what), () => flash('Clipboard blocked: select the text and copy it by hand')); }
  function applyTheme(mode) {
    if (mode === 'system') document.documentElement.removeAttribute('data-theme'); else document.documentElement.setAttribute('data-theme', mode);
    $('theme-toggle').textContent = `Theme: ${mode === 'system' ? 'sys' : mode}`;
  }
  const domain = () => $('domain').value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/\.$/, '');
  const shownDomain = () => domain() || 'example.com';
  const counts = list => list.reduce((a, f) => (a[f.sev] = (a[f.sev] || 0) + 1, a), {});
  function rfcLabel(url) { const m = url.match(/rfc(\d+)(?:#section-([\d.]+))?/); return m ? `RFC ${m[1]}${m[2] ? ` §${m[2]}` : ''}` : 'reference'; }
  const SEV_ORDER = { error: 0, warn: 1, info: 2, ok: 3 };
  const SEV_LABEL = { error: 'error', warn: 'warn', info: 'note', ok: 'ok' };
  function findingsHtml(list) {
    if (!list.length) return '';
    return list.slice().sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]).map(f => `<div class="finding ${f.sev}"><span class="sev">${SEV_LABEL[f.sev]}</span><div class="body"><strong>${esc(f.title)}</strong>${f.detail ? `<span class="detail">${esc(f.detail)}</span>` : ''}${f.ref ? `<a class="rfc" href="${esc(f.ref)}" target="_blank" rel="noopener noreferrer">${esc(rfcLabel(f.ref))}</a>` : ''}</div></div>`).join('');
  }
  function setCount(kind, findings) {
    const el = $(`count-${kind}`), c = counts(findings);
    const n = c.error || c.warn || 0;
    el.hidden = !findings.length;
    el.className = `count ${c.error ? 'error' : c.warn ? 'warn' : 'ok'}`;
    el.textContent = c.error || c.warn ? n : '✓';
    el.setAttribute('aria-label', c.error ? `${c.error} errors` : c.warn ? `${c.warn} warnings` : 'no problems');
  }
  const KIND_LABEL = { cosmetic: 'format', dead: 'no effect', merge: 'merge', fix: 'fix' };
  function repairHtml(rep, { kind, applyLabel = 'Use this record', note = '' } = {}) {
    if (!rep || (!rep.changes?.length && !rep.blocked?.length && !rep.notes?.length)) return '';
    const items = [
      ...(rep.notes || []).map(t => `<li><span class="kind fix">review</span><span>${esc(t)}</span></li>`),
      ...(rep.changes || []).map(c => `<li><span class="kind ${c.kind}">${KIND_LABEL[c.kind] || c.kind}</span><span>${esc(c.text)}</span></li>`),
      ...(rep.blocked || []).map(t => `<li><span class="kind blocked">by hand</span><span>${esc(t)}</span></li>`)
    ].join('');
    const proposal = rep.value && (rep.changed || rep.needsReview)
      ?`<pre class="record">${esc(rep.value)}</pre><div class="row"><button class="button small primary" type="button" data-apply="${kind}" data-value="${esc(rep.value)}">${esc(applyLabel)}</button><span class="hint">${esc(note || 'Nothing changes until you choose this. Check it before publishing.')}</span></div>`
      : '';
    return `<div class="section-head" style="margin:14px 0 0"><h3>proposed repair</h3><p>${rep.changes?.length ? `${rep.changes.length} change${rep.changes.length === 1 ? '' : 's'}` : 'no automatic changes'}${rep.blocked?.length ? ` · ${rep.blocked.length} to fix by hand` : ''}</p></div><ul>${items}</ul>${proposal}`;
  }

  // ---------- DNS output ----------
  const FORMATS = { zone: 'Zone file', cloudflare: 'Cloudflare', route53: 'Route 53 console', route53Json: 'Route 53 CLI', plain: 'Other web panel' };
  const copyStore = new Map();
  function outputHtml(kind, host, value, findings) {
    for (const key of [...copyStore.keys()]) if (key.startsWith(`${kind}-`)) copyStore.delete(key);
    let copyId = 0;
    const copyBtn = text => { const id = `${kind}-${++copyId}`; copyStore.set(id, text); return `<button class="button small" type="button" data-copy="${id}">Copy</button>`; };
    if (!value) return '<p class="empty">Nothing to publish yet.</p>';
    const o = MF.dnsOutput({ zone: shownDomain(), host, value, ttl: 3600 });
    const fmt = state.format in FORMATS ? state.format : 'zone';
    const errs = findings.filter(f => f.sev === 'error').length;
    const picker = `<div class="format-picker" role="group" aria-label="Output format">${Object.entries(FORMATS).map(([k, label]) => `<button type="button" data-format="${k}" aria-pressed="${k === fmt}">${label}</button>`).join('')}</div>`;
    const banner = errs ? `<p class="banner error"><strong>${errs} error${errs === 1 ? '' : 's'} above.</strong> Fix ${errs === 1 ? 'it' : 'them'} before publishing; this record will not work as written.</p>` : '';
    const row = (label, text, copyable = true, cls = '') => `<tr><th scope="row">${label}</th><td><div class="cell"><pre class="${cls}">${esc(text)}</pre>${copyable ? copyBtn(text) : ''}</div></td></tr>`;
    const ttlRow = ttl => `<tr><th scope="row">TTL</th><td>${ttl} <span class="hint">· one hour; use 300 while you are testing changes</span></td></tr>`;
    let body = '', note = '';
    if (fmt === 'zone') { body = `<div class="cell" style="display:flex;gap:8px;margin-bottom:10px"><pre class="codebox">${esc(o.formats.zone)}</pre>${copyBtn(o.formats.zone)}</div>`; note = 'BIND-style zone file line. Works for BIND, PowerDNS, NSD, Knot and most "import zone file" features.'; }
    if (fmt === 'cloudflare') { body = `<table class="out-table"><tbody><tr><th scope="row">Type</th><td>TXT</td></tr>${row('Name', o.formats.cloudflare.name)}${row('Content', o.formats.cloudflare.content)}<tr><th scope="row">TTL</th><td>Auto, or 1 hr</td></tr></tbody></table>`; note = o.strings.length > 1 ? 'Paste the Content exactly as shown, quotes included: Cloudflare reads each quoted part as one string of the same record.' : 'Paste the Content without quotes. Cloudflare stores it as one string.'; }
    if (fmt === 'route53') { body = `<table class="out-table"><tbody>${row('Record name', o.formats.route53.name || '(leave blank)', !!o.formats.route53.name)}<tr><th scope="row">Record type</th><td>TXT</td></tr>${row('Value', o.formats.route53.value)}${ttlRow(3600)}</tbody></table>`; note = 'Keep the whole value on ONE line. Each line in the Value box becomes a separate TXT value, which would split the record in two. If other TXT values already exist at this name (site verification codes, for example), keep them on their own lines.'; }
    if (fmt === 'route53Json') { body = `<div class="cell" style="display:flex;gap:8px;margin-bottom:10px"><pre class="codebox json">${esc(o.formats.route53Json)}</pre>${copyBtn(o.formats.route53Json)}</div>`; note = `aws route53 change-resource-record-sets --hosted-zone-id <ZONE_ID> --change-batch file://change.json. Careful: UPSERT replaces every TXT value at ${o.fqdn}. If others exist there (verification codes, another provider's record), add them to ResourceRecords first.`; }
    if (fmt === 'plain') { body = `<table class="out-table"><tbody>${row('Host / name', o.relative)}<tr><th scope="row">Type</th><td>TXT</td></tr>${row('Value', o.formats.plain)}${ttlRow(3600)}</tbody></table>`; note = o.strings.length > 1 ? `This value is ${o.bytes} bytes. Most web panels split long values into 255-byte strings themselves; some need the quoted form from the Zone file view, and a few reject long values. Check the published result with the button below.` : 'Some panels want the full host name instead; that is ' + o.fqdn + '.'; }
    const strings = `<div class="strings"><div class="strings-head"><strong>1 TXT record</strong> at <code>${esc(o.fqdn)}</code> · ${o.bytes} bytes · ${o.strings.length === 1 ? 'one string' : `<strong>${o.strings.length} strings</strong>, all in this one record`}</div>${o.strings.length > 1 ? o.strings.map((s, i) => `<div class="str"><span>${esc(s)}</span><span class="len">#${i + 1} · ${MF.byteLen(s)} B</span></div>`).join('') : ''}</div>`;
    return `${banner}${picker}${strings}${body}<p class="hint" style="margin-bottom:12px">${esc(note)}</p><div class="row"><button class="button small" type="button" data-verify="${kind}">Check published</button><span class="grow"></span></div><div id="${kind}-verify" aria-live="polite"></div>`;
  }

  // ---------- DNS lookups ----------
  function resolver() {
    const p = $('doh').value;
    return MF.makeResolver((url, init) => fetch(url, init), { order: p === 'google' ? ['google'] : p === 'cloudflare' ? ['cloudflare'] : ['cloudflare', 'google'] });
  }
  const failed = r => ['ERROR', 'SERVFAIL', 'REFUSED'].includes(r.status) || /^RCODE/.test(r.status);
  const isSpf = v => /^v=spf1(\s|$)/i.test(v), isDmarc = v => /^v\s*=\s*DMARC1/i.test(v), isDkim = v => /(^|;)\s*p\s*=/.test(v) || /^v\s*=\s*DKIM1/i.test(v);
  function hostFor(kind) { const d = shownDomain(); return kind === 'spf' ? d : kind === 'dmarc' ? `_dmarc.${d}` : `${($('dkim-selector').value.trim() || 'selector1')}._domainkey.${d}`; }
  async function fetchPublished(kind) {
    if (!domain()) { flash('Enter the domain first'); $('domain').focus(); return null; }
    if (kind === 'dkim' && !$('dkim-selector').value.trim()) { flash('Enter the DKIM selector first'); $('dkim-selector').focus(); return null; }
    const host = hostFor(kind), r = await resolver()(host, 'TXT');
    const recs = failed(r) ? [] : MF.txtRecords(r).filter(x => (kind === 'spf' ? isSpf : kind === 'dmarc' ? isDmarc : isDkim)(x.value));
    return { host, r, recs, cname: (r.answers || []).filter(a => a.type === 'CNAME') };
  }
  async function verifyPublished(kind) {
    const box = $(`${kind}-verify`);
    box.innerHTML = '<p class="hint" style="margin-top:10px"><span class="spinner"></span>Looking up…</p>';
    const got = await fetchPublished(kind);
    if (!got) { box.innerHTML = ''; return; }
    const { host, r, recs } = got, built = currentRecord(kind);
    const via = r.provider ? ` (via ${r.provider})` : '';
    let html;
    if (failed(r)) html = `<p class="banner warn">Could not look up ${esc(host)}: ${esc(r.error || r.status)}</p>`;
    else if (!recs.length) html = `<p class="banner warn">No ${kind.toUpperCase()} record is published at <code>${esc(host)}</code>${r.status === 'NXDOMAIN' ? ' (the name does not exist)' : ''}${via}. If you just published it, wait a few minutes and check again.</p>`;
    else if (recs.length > 1) html = `<p class="banner error">${recs.length} ${kind.toUpperCase()} records are published at <code>${esc(host)}</code>${via}. There must be exactly one. Delete the extra record${recs.length > 2 ? 's' : ''}.</p>`;
    else {
      const cmp = MF.compareRecords(kind, recs[0].value, built);
      const ttl = recs[0].ttl != null ? ` Resolvers may keep serving the cached answer for up to ${recs[0].ttl} s.` : '';
      if (cmp.same) html = `<p class="banner ok">✓ The published record matches what you built${via}.</p>`;
      else html = `<p class="banner warn">The published record differs from what you built${via}.${esc(ttl)}</p><pre class="record">${esc(recs[0].value)}</pre>${diffHtml(cmp)}`;
    }
    box.innerHTML = `<div style="margin-top:10px">${html}</div>`;
  }
  function diffHtml(cmp) {
    if (cmp.unparsable) return '<p class="hint">One of the records could not be parsed, so they cannot be compared term by term.</p>';
    if (cmp.orderDiffers) return '<p class="hint">Same terms in a different order. For SPF, order can change which term matches first.</p>';
    return `<ul class="explain">${cmp.onlyPublished.map(x => `<li>only in published: <code>${esc(x)}</code></li>`).join('')}${cmp.onlyBuilt.map(x => `<li>only in yours: <code>${esc(x)}</code></li>`).join('')}</ul>`;
  }

  // ---------- state ----------
  const DEFAULT_STATE = {
    domain: '', tab: 'spf', format: 'zone', doh: 'auto', selectors: 'selector1, selector2', common: false,
    spf: ['mx', '~all'],
    dkim: { selector: '', k: 'rsa', p: '', h: '', s: '*', n: '', ty: false, ts: false, extra: [] },
    dmarc: { p: 'none', sp: '', np: '', pct: '', rua: '', ruf: '', adkim: 'r', aspf: 'r', ri: '', fo: [], extra: [] },
    imports: { spf: '', dkim: '', dmarc: '' }
  };
  let state;
  try { state = { ...structuredClone(DEFAULT_STATE), ...JSON.parse(safeGet(STATE_KEY) || '{}') }; } catch { state = structuredClone(DEFAULT_STATE); }
  let saveTimer = null;
  // A private key pasted by mistake is refused on screen and never written to storage.
  const scrub = v => (MF.looksLikePrivateKey(v) ? '' : v);
  const storable = () => ({ ...state, imports: Object.fromEntries(Object.entries(state.imports || {}).map(([k, v]) => [k, scrub(v)])), dkim: state.dkim ? { ...state.dkim, p: scrub(state.dkim.p), n: scrub(state.dkim.n) } : state.dkim });
  const save = () => { clearTimeout(saveTimer); saveTimer = setTimeout(() => safeSet(STATE_KEY, JSON.stringify(storable())), 250); };

  // ---------- SPF ----------
  const SPF_KINDS = ['ip4', 'ip6', 'a', 'mx', 'include', 'exists', 'ptr', 'all', 'redirect', 'exp', 'raw'];
  const SPF_PLACEHOLDER = { ip4: '192.0.2.0/24', ip6: '2001:db8::/32', a: '(this domain) or host/24', mx: '(this domain) or domain', include: '_spf.example.com', exists: '%{i}._spf.example.com', ptr: '(deprecated)', all: '', redirect: '_spf.example.com', exp: 'explain.example.com', raw: 'any term, as written' };
  let spfRows = [];
  let spfImportStrings = null;
  function termToRow(t) {
    if (t.kind === 'mod') return ['redirect', 'exp'].includes(t.name) && !t.error ? { q: '', name: t.name, value: t.value } : { q: '', name: 'raw', value: t.raw };
    if (!MF.SPF_MECHS.includes(t.name)) return { q: '', name: 'raw', value: t.raw };
    return { q: t.q, name: t.name, value: t.value };
  }
  function rowToTerm(r) {
    if (r.name === 'raw') return r.value.trim();
    if (r.name === 'redirect' || r.name === 'exp') return `${r.name}=${r.value.trim()}`;
    const v = r.value.trim();
    return `${r.q}${r.name}${v ? `${v.startsWith('/') ? '' : ':'}${v}` : ''}`;
  }
  const spfRecord = () => ['v=spf1', ...spfRows.map(rowToTerm).filter(Boolean)].join(' ');
  function loadSpf(value) {
    const p = MF.parseSpf(value);
    if (!p.ok) { flash('That is not an SPF record'); return; }
    spfRows = p.terms.map(termToRow);
    spfImportStrings = null;
    renderSpfRows(); updateSpf();
  }
  function renderSpfRows() {
    const dead = MF.deadTerms(MF.parseSpf(spfRecord()).terms);
    const visible = spfRows.map((r, i) => ({ r, i })).filter(x => rowToTerm(x.r));
    const deadRows = new Set([...dead.keys()].map(k => visible[k]?.i));
    $('spf-terms').innerHTML = spfRows.map((r, i) => {
      const qualDisabled = ['redirect', 'exp', 'raw'].includes(r.name);
      const valDisabled = r.name === 'all';
      const t = rowToTerm(r), parsed = t ? MF.parseSpfTerm(t) : null;
      return `<li class="term${deadRows.has(i) ? ' dead' : ''}" data-row="${i}">
        <select data-field="q" aria-label="Qualifier for term ${i + 1}"${qualDisabled ? ' disabled' : ''}>${[['', '+ pass'], ['~', '~ soft'], ['-', '- fail'], ['?', '? neutral']].map(([v, l]) => `<option value="${v}"${(r.q || '') === v || (r.q === '+' && v === '') ? ' selected' : ''}>${l}</option>`).join('')}</select>
        <select data-field="name" aria-label="Type of term ${i + 1}">${SPF_KINDS.map(k => `<option value="${k}"${r.name === k ? ' selected' : ''}>${k === 'raw' ? 'custom' : k}</option>`).join('')}</select>
        <input data-field="value" type="text" spellcheck="false" autocomplete="off" aria-label="Value of term ${i + 1}" value="${esc(r.value)}" placeholder="${esc(SPF_PLACEHOLDER[r.name] || '')}"${valDisabled ? ' disabled' : ''}${parsed && parsed.error ? ` class="bad" title="${esc(parsed.error)}"` : ''}>
        <span class="moves"><button class="button icon" type="button" data-move="-1" aria-label="Move term ${i + 1} up"${i === 0 ? ' disabled' : ''}>↑</button><button class="button icon" type="button" data-move="1" aria-label="Move term ${i + 1} down"${i === spfRows.length - 1 ? ' disabled' : ''}>↓</button><button class="button icon" type="button" data-remove aria-label="Remove term ${i + 1}">×</button></span>
      </li>`;
    }).join('') || '<li class="empty">No terms yet. Add senders below; an empty record (v=spf1) authorizes nothing but gives a neutral result.</li>';
  }
  function updateSpf() {
    const rec = spfRecord();
    const a = MF.analyzeSpf(rec, { strings: spfImportStrings });
    $('spf-host').textContent = shownDomain();
    $('spf-record').textContent = rec;
    $('spf-record').classList.toggle('bad', a.findings.some(f => f.sev === 'error'));
    const lvl = a.lookups > 10 ? 'error' : a.lookups >= 8 ? 'warn' : '';
    $('spf-stats').innerHTML = `<span>direct lookups ${a.lookups}/10<span class="meter" aria-hidden="true"><span class="${lvl}" style="width:${Math.min(100, a.lookups * 10)}%"></span></span></span><span>${a.bytes} bytes · ${MF.splitTxt(rec).length} string${MF.splitTxt(rec).length === 1 ? '' : 's'}</span><span>${spfRows.length} term${spfRows.length === 1 ? '' : 's'}</span>`;
    $('spf-findings').innerHTML = findingsHtml(a.findings);
    const rep = MF.repairSpf(rec);
    $('spf-repair').innerHTML = rep.changed || rep.blocked.length ? repairHtml(rep, { kind: 'spf', applyLabel: 'Apply to the builder' }) : '';
    $('spf-output').innerHTML = outputHtml('spf', shownDomain(), rec, a.findings);
    setCount('spf', a.findings);
    state.spf = spfRows.map(rowToTerm).filter(Boolean);
    save();
  }
  function addSpfValues(kind, raw) {
    const values = raw.split(/[\s,;]+/).map(s => s.trim()).filter(Boolean);
    if (!values.length) return 0;
    const rows = values.map(v => {
      if (/^[+\-~?]?(ip4|ip6|a|mx|include|exists|ptr|all)([:/]|$)/i.test(v) || /^(redirect|exp)=/i.test(v)) return termToRow(MF.parseSpfTerm(v));
      let k = kind;
      if (k === 'auto') k = MF.parseIPv4(v.split('/')[0]) !== null ? 'ip4' : v.includes(':') && MF.parseIPv6(v.split('/')[0]) !== null ? 'ip6' : 'include';
      return { q: '', name: k, value: k === 'a' || k === 'mx' ? v.replace(/^:/, '') : v };
    });
    const allAt = spfRows.findIndex(r => r.name === 'all' || r.name === 'redirect');
    spfRows.splice(allAt < 0 ? spfRows.length : allAt, 0, ...rows);
    return rows.length;
  }

  // ---------- DKIM ----------
  let dkimExtra = [];
  function dkimFields() {
    return { selector: $('dkim-selector').value.trim(), k: $('dkim-k').value, p: $('dkim-p').value, h: $('dkim-h').value, s: $('dkim-s').value, n: $('dkim-n').value.trim(), ty: $('dkim-t-y').checked, ts: $('dkim-t-s').checked, extra: dkimExtra };
  }
  function dkimRecord(f = dkimFields()) {
    const t = [f.ty && 'y', f.ts && 's'].filter(Boolean).join(':');
    return MF.buildDkim({ k: f.k, p: f.p, h: f.h, s: f.s, n: f.n, t, extra: f.extra });
  }
  function dkimFieldsFrom(value) {
    const p = MF.parseDkim(value), m = p.map;
    const known = new Set(['v', 'k', 'h', 's', 't', 'n', 'p']);
    const flags = (m.t || '').split(':').map(s => s.trim().toLowerCase()).filter(Boolean);
    const extra = p.tags.filter(t => t.name && !known.has(t.name)).map(t => [t.name, t.value]);
    if (flags.some(f => !['y', 's'].includes(f))) extra.push(['t', flags.filter(f => !['y', 's'].includes(f)).join(':')]);
    return { k: m.k === 'ed25519' ? 'ed25519' : 'rsa', p: (m.p || '').replace(/\s+/g, ''), h: m.h || '', s: m.s || '*', n: m.n || '', ty: flags.includes('y'), ts: flags.includes('s'), extra };
  }
  // A record loads "as-is" only if rebuilding it from the form gives the same meaning AND it has no
  // errors: the form always writes a well-formed record, so loading a broken one would fix it
  // silently (a DMARC record receivers ignore today could start enforcing). Errors go through the
  // labeled repair instead.
  const hasErrors = a => a.findings.some(f => f.sev === 'error');
  function dkimLossless(value) { const f = dkimFieldsFrom(value), p = MF.parseDkim(value); return !p.dups.length && !p.errors.length && !hasErrors(MF.analyzeDkim(value)) && MF.compareRecords('dkim', value, dkimRecord(f)).same && ['', 'sha256', 'sha1:sha256', 'sha1'].includes(f.h) && ['*', 'email'].includes(f.s); }
  function setDkimFields(f) {
    if (f.selector !== undefined && f.selector !== null) $('dkim-selector').value = f.selector;
    $('dkim-k').value = f.k; $('dkim-p').value = f.p; $('dkim-h').value = f.h; $('dkim-s').value = f.s; $('dkim-n').value = f.n; $('dkim-t-y').checked = f.ty; $('dkim-t-s').checked = f.ts;
    dkimExtra = f.extra || [];
  }
  function updateDkim() {
    const f = dkimFields(), rec = dkimRecord(f);
    const a = MF.analyzeDkim(rec, { selector: f.selector || 'selector1' });
    if (MF.looksLikePrivateKey(f.p)) a.findings = [{ sev: 'error', code: 'dkim-private', title: 'This is a PRIVATE key', detail: MF.PRIVATE_KEY_ERROR }];
    else if (!f.p.trim()) a.findings = a.findings.filter(x => x.code !== 'dkim-revoked').concat({ sev: 'info', code: 'dkim-need-key', title: 'Paste the public key to build the record', detail: 'An empty p= revokes the selector. Generate the key in your mail system (or with your provider) and paste the public half here, or paste a full record or PEM key into the check box above.' });
    $('dkim-host').textContent = hostFor('dkim');
    $('dkim-record').textContent = rec;
    $('dkim-record').classList.toggle('bad', a.findings.some(x => x.sev === 'error'));
    const k = a.key;
    $('dkim-stats').innerHTML = [k && k.type === 'rsa' ? `RSA ${k.bits}-bit` : k && k.type === 'ed25519' ? 'Ed25519' : k && k.revoked ? 'no key (revoked)' : '', `${MF.byteLen(rec)} bytes`, `${MF.splitTxt(rec).length} string${MF.splitTxt(rec).length === 1 ? '' : 's'} in one record`].filter(Boolean).map(s => `<span>${esc(s)}</span>`).join('');
    $('dkim-findings').innerHTML = findingsHtml(a.findings);
    $('dkim-extra').innerHTML = dkimExtra.length ? `<p class="hint">Other tags kept from the imported record:</p><div class="chips">${dkimExtra.map(([k2, v], i) => `<span class="chip"><code>${esc(k2)}=${esc(v)}</code><button type="button" data-dkim-extra="${i}" aria-label="Remove tag ${esc(k2)}">×</button></span>`).join('')}</div>` : '';
    $('dkim-output').innerHTML = MF.looksLikePrivateKey(f.p) ? '<p class="empty">No output for a private key. Paste the public key instead.</p>' : f.p.trim() ? outputHtml('dkim', hostFor('dkim'), rec, a.findings) : '<p class="empty">Add the public key to get copy-ready output.</p>';
    setCount('dkim', f.p.trim() ? a.findings : []);
    state.dkim = f; save();
  }

  // ---------- DMARC ----------
  let dmarcExtra = [];
  function dmarcFields() {
    return { p: (document.querySelector('input[name="dmarc-p"]:checked') || {}).value || 'none', sp: $('dmarc-sp').value, np: $('dmarc-np').value, pct: $('dmarc-pct').value.trim(), rua: $('dmarc-rua').value.trim(), ruf: $('dmarc-ruf').value.trim(), adkim: $('dmarc-adkim').value, aspf: $('dmarc-aspf').value, ri: $('dmarc-ri').value.trim(), fo: [...document.querySelectorAll('input[name="dmarc-fo"]:checked')].map(x => x.value), extra: dmarcExtra };
  }
  const dmarcRecord = (f = dmarcFields()) => MF.buildDmarc({ ...f, fo: f.fo.join(':') });
  function dmarcFieldsFrom(value) {
    const p = MF.parseDmarc(value), m = p.map, known = new Set(['v', 'p', 'sp', 'np', 'pct', 'rua', 'ruf', 'adkim', 'aspf', 'ri', 'fo']);
    return { p: (m.p || 'none').toLowerCase(), sp: (m.sp || '').toLowerCase(), np: (m.np || '').toLowerCase(), pct: m.pct && m.pct !== '100' ? m.pct : '', rua: m.rua || '', ruf: m.ruf || '', adkim: (m.adkim || 'r').toLowerCase(), aspf: (m.aspf || 'r').toLowerCase(), ri: m.ri && m.ri !== '86400' ? m.ri : '', fo: (m.fo || '').split(':').map(s => s.trim().toLowerCase()).filter(Boolean), extra: p.tags.filter(t => t.key && !known.has(t.key)).map(t => [t.name, t.value]) };
  }
  function dmarcLossless(value) {
    const p = MF.parseDmarc(value), f = dmarcFieldsFrom(value);
    const okSel = ['none', 'quarantine', 'reject'].includes(f.p) && ['', 'none', 'quarantine', 'reject'].includes(f.sp) && ['', 'none', 'quarantine', 'reject'].includes(f.np) && ['r', 's'].includes(f.adkim) && ['r', 's'].includes(f.aspf);
    return okSel && p.map.p !== undefined && !p.dups.length && !p.errors.length && !hasErrors(MF.analyzeDmarc(value)) && MF.compareRecords('dmarc', value, dmarcRecord(f)).same;
  }
  function setDmarcFields(f) {
    document.querySelectorAll('input[name="dmarc-p"]').forEach(x => { x.checked = x.value === f.p; });
    $('dmarc-sp').value = f.sp; $('dmarc-np').value = f.np; $('dmarc-pct').value = f.pct; $('dmarc-rua').value = f.rua; $('dmarc-ruf').value = f.ruf; $('dmarc-adkim').value = f.adkim; $('dmarc-aspf').value = f.aspf; $('dmarc-ri').value = f.ri;
    document.querySelectorAll('input[name="dmarc-fo"]').forEach(x => { x.checked = (f.fo || []).includes(x.value); });
    dmarcExtra = f.extra || [];
  }
  function updateDmarc() {
    const f = dmarcFields(), rec = dmarcRecord(f);
    const a = MF.analyzeDmarc(rec, { domain: domain() || null });
    $('dmarc-host').textContent = hostFor('dmarc');
    $('dmarc-record').textContent = rec;
    $('dmarc-record').classList.toggle('bad', a.findings.some(x => x.sev === 'error'));
    $('dmarc-explain').innerHTML = a.explain.map(l => `<li>${esc(l)}</li>`).join('');
    $('dmarc-findings').innerHTML = findingsHtml(a.findings);
    $('dmarc-extra').innerHTML = dmarcExtra.length ? `<p class="hint">Other tags kept from the imported record:</p><div class="chips">${dmarcExtra.map(([k, v], i) => `<span class="chip"><code>${esc(k)}=${esc(v)}</code><button type="button" data-dmarc-extra="${i}" aria-label="Remove tag ${esc(k)}">×</button></span>`).join('')}</div>` : '';
    $('dmarc-output').innerHTML = outputHtml('dmarc', hostFor('dmarc'), rec, a.findings);
    setCount('dmarc', a.findings);
    state.dmarc = f; save();
  }

  const currentRecord = kind => (kind === 'spf' ? spfRecord() : kind === 'dkim' ? dkimRecord() : dmarcRecord());

  // ---------- import / check ----------
  function importHtml(kind, text) {
    if (!text.trim()) return '<p class="empty" style="margin-top:12px">Paste a record first.</p>';
    if (kind === 'spf') {
      const pieces = /\(/.test(text) ? [MF.parseTxtPresentation(text)] : text.split(/\r?\n/).map(l => l.trim()).filter(Boolean).map(l => MF.parseTxtPresentation(l));
      const spf = pieces.filter(p => isSpf(p.value.trim()));
      const warnings = pieces.flatMap(p => p.warnings).map(w => ({ sev: 'warn', code: 'txt', title: 'DNS string problem', detail: w }));
      if (spf.length > 1) {
        const merged = MF.mergeSpfRecords(spf.map(p => p.value));
        const f = [{ sev: 'error', code: 'spf-multiple', title: `${spf.length} SPF records`, detail: 'A host name with more than one SPF record is a permerror: SPF fails for every message. They must be merged into one record.', ref: 'https://www.rfc-editor.org/rfc/rfc7208#section-4.5' }, ...warnings];
        return `<div style="margin-top:14px">${findingsHtml(f)}${repairHtml({ ...merged, changes: merged.changes || [] }, { kind: 'spf', applyLabel: 'Load merged record into the builder', note: 'Review the merged record carefully before publishing it.' })}</div>`;
      }
      const piece = spf[0] || pieces[0];
      const value = piece.value.trim();
      const a = MF.analyzeSpf(value, { strings: piece.strings.length > 1 ? piece.strings : null });
      const rep = MF.repairSpf(value);
      const asIs = a.ok ? `<button class="button small" type="button" data-load="spf" data-value="${esc(value)}" data-strings="${esc(JSON.stringify(piece.strings))}">Load as-is into the builder</button>` : '';
      return `<div style="margin-top:14px"><pre class="record">${esc(value)}</pre>${findingsHtml([...warnings, ...a.findings])}${repairHtml(rep, { kind: 'spf', applyLabel: 'Load the repaired record' })}<div class="row" style="margin-top:8px">${asIs}</div></div>`;
    }
    if (kind === 'dkim') {
      const n = MF.normalizeDkimInput(text);
      if (n.error) return `<div style="margin-top:14px">${findingsHtml([{ sev: 'error', code: 'dkim-input', title: 'Cannot use this input', detail: n.error }])}</div>`;
      const sel = n.selector || $('dkim-selector').value.trim() || undefined;
      const a = MF.analyzeDkim(n.value, { selector: sel });
      const rep = MF.repairDkim(n.value);
      const pre = n.from && n.from !== 'record' ? [{ sev: 'info', code: 'dkim-from-key', title: 'Built a record from the public key', detail: n.converted ? 'The key was converted to the form DKIM publishes (same key).' : 'The key is used as given.' }] : [];
      const warnings = (n.warnings || []).map(w => ({ sev: 'warn', code: 'txt', title: 'DNS string problem', detail: w }));
      const lossless = dkimLossless(n.value);
      const repOk = rep.value && dkimLossless(rep.value);
      return `<div style="margin-top:14px">${n.selector ? `<p class="hint">Selector found in the input: <code>${esc(n.selector)}</code></p>` : ''}<pre class="record">${esc(n.value)}</pre>${findingsHtml([...pre, ...warnings, ...a.findings])}${repairHtml(repOk ? rep : { ...rep, value: null }, { kind: 'dkim', applyLabel: 'Load the repaired record' })}<div class="row" style="margin-top:8px"><button class="button small" type="button" data-load="dkim" data-value="${esc(n.value)}" data-selector="${esc(n.selector || '')}"${lossless ? '' : ' disabled title="Fix the errors first, or use the proposed repair"'}>Load as-is into the builder</button>${lossless ? '' : '<span class="hint">Only an error-free record the form can hold exactly loads as-is. Use the proposed repair, or fix the text and check again.</span>'}</div></div>`;
    }
    const value = MF.parseTxtPresentation(text).value.trim();
    const a = MF.analyzeDmarc(value, { domain: domain() || null });
    const rep = MF.repairDmarc(value);
    const lossless = dmarcLossless(value), repOk = rep.value && dmarcLossless(rep.value);
    return `<div style="margin-top:14px"><pre class="record">${esc(value)}</pre><ul class="explain">${a.explain.map(l => `<li>${esc(l)}</li>`).join('')}</ul>${findingsHtml(a.findings)}${repairHtml(repOk ? rep : { ...rep, value: null }, { kind: 'dmarc', applyLabel: 'Load the repaired record' })}<div class="row" style="margin-top:8px"><button class="button small" type="button" data-load="dmarc" data-value="${esc(value)}"${lossless ? '' : ' disabled title="Fix the errors first, or use the proposed repair"'}>Load as-is into the builder</button>${lossless ? '' : '<span class="hint">Only an error-free record the form can hold exactly loads as-is. Use the proposed repair, or fix the text and check again.</span>'}</div></div>`;
  }
  function runImport(kind) { state.imports[kind] = $(`${kind}-import`).value; save(); $(`${kind}-import-result`).innerHTML = importHtml(kind, $(`${kind}-import`).value); }
  function loadInto(kind, value, extra = {}) {
    if (kind === 'spf') { loadSpf(value); if (extra.strings) { spfImportStrings = extra.strings; updateSpf(); } }
    if (kind === 'dkim') { setDkimFields({ ...dkimFieldsFrom(value), selector: extra.selector || undefined }); updateDkim(); }
    if (kind === 'dmarc') { setDmarcFields(dmarcFieldsFrom(value)); updateDmarc(); }
    flash('Loaded into the builder');
    $(`${kind}-record`).scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
  async function runFetch(kind) {
    const box = $(`${kind}-import-result`);
    box.innerHTML = '<p class="hint" style="margin-top:12px"><span class="spinner"></span>Looking up…</p>';
    const got = await fetchPublished(kind);
    if (!got) { box.innerHTML = ''; return; }
    const { host, r, recs, cname } = got;
    if (failed(r)) { box.innerHTML = `<p class="banner warn" style="margin-top:12px">Lookup of ${esc(host)} failed: ${esc(r.error || r.status)}</p>`; return; }
    if (!recs.length) { box.innerHTML = `<p class="banner warn" style="margin-top:12px">Nothing published at <code>${esc(host)}</code>${r.status === 'NXDOMAIN' ? ' (the name does not exist)' : ''}.</p>`; return; }
    // Keep the published string boundaries so problems at the joins (missing spaces) still show.
    $(`${kind}-import`).value = recs.map(x => (x.boundariesUnknown || x.strings.length < 2 ? x.value : x.strings.map(MF.quoteTxtString).join(' '))).join('\n');
    runImport(kind);
    box.insertAdjacentHTML('afterbegin', `<p class="hint" style="margin-top:12px">Fetched from <code>${esc(host)}</code> via ${esc(r.provider)}${cname.length ? ` (CNAME → ${esc(cname.map(c => c.data).join(' → '))})` : ''}.</p>`);
  }

  // ---------- inspect ----------
  function subtotal(node) { return (node.lookups || 0) + (node.children || []).reduce((s, c) => s + subtotal(c), 0); }
  function treeHtml(node) {
    const parts = [];
    parts.push(node.term ? `<code>${esc(node.term)}</code>` : `<strong>${esc(node.domain)}</strong>`);
    const meta = [];
    if (node.term && node.kind && ['include', 'redirect'].includes(node.kind) && node.record !== undefined) { const st = subtotal(node); if (st) meta.push(`${st} more lookup${st === 1 ? '' : 's'} inside`); }
    if (node.detail) meta.push(node.detail);
    if (node.note) meta.push(node.note);
    if (node.void) meta.push('void lookup');
    let html = `${parts.join(' ')}${meta.length ? ` <span class="meta">· ${esc(meta.join(' · '))}</span>` : ''}${node.error ? ` <span class="err">${esc(node.error)}</span>` : ''}`;
    if (node.record) html += `<div class="rec">${esc(node.record)}</div>`;
    if (node.children && node.children.length) html += `<ul>${node.children.map(c => `<li>${treeHtml(c)}</li>`).join('')}</ul>`;
    return html;
  }
  function compareBlock(kind, published, label) {
    const built = currentRecord(kind);
    if (kind === 'dkim' && !$('dkim-p').value.trim()) return '';
    const cmp = MF.compareRecords(kind, published, built);
    return cmp.same ? `<p class="banner ok">✓ Matches the record in the ${label} builder.</p>` : `<details class="help"><summary>Differs from the record in the ${label} builder</summary>${diffHtml(cmp)}</details>`;
  }
  const statusTag = findings => { const c = counts(findings); return c.error ? `<span class="tag error">${c.error} error${c.error === 1 ? '' : 's'}</span>` : c.warn ? `<span class="tag warn">${c.warn} warning${c.warn === 1 ? '' : 's'}</span>` : '<span class="tag ok">ok</span>'; };
  async function runInspect() {
    const d = domain();
    if (!d) { flash('Enter a domain first'); $('domain').focus(); return; }
    const de = MF.checkDomain(d);
    if (de) { $('inspect-results').innerHTML = `<p class="banner error">The domain ${esc(de)}.</p>`; return; }
    const out = $('inspect-results');
    out.innerHTML = `<section class="section panel"><p class="hint"><span class="spinner"></span>Looking up ${esc(d)}…</p></section>`;
    $('inspect-run').disabled = true;
    try {
      const resolve = resolver();
      const sels = [...new Set([...$('selectors').value.split(/[\s,]+/).map(s => s.trim()).filter(Boolean), ...($('common-selectors').checked ? MF.COMMON_SELECTORS : [])])];
      const [spf, dmarc, dkims, mx] = await Promise.all([MF.inspectSpf(d, resolve), MF.inspectDmarc(d, resolve), Promise.all(sels.map(s => MF.inspectDkim(d, s, resolve))), resolve(d, 'MX')]);
      let html = '';
      // SPF
      {
        const f = spf.error ? [{ sev: 'warn', code: 'lookup', title: 'Lookup failed', detail: spf.error }] : [...spf.findings, ...(spf.walk ? spf.walk.findings : []), ...(spf.walk && spf.walk.root.analysis ? spf.walk.root.analysis.findings.filter(x => !['spf-lookups', 'spf-syntax-ok'].includes(x.code)) : [])];
        const recs = spf.records || [];
        html += `<section class="section panel"><div class="section-head"><h3>spf · ${esc(d)}</h3><p>${statusTag(f)}${spf.provider ? ` via ${esc(spf.provider)}` : ''}</p></div>
          ${recs.map(r => `<pre class="record">${esc(r.value)}</pre>${r.strings.length > 1 ? `<p class="hint" style="margin:-6px 0 10px">published as ${r.strings.length} strings in one record</p>` : ''}`).join('')}
          ${findingsHtml(f)}
          ${spf.walk ? `<div class="section-head" style="margin-top:14px"><h3>lookup tree</h3><p>${spf.walk.lookups}/10 lookups · ${spf.walk.voids}/2 void · ${spf.walk.queries} queries made</p></div><ul class="tree"><li>${treeHtml(spf.walk.root)}</li></ul>` : ''}
          ${recs.length === 1 ? compareBlock('spf', recs[0].value, 'SPF') : ''}
          <div class="row" style="margin-top:10px">${recs.length === 1 ? `<button class="button small" type="button" data-load="spf" data-value="${esc(recs[0].value)}" data-goto="spf">Open in SPF builder</button>` : ''}${recs.length > 1 ? `<button class="button small" type="button" data-merge-spf="${esc(JSON.stringify(recs.map(r => r.value)))}">Propose a merged record</button>` : ''}</div></section>`;
      }
      // DMARC
      {
        const f = dmarc.error ? [{ sev: 'warn', code: 'lookup', title: 'Lookup failed', detail: dmarc.error }] : [...dmarc.findings, ...(dmarc.analysis ? dmarc.analysis.findings.filter(x => x.code !== 'dmarc-external') : [])];
        html += `<section class="section panel"><div class="section-head"><h3>dmarc · ${esc(dmarc.host || `_dmarc.${d}`)}</h3><p>${statusTag(f)}${dmarc.provider ? ` via ${esc(dmarc.provider)}` : ''}</p></div>
          ${dmarc.record ? `<pre class="record">${esc(dmarc.record)}</pre><ul class="explain">${dmarc.analysis.explain.map(l => `<li>${esc(l)}</li>`).join('')}</ul>` : ''}
          ${(dmarc.records || []).map(r => `<pre class="record bad">${esc(r.value)}</pre>`).join('')}
          ${findingsHtml(f)}
          ${dmarc.record && !dmarc.inherited ? compareBlock('dmarc', dmarc.record, 'DMARC') : ''}
          ${dmarc.record ? `<div class="row" style="margin-top:10px"><button class="button small" type="button" data-check="dmarc" data-value="${esc(dmarc.record)}">Open in DMARC tab</button></div>` : ''}</section>`;
      }
      // DKIM
      {
        const found = dkims.filter(x => x.record || x.findings.length || x.error);
        const missing = dkims.filter(x => x.missing);
        html += `<section class="section panel"><div class="section-head"><h3>dkim</h3><p>${sels.length ? `${found.length} of ${sels.length} selector${sels.length === 1 ? '' : 's'} found` : 'no selectors given'}</p></div>`;
        if (!sels.length) html += '<p class="empty">Enter the selectors your mail systems use. DKIM keys cannot be listed from DNS; you have to know (or guess) the selector. A received message\'s DKIM-Signature header shows it as s=.</p>';
        for (const k of found) {
          const f = k.error ? [{ sev: 'warn', code: 'lookup', title: 'Lookup failed', detail: k.error }] : [...k.findings, ...(k.analysis ? k.analysis.findings : [])];
          const key = k.analysis && k.analysis.key;
          html += `<div style="margin-bottom:16px"><div class="sub-head row" style="margin-bottom:6px"><code>${esc(k.host)}</code> ${statusTag(f)} ${key && key.type ? `<span class="tag">${key.type === 'rsa' ? `RSA ${key.bits}` : 'Ed25519'}</span>` : ''}</div>
            ${k.cname && k.cname.length ? `<p class="hint">CNAME → ${esc(k.cname.map(c => c.to).join(' → '))} (key hosted by your provider)</p>` : ''}
            ${k.record ? `<pre class="record">${esc(k.record)}</pre>${k.strings && k.strings.length > 1 ? `<p class="hint" style="margin:-6px 0 10px">published as ${k.strings.length} strings in one record</p>` : ''}` : ''}
            ${findingsHtml(f)}
            ${k.record && $('dkim-selector').value.trim() === k.selector ? compareBlock('dkim', k.record, 'DKIM') : ''}
            ${k.record ? `<button class="button small" type="button" data-check="dkim" data-value="${esc(k.record)}" data-selector="${esc(k.selector)}">Open in DKIM tab</button>` : ''}</div>`;
        }
        if (missing.length) html += `<p class="hint">No key at: ${missing.map(x => `<code>${esc(x.selector)}</code>`).join(', ')}</p>`;
        html += '</section>';
      }
      // MX
      if (!failed(mx)) {
        const hosts = mx.answers.filter(a => a.type === 'MX').map(a => a.data);
        html += `<section class="section panel"><div class="section-head"><h3>mx</h3><p>where inbound mail goes (context only)</p></div>${hosts.length ? `<ul class="explain">${hosts.map(h => `<li>${esc(h)}</li>`).join('')}</ul>` : '<p class="empty">No MX records. That is fine for a domain that receives no mail; such domains should also publish v=spf1 -all and a reject DMARC policy.</p>'}</section>`;
      }
      out.innerHTML = html;
    } catch (e) {
      out.innerHTML = `<p class="banner error">Inspect failed: ${esc(e.message)}</p>`;
    } finally { $('inspect-run').disabled = false; }
  }

  // ---------- tabs ----------
  function showTab(name, focus = false) {
    if (!TABS.includes(name)) name = 'spf';
    for (const t of TABS) {
      const on = t === name;
      $(`tab-${t}`).setAttribute('aria-selected', String(on));
      $(`tab-${t}`).tabIndex = on ? 0 : -1;
      $(`panel-${t}`).hidden = !on;
    }
    if (focus) $(`tab-${name}`).focus();
    state.tab = name; save();
    if (location.hash !== `#${name}`) history.replaceState(null, '', `#${name}`);
  }

  // ---------- events ----------
  document.querySelector('.tabs').addEventListener('click', e => { const b = e.target.closest('[data-tab]'); if (b) showTab(b.dataset.tab); });
  document.querySelector('.tabs').addEventListener('keydown', e => {
    const i = TABS.indexOf(state.tab);
    if (e.key === 'ArrowRight') { e.preventDefault(); showTab(TABS[(i + 1) % TABS.length], true); }
    if (e.key === 'ArrowLeft') { e.preventDefault(); showTab(TABS[(i + TABS.length - 1) % TABS.length], true); }
    if (e.key === 'Home') { e.preventDefault(); showTab(TABS[0], true); }
    if (e.key === 'End') { e.preventDefault(); showTab(TABS[TABS.length - 1], true); }
  });
  window.addEventListener('hashchange', () => showTab(location.hash.slice(1)));
  $('domain').addEventListener('input', () => {
    state.domain = $('domain').value.trim();
    const d = domain(), e = d ? MF.checkDomain(d) : null;
    $('domain-hint').textContent = e ? `This domain ${e}.` : 'The domain the records are for. It sets the host names in the output and is what Inspect looks up.';
    $('domain-hint').style.color = e ? 'var(--bad)' : '';
    updateSpf(); updateDkim(); updateDmarc();
  });

  $('spf-terms').addEventListener('input', e => {
    const li = e.target.closest('[data-row]'); if (!li) return;
    const r = spfRows[Number(li.dataset.row)];
    r[e.target.dataset.field] = e.target.value;
    spfImportStrings = null;
    updateSpf();
    const parsed = rowToTerm(r) ? MF.parseSpfTerm(rowToTerm(r)) : null;
    const input = li.querySelector('[data-field="value"]');
    input.classList.toggle('bad', !!(parsed && parsed.error)); input.title = parsed && parsed.error ? parsed.error : '';
  });
  $('spf-terms').addEventListener('change', e => { if (e.target.tagName === 'SELECT') { const li = e.target.closest('[data-row]'); const r = spfRows[Number(li.dataset.row)]; if (e.target.dataset.field === 'name' && r.name === 'all') r.value = ''; renderSpfRows(); updateSpf(); } });
  $('spf-terms').addEventListener('click', e => {
    const li = e.target.closest('[data-row]'); if (!li) return;
    const i = Number(li.dataset.row);
    if (e.target.closest('[data-remove]')) { spfRows.splice(i, 1); }
    else if (e.target.closest('[data-move]')) { const j = i + Number(e.target.closest('[data-move]').dataset.move); if (j < 0 || j >= spfRows.length) return; [spfRows[i], spfRows[j]] = [spfRows[j], spfRows[i]]; }
    else return;
    spfImportStrings = null; renderSpfRows(); updateSpf();
  });
  const addFromInput = () => { const n = addSpfValues($('spf-add-kind').value, $('spf-add-value').value); if (!n) { flash('Type one or more values first'); return; } $('spf-add-value').value = ''; spfImportStrings = null; renderSpfRows(); updateSpf(); flash(`Added ${n} term${n === 1 ? '' : 's'}`); };
  $('spf-add').addEventListener('click', addFromInput);
  $('spf-add-value').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); addFromInput(); } });
  document.querySelectorAll('[data-preset]').forEach(b => b.addEventListener('click', () => { addSpfValues('auto', b.dataset.preset); renderSpfRows(); updateSpf(); flash(`Added ${b.dataset.preset}`); }));
  $('spf-reset').addEventListener('click', () => { loadSpf('v=spf1 ~all'); flash('Started over'); });
  $('spf-reset-none').addEventListener('click', () => { loadSpf('v=spf1 -all'); flash('v=spf1 -all: no server may send as this domain'); });

  ['dkim-selector', 'dkim-k', 'dkim-p', 'dkim-h', 'dkim-s', 'dkim-n', 'dkim-t-y', 'dkim-t-s'].forEach(id => $(id).addEventListener('input', updateDkim));
  document.querySelectorAll('#panel-dmarc input, #panel-dmarc select').forEach(el => { if (!el.closest('#dmarc-import-result') && el.id !== 'dmarc-import') el.addEventListener('input', updateDmarc); });

  document.addEventListener('click', e => {
    const t = e.target;
    const btn = sel => t.closest(sel);
    let b;
    if ((b = btn('[data-copy]'))) { copy(copyStore.get(b.dataset.copy) || '', 'Copied'); return; }
    if ((b = btn('[data-format]'))) { state.format = b.dataset.format; save(); updateSpf(); updateDkim(); updateDmarc(); return; }
    if ((b = btn('[data-verify]'))) { verifyPublished(b.dataset.verify); return; }
    if ((b = btn('[data-import]'))) { runImport(b.dataset.import); return; }
    if ((b = btn('[data-fetch]'))) { runFetch(b.dataset.fetch); return; }
    if ((b = btn('[data-clear-import]'))) { const k = b.dataset.clearImport; $(`${k}-import`).value = ''; $(`${k}-import-result`).innerHTML = ''; state.imports[k] = ''; save(); return; }
    if ((b = btn('[data-load]'))) { const k = b.dataset.load; if (b.dataset.goto) showTab(b.dataset.goto); loadInto(k, b.dataset.value, { strings: b.dataset.strings ? JSON.parse(b.dataset.strings) : null, selector: b.dataset.selector || null }); return; }
    if ((b = btn('[data-apply]'))) { const k = b.dataset.apply; loadInto(k, b.dataset.value); return; }
    if ((b = btn('[data-check]'))) { const k = b.dataset.check; showTab(k); if (b.dataset.selector) $('dkim-selector').value = b.dataset.selector; $(`${k}-import`).value = b.dataset.value; runImport(k); $(`${k}-import`).scrollIntoView({ behavior: 'smooth', block: 'start' }); return; }
    if ((b = btn('[data-merge-spf]'))) { showTab('spf'); $('spf-import').value = JSON.parse(b.dataset.mergeSpf).join('\n'); runImport('spf'); return; }
    if ((b = btn('[data-dkim-extra]'))) { dkimExtra.splice(Number(b.dataset.dkimExtra), 1); updateDkim(); return; }
    if ((b = btn('[data-dmarc-extra]'))) { dmarcExtra.splice(Number(b.dataset.dmarcExtra), 1); updateDmarc(); return; }
    if ((b = btn('[data-example]'))) {
      if (b.dataset.example === 'parked') { loadSpf('v=spf1 -all'); setDmarcFields(dmarcFieldsFrom('v=DMARC1; p=reject')); updateDmarc(); showTab('spf'); flash('Loaded: SPF -all and DMARC reject'); }
      else { loadSpf('v=spf1 include:spf.protection.outlook.com -all'); setDmarcFields(dmarcFieldsFrom(`v=DMARC1; p=none; rua=mailto:dmarc@${shownDomain()}`)); updateDmarc(); showTab('spf'); flash('Loaded: Microsoft 365 SPF and a starting DMARC policy'); }
    }
  });
  $('inspect-form').addEventListener('submit', e => { e.preventDefault(); runInspect(); });
  $('selectors').addEventListener('input', () => { state.selectors = $('selectors').value; save(); });
  $('doh').addEventListener('change', () => { state.doh = $('doh').value; save(); });
  $('common-selectors').addEventListener('change', () => { state.common = $('common-selectors').checked; save(); });
  ['spf', 'dkim', 'dmarc'].forEach(k => {
    $(`${k}-import`).addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); runImport(k); } });
    $(`${k}-import`).addEventListener('input', () => { state.imports[k] = $(`${k}-import`).value; save(); });
  });
  $('theme-toggle').addEventListener('click', () => {
    const stored = safeGet(THEME_KEY), cur = THEMES.includes(stored) ? stored : 'system';
    const next = THEMES[(THEMES.indexOf(cur) + 1) % THEMES.length];
    applyTheme(next); safeSet(THEME_KEY, next); flash(`Theme: ${next}`);
  });

  // ---------- start ----------
  const storedTheme = safeGet(THEME_KEY); applyTheme(THEMES.includes(storedTheme) ? storedTheme : 'system');
  $('core-version').textContent = MF.version;
  $('domain').value = state.domain || '';
  $('selectors').value = state.selectors ?? '';
  $('doh').value = state.doh || 'auto';
  $('common-selectors').checked = !!state.common;
  for (const k of ['spf', 'dkim', 'dmarc']) $(`${k}-import`).value = (state.imports || {})[k] || '';
  spfRows = (state.spf || []).map(t => termToRow(MF.parseSpfTerm(t)));
  setDkimFields({ ...DEFAULT_STATE.dkim, ...state.dkim });
  setDmarcFields({ ...DEFAULT_STATE.dmarc, ...state.dmarc });
  renderSpfRows(); updateSpf(); updateDkim(); updateDmarc();
  showTab(TABS.includes(location.hash.slice(1)) ? location.hash.slice(1) : state.tab);
})();
