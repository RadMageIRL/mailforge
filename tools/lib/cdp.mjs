// Just enough of the Chrome DevTools Protocol to drive headless Chrome from Node with no
// dependencies (Node 22+ has a global WebSocket).
//
// Chrome picks a free debugging port itself (--remote-debugging-port=0) and writes it to
// DevToolsActivePort in a fresh profile folder, so a run can never attach to a stale browser left
// by an earlier run. close() asks Chrome to exit and then removes the profile.
import { spawn, execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export function findChrome() {
  const candidates = [
    process.env.CHROME_PATH,
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
    process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, 'Google/Chrome/Application/chrome.exe'),
    'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser',
  ].filter(Boolean);
  return candidates.find((p) => existsSync(p)) || null;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class Connection {
  constructor(ws) {
    this.ws = ws; this.nextId = 1; this.pending = new Map(); this.listeners = [];
    ws.addEventListener('message', (e) => {
      const msg = JSON.parse(e.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { ok, fail } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) fail(new Error(`${msg.error.message} (${msg.error.code})`)); else ok(msg.result);
      } else if (msg.method) {
        for (const l of this.listeners) l(msg);
      }
    });
  }
  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    this.ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    return new Promise((ok, fail) => this.pending.set(id, { ok, fail }));
  }
}

export async function launchChrome() {
  const exe = findChrome();
  if (!exe) throw new Error('Chrome not found; set CHROME_PATH');
  const profile = mkdtempSync(join(tmpdir(), 'mailforge-chrome-'));
  const child = spawn(exe, [
    '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run',
    '--no-default-browser-check', '--disable-extensions', '--disable-background-networking', '--mute-audio',
    ...(process.env.CI ? ['--no-sandbox'] : []), // Linux CI runners do not allow Chrome's sandbox
    'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  // Keep the end of Chrome's own error output, so a failed start says why.
  let stderr = '';
  child.stderr.on('data', (d) => { stderr = (stderr + d).slice(-4000); });
  const portFile = join(profile, 'DevToolsActivePort');
  let lines = [];
  // On Windows the launched chrome.exe can hand off to the real browser and exit 0, so only a
  // non-zero exit ends the wait early.
  for (let i = 0; i < 300 && lines.length < 2 && !child.exitCode; i++) {
    await sleep(100);
    if (existsSync(portFile)) lines = readFileSync(portFile, 'utf8').trim().split('\n');
  }
  if (lines.length < 2) {
    child.kill();
    throw new Error(`Chrome did not start (${exe}, exit ${child.exitCode}):\n${stderr.trim() || '(no output)'}`);
  }
  const ws = new WebSocket(`ws://127.0.0.1:${lines[0]}${lines[1]}`);
  await new Promise((ok, fail) => { ws.addEventListener('open', ok, { once: true }); ws.addEventListener('error', fail, { once: true }); });
  const conn = new Connection(ws);

  return {
    // Grants permissions (e.g. clipboardReadWrite) to pages from `origin` without a prompt.
    async grant(origin, permissions) {
      await conn.send('Browser.grantPermissions', { origin, permissions });
    },
    async newPage() {
      const { targetId } = await conn.send('Target.createTarget', { url: 'about:blank' });
      const { sessionId } = await conn.send('Target.attachToTarget', { targetId, flatten: true });
      return makePage(conn, sessionId, targetId);
    },
    async close() {
      try { await Promise.race([conn.send('Browser.close'), sleep(3000)]); } catch (e) { /* already gone */ }
      for (let i = 0; i < 30 && child.exitCode == null; i++) await sleep(100);
      if (child.exitCode == null) {
        if (process.platform === 'win32') { try { execFileSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore' }); } catch (e) { /* gone */ } }
        else child.kill('SIGKILL');
      }
      for (let i = 0; i < 20; i++) {
        try { rmSync(profile, { recursive: true, force: true }); break; } catch (e) { await sleep(250); }
      }
    },
  };
}

async function makePage(conn, sessionId, targetId) {
  const send = (method, params) => conn.send(method, params, sessionId);
  const problems = [], requests = [];
  conn.listeners.push((msg) => {
    if (msg.sessionId !== sessionId) return;
    const p = msg.params;
    if (msg.method === 'Network.requestWillBeSent') requests.push(p.request.url);
    if (msg.method === 'Runtime.exceptionThrown') problems.push(`exception: ${p.exceptionDetails.exception?.description || p.exceptionDetails.text}`);
    if (msg.method === 'Runtime.consoleAPICalled' && p.type === 'error') problems.push(`console.error: ${p.args.map((a) => a.value ?? a.description).join(' ')}`);
    if (msg.method === 'Log.entryAdded' && p.entry.level === 'error' && !/status of 404/.test(p.entry.text)) problems.push(`log: ${p.entry.text}`);
    if (msg.method === 'Network.loadingFailed' && !p.canceled) problems.push(`failed: ${p.errorText} ${p.requestId}`);
    if (msg.method === 'Network.responseReceived' && p.response.status >= 400) problems.push(`HTTP ${p.response.status} ${p.response.url}`);
  });
  await Promise.all(['Page.enable', 'Runtime.enable', 'Network.enable', 'Log.enable'].map((m) => send(m)));
  await send('Network.setCacheDisabled', { cacheDisabled: true });

  const page = {
    problems, requests,
    // Raw protocol access for this tab, and a listener for its events.
    send,
    on(method, handler) { conn.listeners.push((msg) => { if (msg.sessionId === sessionId && msg.method === method) handler(msg.params); }); },
    // Runs `source` in every later document before its own scripts.
    async beforeLoad(source) { await send('Page.addScriptToEvaluateOnNewDocument', { source }); },
    async eval(expression) {
      const r = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(`${expression}: ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}`);
      return r.result.value;
    },
    async waitFor(expression, timeout = 8000) {
      const until = Date.now() + timeout;
      let last;
      while (Date.now() < until) {
        try { last = await page.eval(expression); if (last) return last; } catch (e) { last = e.message; }
        await sleep(100);
      }
      throw new Error(`timed out waiting for ${expression} (last: ${JSON.stringify(last)})`);
    },
    async goto(url) {
      await send('Page.navigate', { url });
      await page.waitFor("document.readyState === 'complete'");
    },
    async reload() {
      await send('Page.reload', { ignoreCache: true });
      await sleep(200);
      await page.waitFor("document.readyState === 'complete'");
    },
    // Makes Date.now() in every later page load read `ms` at the moment of loading, then tick on.
    async startClockAt(ms) {
      const source = `(() => { const real = Date.now; const offset = ${Number(ms)} - real(); Date.now = () => real() + offset; })();`;
      await send('Page.addScriptToEvaluateOnNewDocument', { source });
    },
    async emulate({ timezone, locale }) {
      if (timezone) await send('Emulation.setTimezoneOverride', { timezoneId: timezone });
      if (locale) await send('Emulation.setLocaleOverride', { locale });
    },
    async viewport(width, height, mobile = false) {
      await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: mobile ? 2 : 1, mobile });
    },
    // Changes the time zone of the open page without reloading (the system zone changing).
    async setTimezone(timezone) {
      await send('Emulation.setTimezoneOverride', { timezoneId: '' });
      await send('Emulation.setTimezoneOverride', { timezoneId: timezone });
    },
    // e.g. [{ name: 'prefers-reduced-motion', value: 'reduce' }]
    async emulateMedia(features) {
      await send('Emulation.setEmulatedMedia', { features });
    },
    // Puts files into an <input type=file> as if the user picked them.
    async setFiles(selector, files) {
      const { root } = await send('DOM.getDocument', {});
      const { nodeId } = await send('DOM.querySelector', { nodeId: root.nodeId, selector });
      await send('DOM.setFileInputFiles', { nodeId, files });
    },
    // fullPage: true for the whole page, or { height } for the top of the page down to that y.
    async screenshot(file, fullPage = false) {
      const params = { format: 'png', captureBeyondViewport: Boolean(fullPage) };
      if (fullPage) {
        // Capturing beyond the viewport drops the scrollbar, so the page lays out at full width.
        const w = await page.eval('innerWidth');
        const h = fullPage === true ? await page.eval('document.documentElement.scrollHeight') : fullPage.height;
        params.clip = { x: 0, y: 0, width: w, height: h, scale: 1 };
      }
      const { data } = await send('Page.captureScreenshot', params);
      writeFileSync(file, Buffer.from(data, 'base64'));
    },
    // Close the tab: a background tab left open gets throttled timers and can slow later checks.
    async close() { await conn.send('Target.closeTarget', { targetId }); },
  };
  return page;
}
