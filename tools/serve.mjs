// The local development server: node tools/serve.mjs [dir] [port]
// Defaults: the repository root on port 8080 (port 0 picks a free one), so edits show on reload with
// no build step; `node tools/serve.mjs dist 8081` previews the production build. It serves only the
// site files, never tests, tools or git internals. Also used by tools/smoke.mjs.
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { join, normalize, extname, resolve, sep } from 'node:path';

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml', '.txt': 'text/plain; charset=utf-8',
};
const SITE = new Set(['index.html', 'app.js', 'mailforge-core.js']);

export function serve(dir, port = 0) {
  const root = resolve(dir);
  const server = createServer(async (req, res) => {
    try {
      let path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
      if (path.endsWith('/')) path += 'index.html';
      const file = normalize(join(root, path));
      if (!file.startsWith(root + sep)) { res.writeHead(403).end(); return; }
      const rel = file.slice(root.length + 1);
      if (!SITE.has(rel)) throw new Error('not served');
      const st = await stat(file);
      if (!st.isFile()) throw new Error('not a file');
      const body = await readFile(file);
      res.writeHead(200, { 'Content-Type': TYPES[extname(file)] || 'application/octet-stream', 'Content-Length': body.length, 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff' });
      res.end(req.method === 'HEAD' ? undefined : body);
    } catch (e) {
      if (!res.headersSent) res.writeHead(404, { 'Content-Type': 'text/plain' }).end('Not found');
    }
  });
  return new Promise((ok) => server.listen(port, '127.0.0.1', () => ok({ server, port: server.address().port })));
}

if (process.argv[1] && process.argv[1].endsWith('serve.mjs')) {
  const dir = process.argv[2] || join(import.meta.dirname, '..');
  const { port } = await serve(dir, Number(process.argv[3] ?? 8080));
  console.log(`Serving ${resolve(dir)} at http://127.0.0.1:${port}/`);
}
