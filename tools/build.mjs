// The production build: copies exactly the files the site serves into dist/ and prints their
// SHA-256. The output is byte-for-byte reproducible; --verify builds twice more into fresh folders
// and compares.
//
//   node tools/build.mjs            build dist/
//   node tools/build.mjs --verify   also prove two more builds are identical
import { mkdirSync, rmSync, readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** The files the site is made of, relative to the repository root. Nothing else is published. */
export const SITE_FILES = ['index.html', 'app.js', 'mailforge-core.js', '.nojekyll'];

export function build(outDir = join(ROOT, 'dist')) {
  const html = readFileSync(join(ROOT, 'index.html'), 'utf8');
  const scripts = [...html.matchAll(/<script src="([^"?]+)(?:\?[^"]*)?"><\/script>/g)].map((m) => m[1]).sort();
  const listed = SITE_FILES.filter((f) => f.endsWith('.js')).sort();
  if (JSON.stringify(scripts) !== JSON.stringify(listed)) throw new Error(`index.html loads ${scripts.join(', ')} but SITE_FILES lists ${listed.join(', ')}`);
  rmSync(outDir, { recursive: true, force: true });
  const manifest = [];
  for (const f of SITE_FILES) {
    const body = readFileSync(join(ROOT, f));
    if (body.includes(13)) throw new Error(`${f} has CRLF line endings`);
    mkdirSync(join(outDir, f, '..'), { recursive: true });
    writeFileSync(join(outDir, f), body);
    manifest.push(`${createHash('sha256').update(body).digest('hex')}  ${f}`);
  }
  return { outDir, manifest };
}

if (process.argv[1] && process.argv[1].endsWith('build.mjs')) {
  try {
    const { outDir, manifest } = build();
    console.log(`Built ${outDir}:\n` + manifest.join('\n'));
    if (process.argv.includes('--verify')) {
      const a = build(mkdtempSync(join(tmpdir(), 'mailforge-build-a-'))), b = build(mkdtempSync(join(tmpdir(), 'mailforge-build-b-')));
      for (const d of [a.outDir, b.outDir]) rmSync(d, { recursive: true, force: true });
      if (a.manifest.join('\n') !== manifest.join('\n') || b.manifest.join('\n') !== manifest.join('\n')) { console.error('Two builds differ.'); process.exit(1); }
      console.log('Reproducible: three builds produced identical files.');
    }
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}
