#!/usr/bin/env node
// Builds browser-specific packages from ./extension:
//   dist/chrome/   + dist/phishing-url-classifier-chrome-<version>.zip
//   dist/firefox/  + dist/phishing-url-classifier-firefox-<version>.zip
//
// Chrome needs `background.service_worker`; Firefox needs `background.scripts`
// and additionally gets the webRequest permissions used to read TLS state.
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const src = join(root, 'extension');
const dist = join(root, 'dist');
const base = JSON.parse(readFileSync(join(src, 'manifest.json'), 'utf8'));

const targets = {
  chrome: (m) => m,
  firefox: (m) => ({
    ...m,
    background: { scripts: ['background.js'], type: 'module' },
    permissions: [...m.permissions, 'webRequest', 'webRequestBlocking'],
    browser_specific_settings: {
      gecko: {
        id: 'phishing-url-classifier@daveyd347.github.io',
        strict_min_version: '115.0',
        data_collection_permissions: { required: ['none'] },
      },
    },
  }),
};

rmSync(dist, { recursive: true, force: true });
for (const [name, transform] of Object.entries(targets)) {
  const out = join(dist, name);
  mkdirSync(out, { recursive: true });
  cpSync(src, out, { recursive: true });
  writeFileSync(join(out, 'manifest.json'), `${JSON.stringify(transform(base), null, 2)}\n`);
  const zip = join(dist, `phishing-url-classifier-${name}-${base.version}.zip`);
  execFileSync('zip', ['-qr', '-X', zip, '.'], { cwd: out });
  console.log(`built ${name}: ${zip}`);
}
