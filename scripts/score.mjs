#!/usr/bin/env node
// CLI wrapper around the extension's engine, handy for testing heuristics:
//   npm run score -- https://paypa1.com/login "http://192.168.1.1"
//   echo https://example.com | npm run score
//   npm run score -- --json https://example.com
import { analyzeUrl } from '../extension/engine/classifier.js';

const args = process.argv.slice(2);
const json = args.includes('--json');
let urls = args.filter((a) => a !== '--json');
if (!urls.length && !process.stdin.isTTY) {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  urls = input.split(/\s+/).filter(Boolean);
}
if (!urls.length) {
  console.error('usage: npm run score -- [--json] <url> [url ...]');
  process.exit(2);
}

const color = process.stdout.isTTY
  ? { dangerous: '\x1b[31m', suspicious: '\x1b[33m', safe: '\x1b[32m', trusted: '\x1b[36m', reset: '\x1b[0m', dim: '\x1b[2m' }
  : new Proxy({}, { get: () => '' });

const results = urls.map((u) => analyzeUrl(u));
if (json) {
  console.log(JSON.stringify(results, null, 2));
} else {
  for (const r of results) {
    const c = color[r.verdict] ?? '';
    console.log(`${c}${String(r.score).padStart(3)}  ${r.verdict.toUpperCase().padEnd(10)}${color.reset} ${r.url}`);
    for (const s of r.signals) {
      if (s.weight) console.log(`${color.dim}       +${String(s.weight).padEnd(3)} ${s.title}: ${s.detail}${color.reset}`);
    }
  }
}
process.exitCode = results.some((r) => r.verdict === 'dangerous') ? 1 : 0;
