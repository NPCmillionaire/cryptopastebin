/**
 * A static check for the mistakes that would quietly break the design.
 *
 * None of these are things a type checker or a unit test would catch: a
 * `console.log` of a key still passes every test, and so does a `fetch` that puts
 * the fragment in a query string. They are cheap to introduce in a hurry and
 * invisible in review once a file is long enough, so they get an automated gate.
 *
 * Usage:  node scripts/audit-leaks.mjs
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { extname, join, relative, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const SKIP_DIRS = new Set(['node_modules', 'dist', 'dist-types', '.git', '.wrangler', '.scratch', 'coverage']);

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (['.ts', '.mjs', '.js', '.html'].includes(extname(full))) out.push(full);
  }
  return out;
}

const RULES = [
  {
    name: 'no console output in shipped source',
    why: 'Anything logged in the client can be read by an extension or a screen recording, and anything logged in the Worker lands in the operator’s log — which is exactly the party this design keeps ignorant.',
    include: (f) => /(apps\/web\/src|apps\/api\/src|packages\/crypto\/src)\//.test(f),
    pattern: /\bconsole\.(log|info|warn|error|debug|trace|dir|table)\s*\(/g,
  },
  {
    name: 'no secret material in a URL outside the fragment',
    why: 'A key or password in a path or query string reaches the access log, the CDN cache key, and any Referer header.',
    include: (f) => /(apps\/web\/src|apps\/api\/src)\//.test(f),
    pattern: /[?&](key|secret|password|pw|token|seed|fragment|linkKey)=/gi,
  },
  {
    name: 'no innerHTML outside the single sanitising module',
    why: 'Paste content is attacker-controlled and the page holds plaintext in memory, so every HTML sink must funnel through DOMPurify in render.ts.',
    include: (f) => /apps\/web\/src\//.test(f) && !/render\.ts$/.test(f),
    pattern: /\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b/g,
  },
  {
    name: 'no eval or dynamic code construction',
    why: 'The Content-Security-Policy forbids it; a local use would only fail at runtime in production.',
    include: (f) => /(apps\/web\/src|apps\/api\/src|packages\/crypto\/src)\//.test(f),
    pattern: /\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['"`]/g,
  },
  {
    name: 'no inline script or style in the HTML shell',
    why: 'Both are blocked by the CSP, and allowing either would be the easiest foothold for injected markup.',
    include: (f) => /apps\/web\/index\.html$/.test(f),
    pattern: /<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?\S[\s\S]*?<\/script>|<style[^>]*>|\son\w+\s*=/gi,
  },
  {
    name: 'no third-party origins in client source',
    why: 'The CSP allows none, and a CDN dependency would put the encryption code under someone else’s control.',
    include: (f) => /apps\/web\/(src\/|index\.html)/.test(f),
    pattern: /https?:\/\/(?!127\.0\.0\.1|localhost)[a-z0-9.-]+\.[a-z]{2,}/gi,
    allow: [/www\.w3\.org/, /http:\/\/127\.0\.0\.1/],
  },
  {
    name: 'crypto core stays free of storage and network APIs',
    why: 'The crypto package must be pure: a fetch or a localStorage read inside it would make the isolated audit of that package meaningless.',
    include: (f) => /packages\/crypto\/src\//.test(f),
    pattern: /\b(fetch|localStorage|sessionStorage|indexedDB|XMLHttpRequest|document)\b/g,
  },
  {
    name: 'no Math.random where randomness matters',
    why: 'Math.random is not a CSPRNG; every random value here must come from crypto.getRandomValues.',
    include: (f) => /(apps\/web\/src|apps\/api\/src|packages\/crypto\/src)\//.test(f),
    pattern: /Math\.random\s*\(/g,
  },
];

const files = walk(ROOT);
let failures = 0;

for (const rule of RULES) {
  const hits = [];
  for (const file of files.filter((f) => rule.include(relative(ROOT, f).replace(/\\/g, '/')))) {
    const text = readFileSync(file, 'utf8');
    const lines = text.split('\n');
    lines.forEach((line, index) => {
      // Comments are where these APIs get *discussed*; only real code counts.
      const stripped = line.replace(/^\s*(\/\/|\*|\/\*).*$/, '');
      for (const match of stripped.matchAll(rule.pattern)) {
        if (rule.allow?.some((a) => a.test(match[0]))) continue;
        hits.push(`${relative(ROOT, file)}:${index + 1}: ${line.trim().slice(0, 110)}`);
      }
    });
  }
  if (hits.length === 0) {
    process.stdout.write(`ok   ${rule.name}\n`);
  } else {
    failures++;
    process.stdout.write(`FAIL ${rule.name}\n     ${rule.why}\n`);
    for (const hit of hits.slice(0, 12)) process.stdout.write(`     ${hit}\n`);
    if (hits.length > 12) process.stdout.write(`     … and ${hits.length - 12} more\n`);
  }
}

process.stdout.write(failures === 0 ? '\nall checks passed\n' : `\n${failures} check(s) failed\n`);
process.exit(failures === 0 ? 0 : 1);
