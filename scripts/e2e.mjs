/**
 * End-to-end verification in a real browser.
 *
 * The unit and integration suites prove the crypto and the API in isolation. This
 * proves the claim that actually matters to a user and that neither of those can
 * check: that when the whole thing runs in a browser, the key never leaves it.
 *
 * Every request the page makes is intercepted and asserted against the key
 * material — URL, headers, and body. A passing run means the secret was not in any
 * of them. It also exercises the strict CSP for real: an inline-script or
 * eval-based regression would surface here as a console violation and fail the run,
 * where a header-only assertion would not notice.
 *
 * Usage:  node scripts/local-server.mjs 8788 &  node scripts/e2e.mjs
 */
import { chromium } from 'playwright';
import { existsSync, readdirSync } from 'node:fs';

const BASE = process.env.E2E_BASE ?? 'http://127.0.0.1:8788';

/**
 * Locate a Chromium to drive.
 *
 * Playwright's own resolution is correct wherever Playwright manages the
 * download — a CI runner after `playwright install`, a developer's machine — so
 * returning `undefined` is the right answer there, not a failure. The lookup
 * below exists only for environments that ship a preinstalled browser and point
 * at it with PLAYWRIGHT_BROWSERS_PATH, where the layout differs between builds.
 *
 * It must never throw. An earlier version read a hard-coded sandbox path
 * directly, which crashed the whole suite on any machine that did not happen to
 * have that directory — the browser was there, Playwright would have found it,
 * and the helper meant to help was the only thing in the way.
 */
function findChromium() {
  if (process.env.CHROMIUM_PATH) return process.env.CHROMIUM_PATH;

  const root = process.env.PLAYWRIGHT_BROWSERS_PATH;
  if (root === undefined || root === '0' || !existsSync(root)) return undefined;

  try {
    const dirs = readdirSync(root)
      .filter((d) => d.startsWith('chromium-'))
      .sort()
      .reverse();
    for (const dir of dirs) {
      for (const sub of ['chrome-linux64/chrome', 'chrome-linux/chrome', 'chrome-mac/Chromium.app/Contents/MacOS/Chromium']) {
        const candidate = `${root}/${dir}/${sub}`;
        if (existsSync(candidate)) return candidate;
      }
    }
  } catch {
    // Unreadable or unexpected layout: fall back to Playwright's resolution.
  }
  return undefined;
}

let failures = 0;
let checks = 0;
function check(name, condition, detail = '') {
  checks++;
  if (condition) {
    process.stdout.write(`  ok   ${name}\n`);
  } else {
    failures++;
    process.stdout.write(`  FAIL ${name}${detail ? ` — ${detail}` : ''}\n`);
  }
}

/** Record every request so the key can be searched for across all of them. */
function watch(context) {
  const seen = [];
  context.on('request', (request) => {
    seen.push({
      url: request.url(),
      method: request.method(),
      headers: JSON.stringify(request.headers()),
      body: request.postData() ?? '',
    });
  });
  return seen;
}

function collectConsole(page, sink) {
  page.on('console', (msg) => {
    const text = msg.text();
    if (msg.type() === 'error' || /Content Security Policy|Refused to/i.test(text)) sink.push(text);
  });
  page.on('pageerror', (error) => sink.push(`pageerror: ${error.message}`));
}

const browser = await chromium.launch({
  executablePath: findChromium(),
  args: ['--no-sandbox', '--disable-dev-shm-usage'],
});

try {
  // ───────────────────────────── 1. link mode ─────────────────────────────
  process.stdout.write('\nlink-mode paste, markdown rendering\n');
  {
    const context = await browser.newContext();
    const requests = watch(context);
    const errors = [];
    const page = await context.newPage();
    collectConsole(page, errors);

    await page.goto(BASE, { waitUntil: 'networkidle' });
    const body = '# Title\n\nSome **bold** text and `code`.\n\n```python\nprint("hi")\n```\n';
    await page.fill('#body', body);
    await page.selectOption('#render', 'markdown');
    await page.selectOption('#expiry', '3600');
    await page.click('button[type="submit"]');
    await page.waitForSelector('#resultUrl', { timeout: 30_000 });

    const url = await page.inputValue('#resultUrl');
    check('produced a link with a fragment', url.includes('/p/') && url.includes('#'), url);
    const fragment = url.split('#')[1] ?? '';
    check('fragment is 43 base64url characters (32 bytes)', /^[A-Za-z0-9_-]{43}$/.test(fragment), fragment);

    // The central claim: the key appears in no request at all.
    const leaked = requests.filter(
      (r) => r.url.includes(fragment) || r.headers.includes(fragment) || r.body.includes(fragment),
    );
    check('key never appears in any request URL, header, or body', leaked.length === 0, JSON.stringify(leaked.slice(0, 2)));

    const plaintextLeak = requests.filter((r) => r.body.includes('Some **bold** text'));
    check('plaintext never appears in any request body', plaintextLeak.length === 0);

    const upload = requests.find((r) => r.method === 'POST' && r.url.includes('/api/pastes'));
    check('upload used a binary body, not JSON', upload !== undefined && !upload.headers.includes('application/json'));
    check('no console errors or CSP violations while composing', errors.length === 0, errors.join(' | '));

    // Read it back in a completely separate context: no shared storage, no cache.
    const reader = await browser.newContext();
    const readerRequests = watch(reader);
    const readerErrors = [];
    const readerPage = await reader.newPage();
    collectConsole(readerPage, readerErrors);
    await readerPage.goto(url, { waitUntil: 'networkidle' });
    await readerPage.waitForSelector('.markdown', { timeout: 30_000 });

    const heading = await readerPage.textContent('.markdown h1');
    check('markdown heading rendered', heading?.trim() === 'Title', heading ?? '');
    const bold = await readerPage.$('.markdown strong');
    check('markdown emphasis rendered as an element', bold !== null);
    const highlighted = await readerPage.$$('.markdown pre code span.hljs-string, .markdown pre code span[class^="hljs-"]');
    check('fenced python block was syntax highlighted', highlighted.length > 0, `${highlighted.length} spans`);
    check('no console errors or CSP violations while reading', readerErrors.length === 0, readerErrors.join(' | '));

    const readerLeak = readerRequests.filter(
      (r) => r.url.includes(fragment) || r.headers.includes(fragment) || r.body.includes(fragment),
    );
    check('reader also never transmits the key', readerLeak.length === 0, JSON.stringify(readerLeak.slice(0, 2)));

    await context.close();
    await reader.close();
  }

  // ─────────────────────── 2. XSS attempt in a paste ───────────────────────
  process.stdout.write('\nhostile paste content is neutralised\n');
  {
    const context = await browser.newContext();
    const page = await context.newPage();
    const errors = [];
    collectConsole(page, errors);
    await page.goto(BASE, { waitUntil: 'networkidle' });

    await page.evaluate(() => {
      window.__xss = false;
    });

    const hostile = [
      '# Heading',
      '',
      '<img src=x onerror="window.__xss=true">',
      '<script>window.__xss=true</script>',
      '<a href="javascript:window.__xss=true">click</a>',
      '<iframe src="data:text/html,<script>parent.__xss=true</script>"></iframe>',
      '<div style="position:fixed;inset:0;background:red">overlay</div>',
      '[link](javascript:window.__xss=true)',
    ].join('\n');

    await page.fill('#body', hostile);
    await page.selectOption('#render', 'markdown');
    await page.click('button[type="submit"]');
    await page.waitForSelector('#resultUrl', { timeout: 30_000 });
    const url = await page.inputValue('#resultUrl');

    const victim = await browser.newContext();
    const victimPage = await victim.newPage();
    const victimErrors = [];
    collectConsole(victimPage, victimErrors);
    await victimPage.goto(url, { waitUntil: 'networkidle' });
    await victimPage.waitForSelector('.markdown', { timeout: 30_000 });
    await victimPage.waitForTimeout(600);

    const executed = await victimPage.evaluate(() => Boolean(window.__xss));
    check('no injected script executed', executed === false);
    check('no <script> survived sanitising', (await victimPage.$$('.markdown script')).length === 0);
    check('no <img> survived sanitising', (await victimPage.$$('.markdown img')).length === 0);
    check('no <iframe> survived sanitising', (await victimPage.$$('.markdown iframe')).length === 0);
    check('no style attribute survived sanitising', (await victimPage.$$('.markdown [style]')).length === 0);
    const hrefs = await victimPage.$$eval('.markdown a', (as) => as.map((a) => a.getAttribute('href') ?? ''));
    check('no javascript: URL survived', hrefs.every((h) => !h.toLowerCase().startsWith('javascript:')), hrefs.join(','));
    const rels = await victimPage.$$eval('.markdown a', (as) => as.map((a) => a.getAttribute('rel') ?? ''));
    check('surviving links carry noreferrer', rels.every((r) => r.includes('noreferrer')), rels.join(','));
    check('the heading still rendered, so sanitising did not gut the content',
      (await victimPage.textContent('.markdown h1'))?.trim() === 'Heading');

    await context.close();
    await victim.close();
  }

  // ─────────────────────────── 3. burn after read ───────────────────────────
  process.stdout.write('\nburn-after-read\n');
  {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(BASE, { waitUntil: 'networkidle' });
    await page.fill('#body', 'this message will self destruct');
    await page.check('#burn');
    await page.click('button[type="submit"]');
    await page.waitForSelector('#resultUrl', { timeout: 30_000 });
    const url = await page.inputValue('#resultUrl');

    const first = await browser.newContext();
    const firstPage = await first.newPage();
    await firstPage.goto(url, { waitUntil: 'networkidle' });
    const warned = await firstPage.textContent('.banner.warn');
    check('warns before consuming the single read', /single-use/i.test(warned ?? ''), (warned ?? '').slice(0, 60));
    check('did not fetch the paste before the click',
      (await firstPage.$('pre.code')) === null);

    await firstPage.click('button.primary');
    await firstPage.waitForSelector('pre.code', { timeout: 30_000 });
    const shown = await firstPage.textContent('pre.code');
    check('content decrypted on the one permitted read', shown?.includes('self destruct') === true);

    const second = await browser.newContext();
    const secondPage = await second.newPage();
    await secondPage.goto(url, { waitUntil: 'networkidle' });
    await secondPage.waitForSelector('.banner.warn', { timeout: 30_000 });
    const gone = await secondPage.textContent('.banner.warn');
    check('second visit reports the paste is gone', /not here/i.test(gone ?? ''), (gone ?? '').slice(0, 60));

    await context.close();
    await first.close();
    await second.close();
  }

  // ──────────────────────────── 4. password layer ────────────────────────────
  process.stdout.write('\npassword layer\n');
  {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(BASE, { waitUntil: 'networkidle' });
    await page.fill('#body', 'guarded by two factors');
    await page.fill('#password', 'correct horse battery staple');
    await page.click('button[type="submit"]');
    await page.waitForSelector('#resultUrl', { timeout: 60_000 });
    const url = await page.inputValue('#resultUrl');

    const reader = await browser.newContext();
    const readerPage = await reader.newPage();
    const readerRequests = watch(reader);
    await readerPage.goto(url, { waitUntil: 'networkidle' });
    await readerPage.waitForSelector('#unlock', { timeout: 30_000 });
    check('prompts for the password', true);

    await readerPage.fill('#unlock', 'wrong password');
    await readerPage.click('button[type="submit"]');
    await readerPage.waitForSelector('.status.error', { timeout: 60_000 });
    check('rejects a wrong password', /did not work/i.test((await readerPage.textContent('.status.error')) ?? ''));

    await readerPage.fill('#unlock', 'correct horse battery staple');
    await readerPage.click('button[type="submit"]');
    await readerPage.waitForSelector('pre.code', { timeout: 60_000 });
    check('accepts the right password', (await readerPage.textContent('pre.code'))?.includes('two factors') === true);
    check('password never appeared in a request',
      readerRequests.every((r) => !r.body.includes('correct horse') && !r.url.includes('correct')));

    await context.close();
    await reader.close();
  }

  // ─────────────────── 5. recipient mode (post-quantum path) ───────────────────
  process.stdout.write('\nrecipient mode with X-Wing\n');
  {
    // The recipient creates an identity and publishes its public key.
    const recipient = await browser.newContext();
    const recipientPage = await recipient.newPage();
    await recipientPage.goto(`${BASE}/identity`, { waitUntil: 'networkidle' });
    await recipientPage.click('button.primary');
    await recipientPage.waitForSelector('.fingerprint', { timeout: 60_000 });
    const fingerprint = (await recipientPage.textContent('.fingerprint'))?.trim() ?? '';
    check('identity has a readable grouped fingerprint', /^[A-Z2-9]{5}-[A-Z2-9]{5}-[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(fingerprint), fingerprint);

    const publicKey = await recipientPage.inputValue('textarea.result-url');
    check('public key is a cpb1pub_ string of the expected size',
      publicKey.startsWith('cpb1pub_') && publicKey.length > 4000, `${publicKey.length} chars`);

    // The sender addresses a paste to that key, with no key in the link.
    const sender = await browser.newContext();
    const senderPage = await sender.newPage();
    const senderRequests = watch(sender);
    await senderPage.goto(BASE, { waitUntil: 'networkidle' });
    await senderPage.fill('#body', 'addressed with a hybrid post-quantum KEM');
    await senderPage.fill('#recipient', publicKey);
    await senderPage.fill('#recipientLabel', 'the recipient');
    await senderPage.click('button:has-text("Add recipient")');
    await senderPage.waitForSelector('.status.ok', { timeout: 15_000 });
    const added = (await senderPage.textContent('.status.ok')) ?? '';
    check('sender sees the same fingerprint the recipient showed', added.includes(fingerprint), added.slice(0, 80));

    await senderPage.uncheck('#linkAccess');
    await senderPage.click('button[type="submit"]');
    await senderPage.waitForSelector('#resultUrl', { timeout: 60_000 });
    const url = await senderPage.inputValue('#resultUrl');
    check('link carries no fragment when link access is off', !url.includes('#'), url);
    check('plaintext was not uploaded', senderRequests.every((r) => !r.body.includes('hybrid post-quantum')));

    // The recipient opens it using only their stored identity.
    const recipientReader = await recipient.newPage();
    await recipientReader.goto(url, { waitUntil: 'networkidle' });
    await recipientReader.waitForSelector('pre.code', { timeout: 60_000 });
    check('recipient decrypted it with their identity alone',
      (await recipientReader.textContent('pre.code'))?.includes('hybrid post-quantum KEM') === true);
    const banner = (await recipientReader.textContent('.banner')) ?? '';
    check('viewer reports the hybrid KEM path', /X-Wing/.test(banner), banner.slice(0, 90));

    // A stranger with the link and no identity gets nothing.
    const stranger = await browser.newContext();
    const strangerPage = await stranger.newPage();
    await strangerPage.goto(url, { waitUntil: 'networkidle' });
    await strangerPage.waitForSelector('.banner.warn', { timeout: 30_000 });
    check('a stranger holding the link cannot open it',
      /No key in this link/i.test((await strangerPage.textContent('.banner.warn')) ?? ''));

    await recipient.close();
    await sender.close();
    await stranger.close();
  }

  // ──────────────────────── 6. signed paste + attachment ────────────────────────
  process.stdout.write('\nsigned paste with an attachment\n');
  {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(`${BASE}/identity`, { waitUntil: 'networkidle' });
    await page.click('button.primary');
    await page.waitForSelector('.fingerprint', { timeout: 60_000 });

    await page.goto(BASE, { waitUntil: 'networkidle' });
    await page.fill('#body', 'signed and carrying a file');
    await page.check('#sign');
    await page.setInputFiles('#files', {
      name: '../../evil‮gnp.exe',
      mimeType: 'application/octet-stream',
      buffer: Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]),
    });
    await page.waitForSelector('ul.files li', { timeout: 10_000 });
    await page.click('button[type="submit"]');
    await page.waitForSelector('#resultUrl', { timeout: 60_000 });
    const url = await page.inputValue('#resultUrl');

    const reader = await browser.newContext();
    const readerPage = await reader.newPage();
    await readerPage.goto(url, { waitUntil: 'networkidle' });
    await readerPage.waitForSelector('pre.code', { timeout: 60_000 });
    const banner = (await readerPage.textContent('.banner')) ?? '';
    check('reader sees a verified signature', /Signed by/.test(banner), banner.slice(0, 80));
    const names = await readerPage.$$eval('ul.files .name', (els) => els.map((e) => e.textContent ?? ''));
    check('attachment is listed', names.length === 1, names.join(','));
    check('filename was stripped of traversal and bidi override',
      names[0] === 'evilgnp.exe', JSON.stringify(names[0]));

    await context.close();
    await reader.close();
  }

  process.stdout.write(`\n${checks - failures}/${checks} checks passed\n`);
} finally {
  await browser.close();
}

process.exit(failures === 0 ? 0 : 1);
