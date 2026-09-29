/**
 * Rendering decrypted content.
 *
 * ## The one place HTML is assigned
 *
 * This module holds the only `innerHTML` assignment in the client, and it happens
 * only on a string that DOMPurify has just returned. Both render paths converge
 * here for that reason.
 *
 * Why sanitise at all, when the paste was authenticated? Because authentication
 * proves the author wrote it, not that the author meant well. Anyone can create a
 * paste and send the link to anyone; a malicious author supplying
 * `<img onerror=…>` in Markdown is the expected case, not an edge case. And the
 * stakes are specific: this page holds decrypted plaintext and, for a recipient,
 * an identity's master seed. A single injected script reads both. The CSP is the
 * backstop, sanitising is the primary control, and neither is treated as
 * sufficient alone.
 *
 * Code rendering does not pass through DOMPurify's permissive path at all — the
 * highlighter is handed pre-escaped text and its output is span-only.
 *
 * @module
 */
import DOMPurify from 'dompurify';
import type { Config as PurifyConfig } from 'dompurify';
import { marked } from 'marked';
import { el } from './dom.js';
import { ensureLanguages, isKnownLanguage } from './languages.js';

const SANITISE_CONFIG: PurifyConfig = {
  ALLOWED_TAGS: [
    'a', 'blockquote', 'br', 'code', 'del', 'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'hr', 'li', 'ol', 'p', 'pre', 'span', 'strong', 'sub', 'sup', 'table', 'tbody',
    'td', 'th', 'thead', 'tr', 'ul',
  ],
  ALLOWED_ATTR: ['href', 'title', 'class', 'colspan', 'rowspan'],
  // No img: a remote image in a paste is a beacon that tells a third party the
  // paste was opened, from which address, and when. The CSP blocks the request
  // anyway; removing the tag means the reader is not left with a broken icon and
  // a false impression that something failed.
  FORBID_TAGS: ['img', 'style', 'script', 'iframe', 'object', 'embed', 'form', 'input', 'svg', 'math'],
  FORBID_ATTR: ['style', 'srcset', 'src', 'formaction', 'background'],
  ALLOW_DATA_ATTR: false,
  ALLOW_UNKNOWN_PROTOCOLS: false,
  ALLOWED_URI_REGEXP: /^(?:https?|mailto):/i,
};

/** Highlighter output is span-and-class only, so it gets a far narrower policy. */
const HIGHLIGHT_CONFIG: PurifyConfig = { ...SANITISE_CONFIG, ALLOWED_TAGS: ['span'], ALLOWED_ATTR: ['class'] };

let hooksInstalled = false;

function installHooks(): void {
  if (hooksInstalled) return;
  DOMPurify.addHook('afterSanitizeAttributes', (node) => {
    if (node instanceof Element && node.tagName === 'A') {
      // Every surviving link is cross-origin as far as this page is concerned.
      // `noreferrer` keeps the paste id out of the destination's logs, and
      // `noopener` stops the opened tab from reaching back through window.opener.
      node.setAttribute('rel', 'noopener noreferrer nofollow');
      node.setAttribute('target', '_blank');
    }
    // Classes are filtered to an allow-list so a paste cannot restyle the page by
    // borrowing the application's own class names — `card`, `banner`, or a
    // position:fixed overlay class would let hostile content impersonate the UI.
    // `language-*` survives because the fenced-block highlighter reads it; it
    // matches no rule in the stylesheet, so it is inert as far as layout goes.
    const cls = node instanceof Element ? node.getAttribute('class') : null;
    if (cls !== null && node instanceof Element) {
      const kept = cls
        .split(/\s+/)
        .filter((c) => c === 'hljs' || c.startsWith('hljs-') || /^language-[\w-]{1,20}$/.test(c));
      if (kept.length > 0) node.setAttribute('class', kept.join(' '));
      else node.removeAttribute('class');
    }
  });
  hooksInstalled = true;
}

/** Render a body as highlighted code. */
export function renderCode(body: string, lang: string | null): HTMLElement {
  const hljs = ensureLanguages();
  const code = el('code');
  if (isKnownLanguage(lang) && lang !== 'plaintext') {
    // `highlight` escapes its input, so the result contains only the original text
    // plus highlight.js's own span markup.
    const result = hljs.highlight(body, { language: lang!, ignoreIllegals: true });
    installHooks();
    code.innerHTML = DOMPurify.sanitize(result.value, HIGHLIGHT_CONFIG);
  } else {
    // No grammar to apply: a text node, which cannot be markup at all.
    code.textContent = body;
  }
  return el('pre', { class: 'code' }, code);
}

/** Render a body as sanitised Markdown. */
export function renderMarkdown(body: string): HTMLElement {
  installHooks();
  const raw = marked.parse(body, { async: false, gfm: true, breaks: false }) as string;
  const container = el('div', { class: 'markdown' });
  container.innerHTML = DOMPurify.sanitize(raw, SANITISE_CONFIG);

  // Highlight fenced blocks after sanitising, using the same escaped-input path as
  // renderCode. Doing it in this order means the highlighter never sees markup that
  // DOMPurify has not already cleared.
  const hljs = ensureLanguages();
  for (const block of container.querySelectorAll('pre > code')) {
    const className = block.getAttribute('class') ?? '';
    const match = /language-([\w-]+)/.exec(className);
    const lang = match?.[1] ?? null;
    if (!isKnownLanguage(lang) || lang === 'plaintext') continue;
    const text = block.textContent ?? '';
    const highlighted = hljs.highlight(text, { language: lang!, ignoreIllegals: true }).value;
    block.innerHTML = DOMPurify.sanitize(highlighted, HIGHLIGHT_CONFIG);
  }
  return container;
}

/** Render as plain text with no interpretation at all. */
export function renderPlain(body: string): HTMLElement {
  const pre = el('pre', { class: 'code' });
  pre.textContent = body;
  return pre;
}
