/**
 * Entry point and router.
 *
 * Routing happens client-side over three paths — `/`, `/p/:id`, `/identity` — and
 * the Worker's asset handler is configured to serve the app shell for unknown
 * paths so a paste link loads the viewer directly.
 *
 * The fragment is read once here and never written into the DOM, a `history`
 * entry, an analytics call, or a fetch. There is nothing to strip afterwards
 * because it is never put anywhere.
 *
 * @module
 */
import './styles.css';
import { append, clear, el } from './dom.js';
import { renderCompose } from './compose.js';
import { renderIdentity } from './identity-view.js';
import { renderView } from './view.js';

const app = document.getElementById('app');
if (app === null) throw new Error('missing #app');

function chrome(): { header: HTMLElement; main: HTMLElement; footer: HTMLElement } {
  const header = el(
    'header',
    { class: 'site' },
    el('h1', {}, el('a', { href: '/' }, 'CryptoPaste')),
    el('p', { class: 'tagline' }, 'Encrypted in your browser. The server only ever sees ciphertext.'),
  );
  const suite = el(
    'p',
    { class: 'suite' },
    'XChaCha20-Poly1305 · X-Wing (ML-KEM-768 + X25519) · Argon2id · ML-DSA-65 · HKDF-SHA3-256',
  );
  const nav = el(
    'nav',
    { class: 'row' },
    navLink('New paste', '/'),
    navLink('Identity', '/identity'),
  );
  const main = el('main', {});
  const footer = el(
    'footer',
    { class: 'site' },
    el(
      'p',
      {},
      'The key lives in the part of the link after the # — browsers never send that to a server. ',
      'Lose it and the paste is unrecoverable, including by whoever runs this instance.',
    ),
  );
  clear(app!);
  append(app!, header, suite, nav, main, footer);
  return { header, main, footer };
}

function navLink(text: string, href: string): HTMLElement {
  const anchor = el('a', { href }, text);
  anchor.addEventListener('click', (event) => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
    event.preventDefault();
    history.pushState(null, '', href);
    route();
  });
  return anchor;
}

function route(): void {
  const { main } = chrome();
  const path = location.pathname;

  const pasteMatch = /^\/p\/([A-Za-z0-9_-]{22})\/?$/.exec(path);
  if (pasteMatch !== null) {
    // Read the fragment directly; it was never transmitted to reach this point.
    const fragment = location.hash.startsWith('#') ? location.hash.slice(1) : '';
    renderView(main, pasteMatch[1]!, fragment.length > 0 ? fragment : null);
    return;
  }

  if (path === '/identity' || path === '/identity/') {
    renderIdentity(main);
    return;
  }

  renderCompose(main);
}

addEventListener('popstate', route);
route();
