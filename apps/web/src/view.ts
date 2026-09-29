/**
 * The paste viewer.
 *
 * @module
 */
import { fetchEnvelope, probePaste, ApiError } from './api.js';
import { append, clear, copyText, downloadBytes, el, formatBytes, formatExpiry } from './dom.js';
import { renderCode, renderMarkdown, renderPlain } from './render.js';
import { cryptoClient, CryptoError } from './worker-client.js';
import { loadSeed } from './identity-store.js';
import type { OpenResponse } from './protocol.js';

export function renderView(root: HTMLElement, id: string, fragment: string | null): void {
  clear(root);
  const status = el('p', { class: 'status busy', role: 'status' }, 'Looking up the paste…');
  const panel = el('div', { id: 'viewPanel' });
  append(root, status, panel);

  const identitySeed = loadSeed();

  function setStatus(message: string, kind: 'ok' | 'error' | 'busy' | '' = ''): void {
    status.className = kind === '' ? 'status' : `status ${kind}`;
    status.textContent = message;
  }

  void (async () => {
    const probe = await probePaste(id).catch(() => ({ exists: false, burn: false, size: 0 }));
    if (!probe.exists) {
      setStatus('', '');
      append(
        panel,
        el(
          'div',
          { class: 'banner warn' },
          el('p', {}, el('strong', {}, 'This paste is not here. ')),
          el(
            'p',
            {},
            'It expired, it was a single-use paste that has already been read, or the link is wrong. ' +
              'The server keeps no record of pastes that are gone, so there is nothing to recover.',
          ),
          link('Write a new paste', '/'),
        ),
      );
      return;
    }

    if (fragment === null && identitySeed === null) {
      setStatus('', '');
      append(
        panel,
        el(
          'div',
          { class: 'banner warn' },
          el('p', {}, el('strong', {}, 'No key in this link. ')),
          el(
            'p',
            {},
            'This paste is addressed to a specific public key, and this browser has no identity set up. ' +
              'Restore your identity from its backup on the identity page, then reload.',
          ),
          link('Identity', '/identity'),
        ),
      );
      return;
    }

    // A burn paste is fetched only on an explicit click. Fetching it on page load
    // would mean a preloaded tab, a restored session, or an accidental double-open
    // silently consumes the one read the sender had.
    if (probe.burn) {
      setStatus('', '');
      const open = el('button', { class: 'primary', type: 'button' }, 'Read it once');
      open.addEventListener('click', () => {
        open.disabled = true;
        void load();
      });
      append(
        panel,
        el(
          'div',
          { class: 'banner warn' },
          el('h2', {}, 'Single-use paste'),
          el(
            'p',
            {},
            `This paste (${formatBytes(probe.size)} of ciphertext) is destroyed by the first read. ` +
              'Once you continue, nobody — including the sender — can open it again. Do not reload after it opens.',
          ),
          el('div', { class: 'row' }, open),
        ),
      );
      return;
    }

    await load();
  })();

  async function load(): Promise<void> {
    clear(panel);
    setStatus('Downloading ciphertext…', 'busy');
    try {
      const fetched = await fetchEnvelope(id);
      setStatus('Decrypting in this tab…', 'busy');
      await decrypt(fetched.envelope, fetched.burned, fetched.expiresAt, null);
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        setStatus('That paste is already gone.', 'error');
      } else if (error instanceof Error) {
        setStatus(error.message, 'error');
      } else {
        setStatus('Could not download the paste.', 'error');
      }
    }
  }

  async function decrypt(
    envelope: Uint8Array,
    burned: boolean,
    expiresAt: number | null,
    password: string | null,
  ): Promise<void> {
    try {
      const opened = await cryptoClient.open({
        envelope,
        fragment,
        identitySeed: fragment === null ? identitySeed : null,
        password,
      });
      setStatus('', '');
      show(opened, burned, expiresAt);
    } catch (error) {
      if (error instanceof CryptoError && error.kind === 'usage' && error.message.includes('requires a password')) {
        setStatus('', '');
        promptForPassword(envelope, burned, expiresAt, null);
        return;
      }
      if (error instanceof CryptoError && error.kind === 'decrypt') {
        if (password !== null) {
          setStatus('', '');
          promptForPassword(envelope, burned, expiresAt, 'That password did not work.');
          return;
        }
        setStatus(
          'Could not decrypt. The key in the link is wrong or incomplete — check that the whole link was copied, including everything after the #.',
          'error',
        );
        return;
      }
      setStatus(error instanceof Error ? error.message : 'Could not decrypt the paste.', 'error');
    }
  }

  function promptForPassword(
    envelope: Uint8Array,
    burned: boolean,
    expiresAt: number | null,
    problem: string | null,
  ): void {
    clear(panel);
    const input = el('input', { type: 'password', id: 'unlock', autocomplete: 'current-password', placeholder: 'password' });
    const go = el('button', { class: 'primary', type: 'submit' }, 'Unlock');
    const note = el('p', { class: problem !== null ? 'status error' : 'status' }, problem ?? '');

    const form = el(
      'form',
      {},
      el('h2', {}, 'This paste needs a password'),
      el(
        'p',
        { class: 'hint' },
        'The password is combined with the key from the link. Unlocking takes a second or two — that delay is Argon2id ' +
          'making guessing expensive.',
      ),
      input,
      el('div', { class: 'row' }, go),
      note,
    );
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      if (input.value.length === 0) return;
      go.disabled = true;
      note.className = 'status busy';
      note.textContent = 'Deriving the key…';
      void decrypt(envelope, burned, expiresAt, input.value).finally(() => {
        go.disabled = false;
      });
    });
    append(panel, el('div', { class: 'card' }, form));
    input.focus();
  }

  function show(opened: OpenResponse, burned: boolean, expiresAt: number | null): void {
    clear(panel);

    const facts: string[] = [];
    if (burned) facts.push('single-use — this copy has been destroyed on the server');
    else if (expiresAt !== null) facts.push(`expires in ${formatExpiry(expiresAt)}`);
    if (opened.passwordProtected) facts.push('password-protected');
    if (fragment === null) facts.push('addressed to your key with X-Wing (ML-KEM-768 + X25519)');

    append(
      panel,
      el(
        'div',
        { class: burned ? 'banner warn' : 'banner' },
        el('p', {}, `Decrypted in your browser · ${facts.join(' · ') || 'no expiry set'}`),
        opened.authorFingerprint !== null
          ? el(
              'p',
              {},
              'Signed by ',
              el('span', { class: 'fingerprint' }, opened.authorFingerprint),
              ' — a valid ML-DSA-65 signature, which proves the holder of that key wrote this exact content. ' +
                'It does not tell you who that is unless you already know the fingerprint.',
            )
          : null,
        burned ? el('p', {}, el('strong', {}, 'Do not reload. '), 'This content exists only in this tab now.') : null,
      ),
    );

    const rendered =
      opened.render === 'markdown'
        ? renderMarkdown(opened.body)
        : opened.render === 'code'
          ? renderCode(opened.body, opened.lang)
          : renderPlain(opened.body);

    const copy = el('button', { type: 'button' }, 'Copy text');
    copy.addEventListener('click', () => {
      void copyText(opened.body).then((ok) => {
        copy.textContent = ok ? 'Copied' : 'Copy failed';
        setTimeout(() => (copy.textContent = 'Copy text'), 2000);
      });
    });

    const save = el('button', { type: 'button' }, 'Save as file');
    save.addEventListener('click', () => {
      downloadBytes(`paste-${id}.txt`, 'text/plain', new TextEncoder().encode(opened.body));
    });

    append(
      panel,
      el(
        'div',
        { class: 'card' },
        el('div', { class: 'row end' }, copy, save, link('New paste', '/')),
        rendered,
      ),
    );

    if (opened.attachments.length > 0) {
      const list = el('ul', { class: 'files' });
      for (const attachment of opened.attachments) {
        const get = el('button', { type: 'button', class: 'link' }, 'download');
        get.addEventListener('click', () => downloadBytes(attachment.name, attachment.mime, attachment.bytes));
        append(
          list,
          el(
            'li',
            {},
            el('span', { class: 'name' }, attachment.name),
            el('span', { class: 'size' }, formatBytes(attachment.bytes.length)),
            get,
          ),
        );
      }
      append(
        panel,
        el(
          'div',
          { class: 'card' },
          el('h2', {}, `Attachments (${opened.attachments.length})`),
          el(
            'p',
            { class: 'hint' },
            'Already decrypted and held in this tab. Filenames were stripped of path separators and text-direction ' +
              'overrides, which are the usual tricks for disguising what a file is.',
          ),
          list,
        ),
      );
    }
  }
}

function link(text: string, href: string): HTMLElement {
  const anchor = el('a', { href }, text);
  anchor.addEventListener('click', (event) => {
    event.preventDefault();
    history.pushState(null, '', href);
    dispatchEvent(new PopStateEvent('popstate'));
  });
  return el('p', {}, anchor);
}
