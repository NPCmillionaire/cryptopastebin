/**
 * The identity page: create, inspect, back up, restore, or discard an identity.
 *
 * @module
 */
import { b64uDecodeExact, b64uEncode, MASTER_SEED_LEN } from '@cryptopaste/crypto';
import { append, clear, copyText, el } from './dom.js';
import { clearSeed, loadContacts, loadSeed, saveContacts, saveSeed } from './identity-store.js';
import { cryptoClient } from './worker-client.js';

export function renderIdentity(root: HTMLElement): void {
  clear(root);
  const panel = el('div', {});
  const status = el('p', { class: 'status', role: 'status' });
  append(root, panel, status);

  function setStatus(message: string, kind: 'ok' | 'error' | 'busy' | '' = ''): void {
    status.className = kind === '' ? 'status' : `status ${kind}`;
    status.textContent = message;
  }

  function draw(): void {
    clear(panel);
    const seed = loadSeed();

    append(
      panel,
      el(
        'div',
        { class: 'card' },
        el('h2', {}, 'What an identity is for'),
        el(
          'p',
          { class: 'hint' },
          'Without one, you can still create and read link-based pastes — those are already quantum-resistant, because ' +
            'they rest on a 256-bit symmetric key. An identity adds one thing: other people can encrypt a paste to your ' +
            'public key, so the link itself carries no secret. That exchange is where a hybrid post-quantum KEM earns its ' +
            'place, since a public key outlives any single message and a recording made today could be attacked years later.',
        ),
        el(
          'p',
          { class: 'hint' },
          'The trade-off is that the private seed has to live in this browser, where a successful script injection could ' +
            'read it. Link-only pastes leave nothing behind on the device at all.',
        ),
      ),
    );

    if (seed === null) {
      const create = el('button', { class: 'primary', type: 'button' }, 'Create an identity');
      create.addEventListener('click', () => {
        create.disabled = true;
        setStatus('Generating an X-Wing keypair and an ML-DSA-65 signing key…', 'busy');
        void cryptoClient
          .newIdentity()
          .then((identity) => {
            if (!saveSeed(identity.seed)) {
              setStatus('This browser refused to store the key — private browsing, or site data is blocked.', 'error');
              create.disabled = false;
              return;
            }
            setStatus('Created. Back up the recovery code below before you rely on it.', 'ok');
            draw();
          })
          .catch(() => {
            setStatus('Key generation failed.', 'error');
            create.disabled = false;
          });
      });
      append(panel, el('div', { class: 'card' }, el('h2', {}, 'No identity on this device'), el('div', { class: 'row' }, create)));
      drawRestore();
      drawContacts();
      return;
    }

    void cryptoClient.describeIdentity(seed).then((described) => {
      const publicBox = el('textarea', { class: 'result-url', readonly: true, rows: '4' });
      publicBox.value = described.publicIdentity;

      const copyPublic = el('button', { type: 'button', class: 'primary' }, 'Copy public key');
      copyPublic.addEventListener('click', () => {
        void copyText(described.publicIdentity).then((ok) => {
          copyPublic.textContent = ok ? 'Copied' : 'Copy failed';
          setTimeout(() => (copyPublic.textContent = 'Copy public key'), 2000);
        });
      });

      const backupBox = el('textarea', { class: 'result-url', readonly: true, rows: '2' });
      backupBox.value = `cpb1sec_${b64uEncode(seed)}`;
      const reveal = el('button', { type: 'button' }, 'Show recovery code');
      const backupWrap = el('div', { class: 'row' }, reveal);
      reveal.addEventListener('click', () => {
        clear(backupWrap);
        append(backupWrap, backupBox);
        backupBox.focus();
        backupBox.select();
      });

      const forget = el('button', { type: 'button' }, 'Remove from this browser');
      forget.addEventListener('click', () => {
        if (!confirm('Remove this identity? Without the recovery code, every paste addressed to it becomes unreadable.')) return;
        clearSeed();
        setStatus('Removed from this browser.', 'ok');
        draw();
      });

      append(
        panel,
        el(
          'div',
          { class: 'card' },
          el('h2', {}, 'Your fingerprint'),
          el('p', { class: 'fingerprint' }, described.fingerprint),
          el(
            'p',
            { class: 'hint' },
            'Read this to anyone who wants to send you a paste, over a channel where you already recognise them — a phone ' +
              'call, in person. Comparing it is the only step that rules out someone having handed them a substituted key, ' +
              'and no amount of cryptography below it can make up for skipping it.',
          ),
        ),
        el(
          'div',
          { class: 'card' },
          el('h2', {}, 'Public key'),
          el('p', { class: 'hint' }, 'Safe to publish anywhere. 1,216 bytes of X-Wing key plus a 1,952-byte ML-DSA-65 verification key.'),
          publicBox,
          el('div', { class: 'row' }, copyPublic),
        ),
        el(
          'div',
          { class: 'card' },
          el('h2', {}, 'Recovery code'),
          el(
            'p',
            { class: 'hint' },
            'Thirty-two bytes, from which both keys are re-derived. This is the whole secret: anyone holding it can read ' +
              'every paste addressed to you and sign as you. Store it in a password manager, not in a chat.',
          ),
          backupWrap,
        ),
        el('div', { class: 'card' }, el('h2', {}, 'Danger zone'), el('div', { class: 'row' }, forget)),
      );
      drawContacts();
    });
  }

  function drawRestore(): void {
    const input = el('input', { type: 'text', placeholder: 'cpb1sec_…', autocomplete: 'off', spellcheck: 'false' });
    const restore = el('button', { type: 'button' }, 'Restore');
    restore.addEventListener('click', () => {
      const value = input.value.trim();
      if (!value.startsWith('cpb1sec_')) {
        setStatus('A recovery code starts with cpb1sec_.', 'error');
        return;
      }
      try {
        const seed = b64uDecodeExact(value.slice('cpb1sec_'.length), MASTER_SEED_LEN);
        if (!saveSeed(seed)) {
          setStatus('This browser refused to store the key.', 'error');
          return;
        }
        setStatus('Restored.', 'ok');
        draw();
      } catch {
        setStatus('That recovery code is not valid.', 'error');
      }
    });
    append(
      panel,
      el('div', { class: 'card' }, el('h2', {}, 'Restore from a recovery code'), input, el('div', { class: 'row' }, restore)),
    );
  }

  function drawContacts(): void {
    const contacts = loadContacts();
    if (contacts.length === 0) return;
    const list = el('ul', { class: 'files' });
    for (const contact of contacts) {
      const remove = el('button', { type: 'button', class: 'link' }, 'forget');
      remove.addEventListener('click', () => {
        saveContacts(contacts.filter((c) => c.publicIdentity !== contact.publicIdentity));
        draw();
      });
      append(
        list,
        el(
          'li',
          {},
          el('span', { class: 'name' }, contact.label || 'unnamed'),
          el('span', { class: 'fingerprint' }, contact.fingerprint),
          remove,
        ),
      );
    }
    append(
      panel,
      el(
        'div',
        { class: 'card' },
        el('h2', {}, `Saved recipients (${contacts.length})`),
        el('p', { class: 'hint' }, 'Public keys only. Verify each fingerprint with its owner before trusting it.'),
        list,
      ),
    );
  }

  draw();
}
