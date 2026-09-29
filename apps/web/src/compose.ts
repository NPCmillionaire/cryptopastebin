/**
 * The compose view.
 *
 * @module
 */
import { fetchConfig, uploadEnvelope, type ServerConfig } from './api.js';
import { append, clear, copyText, el, formatBytes } from './dom.js';
import { LANGUAGES } from './languages.js';
import { cryptoClient, CryptoError } from './worker-client.js';
import { decodeAndFingerprint } from './recipient.js';
import {
  loadContacts,
  loadSeed,
  saveContacts,
  type StoredContact,
} from './identity-store.js';
import type { WireAttachment } from './protocol.js';
import type { RenderMode } from '@cryptopaste/crypto';

const EXPIRY_LABELS = new Map<number, string>([
  [300, '5 minutes'],
  [3_600, '1 hour'],
  [86_400, '1 day'],
  [604_800, '1 week'],
  [2_592_000, '30 days'],
]);

interface Draft {
  attachments: WireAttachment[];
  recipients: StoredContact[];
}

export function renderCompose(root: HTMLElement): void {
  const draft: Draft = { attachments: [], recipients: [] };
  let config: ServerConfig | null = null;

  clear(root);

  const bodyInput = el('textarea', {
    id: 'body',
    placeholder: 'Paste or type here. Everything is encrypted in this tab before it is uploaded.',
    spellcheck: 'false',
    autocapitalize: 'off',
    autocomplete: 'off',
  });

  const langSelect = el(
    'select',
    { id: 'lang' },
    ...LANGUAGES.map(([value, label]) => el('option', { value }, label)),
  );

  const renderSelect = el(
    'select',
    { id: 'render' },
    el('option', { value: 'plain' }, 'Plain text'),
    el('option', { value: 'code', selected: true }, 'Highlighted code'),
    el('option', { value: 'markdown' }, 'Markdown'),
  );

  const expirySelect = el('select', { id: 'expiry' });

  const burnInput = el('input', { type: 'checkbox', id: 'burn' });
  const passwordInput = el('input', {
    type: 'password',
    id: 'password',
    placeholder: 'optional',
    autocomplete: 'new-password',
  });
  const signInput = el('input', { type: 'checkbox', id: 'sign' });
  const linkAccessInput = el('input', { type: 'checkbox', id: 'linkAccess', checked: true });

  const fileInput = el('input', { type: 'file', id: 'files', multiple: true });
  const fileList = el('ul', { class: 'files' });

  const recipientInput = el('input', {
    type: 'text',
    id: 'recipient',
    placeholder: 'cpb1pub_…',
    autocomplete: 'off',
    spellcheck: 'false',
  });
  const recipientLabel = el('input', { type: 'text', id: 'recipientLabel', placeholder: 'name (optional)', autocomplete: 'off' });
  const recipientList = el('ul', { class: 'files' });

  const status = el('p', { class: 'status', id: 'status', role: 'status' });
  const submit = el('button', { class: 'primary', type: 'submit' }, 'Encrypt and upload');
  const result = el('div', { id: 'result' });

  const identitySeed = loadSeed();

  function setStatus(message: string, kind: 'ok' | 'error' | 'busy' | '' = ''): void {
    status.className = kind === '' ? 'status' : `status ${kind}`;
    status.textContent = message;
  }

  function refreshFiles(): void {
    clear(fileList);
    let total = 0;
    for (const [index, file] of draft.attachments.entries()) {
      total += file.bytes.length;
      const remove = el('button', { type: 'button', class: 'link' }, 'remove');
      remove.addEventListener('click', () => {
        draft.attachments.splice(index, 1);
        refreshFiles();
      });
      append(
        fileList,
        el(
          'li',
          {},
          el('span', { class: 'name' }, file.name),
          el('span', { class: 'size' }, formatBytes(file.bytes.length)),
          remove,
        ),
      );
    }
    if (draft.attachments.length > 0) {
      append(fileList, el('li', {}, el('span', { class: 'size' }, `${draft.attachments.length} file(s), ${formatBytes(total)} total`)));
    }
  }

  function refreshRecipients(): void {
    clear(recipientList);
    for (const [index, contact] of draft.recipients.entries()) {
      const remove = el('button', { type: 'button', class: 'link' }, 'remove');
      remove.addEventListener('click', () => {
        draft.recipients.splice(index, 1);
        refreshRecipients();
      });
      append(
        recipientList,
        el(
          'li',
          {},
          el('span', { class: 'name' }, contact.label || 'unnamed'),
          el('span', { class: 'fingerprint' }, contact.fingerprint),
          remove,
        ),
      );
    }
  }

  fileInput.addEventListener('change', () => {
    const files = Array.from(fileInput.files ?? []);
    void (async () => {
      for (const file of files) {
        const bytes = new Uint8Array(await file.arrayBuffer());
        draft.attachments.push({ name: file.name, mime: file.type || 'application/octet-stream', bytes });
      }
      fileInput.value = '';
      refreshFiles();
      // Attachments are usually already compressed, so adding one turns
      // compression off by default; the user can still force it back on.
      setStatus('');
    })();
  });

  const addRecipient = el('button', { type: 'button' }, 'Add recipient');
  addRecipient.addEventListener('click', () => {
    const encoded = recipientInput.value.trim();
    if (encoded.length === 0) return;
    try {
      const fingerprint = decodeAndFingerprint(encoded);
      if (draft.recipients.some((r) => r.publicIdentity === encoded)) {
        setStatus('That recipient is already on the list.', 'error');
        return;
      }
      const contact: StoredContact = { label: recipientLabel.value.trim(), publicIdentity: encoded, fingerprint };
      draft.recipients.push(contact);
      const saved = loadContacts();
      if (!saved.some((c) => c.publicIdentity === encoded)) saveContacts([...saved, contact]);
      recipientInput.value = '';
      recipientLabel.value = '';
      refreshRecipients();
      setStatus(
        `Added ${fingerprint}. Confirm that fingerprint with them over a channel they already trust — ` +
          'a substituted key would encrypt the paste to whoever supplied it.',
        'ok',
      );
    } catch {
      setStatus('That does not look like a CryptoPaste public key.', 'error');
    }
  });

  const savedContacts = loadContacts();
  const contactPicker =
    savedContacts.length > 0
      ? el(
          'select',
          { id: 'savedContacts' },
          el('option', { value: '' }, `Saved recipients (${savedContacts.length})…`),
          ...savedContacts.map((c) => el('option', { value: c.publicIdentity }, `${c.label || 'unnamed'} · ${c.fingerprint}`)),
        )
      : null;
  contactPicker?.addEventListener('change', () => {
    if (contactPicker.value === '') return;
    recipientInput.value = contactPicker.value;
    const match = savedContacts.find((c) => c.publicIdentity === contactPicker.value);
    recipientLabel.value = match?.label ?? '';
    contactPicker.value = '';
  });

  const form = el(
    'form',
    { id: 'compose' },
    el('div', { class: 'card' }, el('h2', {}, 'Content'), bodyInput),

    el(
      'div',
      { class: 'card' },
      el('h2', {}, 'Presentation'),
      el(
        'div',
        { class: 'grid' },
        el('div', { class: 'field' }, el('label', { for: 'render' }, 'Render as'), renderSelect),
        el('div', { class: 'field' }, el('label', { for: 'lang' }, 'Language'), langSelect),
      ),
    ),

    el(
      'div',
      { class: 'card' },
      el('h2', {}, 'Attachments'),
      el('p', { class: 'hint' }, 'Files are encrypted inside the same envelope as the text.'),
      fileInput,
      fileList,
    ),

    el(
      'div',
      { class: 'card' },
      el('h2', {}, 'Lifetime'),
      el(
        'div',
        { class: 'grid' },
        el('div', { class: 'field' }, el('label', { for: 'expiry' }, 'Expires after'), expirySelect),
      ),
      el(
        'div',
        { class: 'check' },
        burnInput,
        el(
          'label',
          { for: 'burn' },
          'Destroy after the first read',
          el(
            'span',
            { class: 'note' },
            'The server deletes it before sending the bytes, so exactly one reader can ever get it. ' +
              'If that download fails halfway, the paste is gone — that is the cost of guaranteeing nobody got a second copy.',
          ),
        ),
      ),
    ),

    el(
      'div',
      { class: 'card' },
      el('h2', {}, 'Access'),
      el(
        'div',
        { class: 'check' },
        linkAccessInput,
        el(
          'label',
          { for: 'linkAccess' },
          'Anyone with the link can open it',
          el('span', { class: 'note' }, 'Turn this off to address the paste only to the recipients below. The link then carries no key at all.'),
        ),
      ),
      el(
        'div',
        { class: 'field' },
        el('label', { for: 'password' }, 'Password (optional, required in addition to the link)'),
        passwordInput,
        el(
          'span',
          { class: 'note' },
          'Stretched with Argon2id and combined with the link key — it is a second factor, not a replacement. ' +
            'Adding one takes a second or two of computation on both ends.',
        ),
      ),
      el(
        'div',
        { class: 'check' },
        signInput,
        el(
          'label',
          { for: 'sign' },
          identitySeed !== null ? 'Sign it with my identity' : 'Sign it with my identity (create one first)',
          el('span', { class: 'note' }, 'The signature sits inside the ciphertext, so only someone who can decrypt learns who wrote it.'),
        ),
      ),
      el('h2', {}, 'Recipients (post-quantum hybrid)'),
      el(
        'p',
        { class: 'hint' },
        'Addressing a paste to a public key uses X-Wing — ML-KEM-768 combined with X25519 — so a recording made today ' +
          'is not decryptable later by a quantum computer. Link-only pastes are already quantum-safe; this is for keys that outlive the link.',
      ),
      el('div', { class: 'grid' }, recipientInput, recipientLabel),
      el('div', { class: 'row' }, addRecipient, contactPicker),
      recipientList,
    ),

    el('div', { class: 'row end' }, submit),
    status,
    result,
  );

  if (identitySeed === null) signInput.disabled = true;

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    void submitDraft();
  });

  async function submitDraft(): Promise<void> {
    const body = bodyInput.value;
    if (body.length === 0 && draft.attachments.length === 0) {
      setStatus('Add some text or a file first.', 'error');
      return;
    }
    if (!linkAccessInput.checked && draft.recipients.length === 0) {
      setStatus('With link access off, the paste needs at least one recipient — otherwise nobody could open it.', 'error');
      return;
    }

    submit.disabled = true;
    clear(result);
    const password = passwordInput.value;
    setStatus(password.length > 0 ? 'Stretching the password with Argon2id, then encrypting…' : 'Encrypting…', 'busy');

    try {
      const sealed = await cryptoClient.seal({
        body,
        lang: langSelect.value,
        render: renderSelect.value as RenderMode,
        attachments: draft.attachments,
        recipients: draft.recipients.map((r) => r.publicIdentity),
        linkAccess: linkAccessInput.checked,
        password: password.length > 0 ? password : null,
        signSeed: signInput.checked ? identitySeed : null,
        compress: null,
      });

      if (config !== null && sealed.envelope.length > config.maxEnvelopeBytes) {
        setStatus(
          `Encrypted size is ${formatBytes(sealed.envelope.length)}, over this server's ${formatBytes(config.maxEnvelopeBytes)} limit.`,
          'error',
        );
        return;
      }

      setStatus(`Uploading ${formatBytes(sealed.envelope.length)} of ciphertext…`, 'busy');
      const uploaded = await uploadEnvelope(sealed.envelope, {
        expiresIn: Number(expirySelect.value),
        burn: burnInput.checked,
      });

      const url = `${location.origin}/p/${uploaded.id}${sealed.fragment !== null ? `#${sealed.fragment}` : ''}`;
      showResult(url, uploaded.expiresAt, burnInput.checked, sealed.fragment === null, password.length > 0);
      setStatus('Done. The server holds ciphertext only.', 'ok');
    } catch (error) {
      if (error instanceof CryptoError) setStatus(`Encryption failed: ${error.message}`, 'error');
      else if (error instanceof Error) setStatus(error.message, 'error');
      else setStatus('Something went wrong.', 'error');
    } finally {
      submit.disabled = false;
    }
  }

  function showResult(url: string, expiresAt: number, burn: boolean, recipientOnly: boolean, hasPassword: boolean): void {
    const urlBox = el('textarea', { class: 'result-url', readonly: true, rows: '2', id: 'resultUrl' });
    urlBox.value = url;

    const copy = el('button', { type: 'button', class: 'primary' }, 'Copy link');
    copy.addEventListener('click', () => {
      void copyText(url).then((ok) => {
        copy.textContent = ok ? 'Copied' : 'Copy failed — select it manually';
        setTimeout(() => (copy.textContent = 'Copy link'), 2000);
      });
    });

    const another = el('button', { type: 'button' }, 'New paste');
    another.addEventListener('click', () => renderCompose(root));

    const notes: (Node | string)[] = [
      el(
        'p',
        {},
        recipientOnly
          ? 'This link carries no key. Only the recipients you listed can open it.'
          : 'Everything after the # is the decryption key. It stays in the browser and is never sent to the server — which also means this server cannot help you recover it.',
      ),
    ];
    if (hasPassword) notes.push(el('p', {}, 'The reader will also need the password. Send it separately, over a different channel.'));
    if (burn) notes.push(el('p', {}, el('strong', {}, 'Single use: '), 'the first successful read destroys it.'));
    notes.push(el('p', {}, `Expires in about ${EXPIRY_LABELS.get(expiresAt - Math.floor(Date.now() / 1000)) ?? 'the selected window'}.`));

    append(
      result,
      el(
        'div',
        { class: 'banner good' },
        el('h2', {}, 'Your link'),
        urlBox,
        el('div', { class: 'row' }, copy, another),
        ...notes,
      ),
    );
    urlBox.focus();
    urlBox.select();
  }

  append(root, form);
  refreshFiles();
  refreshRecipients();

  void (async () => {
    try {
      config = await fetchConfig();
      clear(expirySelect);
      for (const seconds of config.expiryOptions) {
        append(
          expirySelect,
          el('option', { value: String(seconds), selected: seconds === config.defaultExpiry }, EXPIRY_LABELS.get(seconds) ?? `${seconds}s`),
        );
      }
    } catch {
      // The server is unreachable or misconfigured. Offer the common windows so
      // composing still works; the upload itself will report the real error.
      clear(expirySelect);
      for (const [seconds, label] of EXPIRY_LABELS) {
        append(expirySelect, el('option', { value: String(seconds), selected: seconds === 86_400 }, label));
      }
    }
  })();

}
