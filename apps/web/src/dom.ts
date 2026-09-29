/**
 * DOM construction helpers.
 *
 * Everything in the UI is built from these, and none of them accept HTML. That is
 * the point: the only place in the entire client that assigns `innerHTML` is
 * {@link ./render.js}, immediately after DOMPurify, so a reviewer looking for XSS
 * has exactly one line to audit instead of a codebase to read. Paste content is
 * attacker-controlled by definition — anyone can send anyone a link — and with
 * plaintext living in this page's memory, an injected script is the only way to
 * reach it without the key.
 *
 * @module
 */

type Attrs = Record<string, string | number | boolean | undefined>;
type Child = Node | string | null | undefined | false;

/** Create an element, setting attributes as attributes and text as text nodes. */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    if (value === true) node.setAttribute(name, '');
    else node.setAttribute(name, String(value));
  }
  append(node, ...children);
  return node;
}

export function append(parent: Node, ...children: Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    parent.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
}

export function clear(node: Node): void {
  while (node.firstChild !== null) node.removeChild(node.firstChild);
}

export function byId<T extends HTMLElement>(root: ParentNode, id: string): T {
  const found = root.querySelector<T>(`#${id}`);
  if (found === null) throw new Error(`missing element #${id}`);
  return found;
}

/** Human-readable byte size. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KiB', 'MiB', 'GiB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

/** Relative time for an expiry timestamp in seconds. */
export function formatExpiry(expiresAtSeconds: number): string {
  const seconds = expiresAtSeconds - Math.floor(Date.now() / 1000);
  if (seconds <= 0) return 'expired';
  const units: [number, string][] = [
    [86_400, 'day'],
    [3_600, 'hour'],
    [60, 'minute'],
  ];
  for (const [size, name] of units) {
    if (seconds >= size) {
      const n = Math.round(seconds / size);
      return `${n} ${name}${n === 1 ? '' : 's'}`;
    }
  }
  return `${seconds} seconds`;
}

/**
 * Trigger a download of decrypted bytes.
 *
 * The blob URL is revoked on the next tick. Leaving it alive would keep the
 * plaintext reachable from the document for as long as the tab lives, which
 * defeats the effort spent wiping buffers elsewhere.
 */
export function downloadBytes(name: string, mime: string, bytes: Uint8Array): void {
  // A generic type is forced regardless of the claimed one. An attachment's MIME
  // is author-supplied, and honouring `text/html` here would let a paste hand the
  // viewer a same-origin page to open.
  const safeMime = /^[\w.+-]+\/[\w.+-]+$/.test(mime) && !/html|xml|svg/i.test(mime) ? mime : 'application/octet-stream';
  const url = URL.createObjectURL(new Blob([bytes as unknown as BlobPart], { type: safeMime }));
  const link = el('a', { href: url, download: name || 'attachment' });
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/** Copy text, falling back to a selection when the clipboard API is unavailable. */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
