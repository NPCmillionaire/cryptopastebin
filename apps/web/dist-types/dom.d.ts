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
export declare function el<K extends keyof HTMLElementTagNameMap>(tag: K, attrs?: Attrs, ...children: Child[]): HTMLElementTagNameMap[K];
export declare function append(parent: Node, ...children: Child[]): void;
export declare function clear(node: Node): void;
export declare function byId<T extends HTMLElement>(root: ParentNode, id: string): T;
/** Human-readable byte size. */
export declare function formatBytes(bytes: number): string;
/** Relative time for an expiry timestamp in seconds. */
export declare function formatExpiry(expiresAtSeconds: number): string;
/**
 * Trigger a download of decrypted bytes.
 *
 * The blob URL is revoked on the next tick. Leaving it alive would keep the
 * plaintext reachable from the document for as long as the tab lives, which
 * defeats the effort spent wiping buffers elsewhere.
 */
export declare function downloadBytes(name: string, mime: string, bytes: Uint8Array): void;
/** Copy text, falling back to a selection when the clipboard API is unavailable. */
export declare function copyText(text: string): Promise<boolean>;
export {};
//# sourceMappingURL=dom.d.ts.map