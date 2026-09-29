/**
 * Local identity storage.
 *
 * ## An honest note on where this key lives
 *
 * The master seed is kept in `localStorage`, and that is a real, unavoidable
 * trade-off rather than an oversight. `localStorage` is readable by any script
 * running on this origin, so a successful XSS reads the seed and every paste ever
 * addressed to it — not just the one currently open. The mitigations are the strict
 * CSP, the absence of any third-party script, and the single audited sanitisation
 * point in {@link ./render.js}, but none of those makes the seed *unreachable*.
 *
 * The alternatives were considered and each trades this risk for a worse one. A
 * non-extractable WebCrypto key cannot hold an X-Wing seed at all, because
 * WebCrypto has no ML-KEM. Keeping the seed only in memory means re-entering a
 * 32-byte secret on every visit, which in practice means users store it in a note
 * or a password manager and paste it in — no safer, and much worse ergonomically.
 * Wrapping it under a passphrase moves the risk rather than removing it: the
 * unwrapped seed still sits in the page's memory while a paste is open, which is
 * the window an XSS needs anyway.
 *
 * So the design states the limit plainly instead of implying a guarantee it cannot
 * make: link-mode pastes leave no long-term secret on the device at all, and that
 * is the mode to prefer unless recipient addressing is specifically needed.
 *
 * @module
 */
import { b64uDecodeExact, b64uEncode, MASTER_SEED_LEN } from '@cryptopaste/crypto';

const STORAGE_KEY = 'cryptopaste.identity.v1';
const CONTACTS_KEY = 'cryptopaste.contacts.v1';

export interface StoredContact {
  label: string;
  /** Encoded `cpb1pub_…` public identity. */
  publicIdentity: string;
  fingerprint: string;
}

function safeRead(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    // Private browsing, disabled site data, or a sandboxed context. Treated as
    // "no identity", which degrades to link-only mode rather than failing.
    return null;
  }
}

function safeWrite(key: string, value: string): boolean {
  try {
    localStorage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}

/** The stored master seed, or null when none is set. */
export function loadSeed(): Uint8Array | null {
  const encoded = safeRead(STORAGE_KEY);
  if (encoded === null) return null;
  try {
    return b64uDecodeExact(encoded, MASTER_SEED_LEN);
  } catch {
    return null;
  }
}

export function saveSeed(seed: Uint8Array): boolean {
  return safeWrite(STORAGE_KEY, b64uEncode(seed));
}

export function clearSeed(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Nothing to do; the caller reports the outcome from loadSeed().
  }
}

/** Saved recipients, so a public key need not be pasted in every time. */
export function loadContacts(): StoredContact[] {
  const raw = safeRead(CONTACTS_KEY);
  if (raw === null) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    // Validated field by field: this came from storage, which another script or a
    // previous version of this app could have written.
    return parsed.flatMap((entry): StoredContact[] => {
      if (typeof entry !== 'object' || entry === null) return [];
      const e = entry as Record<string, unknown>;
      if (typeof e['label'] !== 'string' || typeof e['publicIdentity'] !== 'string' || typeof e['fingerprint'] !== 'string') {
        return [];
      }
      if (!e['publicIdentity'].startsWith('cpb1pub_')) return [];
      return [{ label: e['label'].slice(0, 80), publicIdentity: e['publicIdentity'], fingerprint: e['fingerprint'] }];
    });
  } catch {
    return [];
  }
}

export function saveContacts(contacts: readonly StoredContact[]): boolean {
  return safeWrite(CONTACTS_KEY, JSON.stringify(contacts.slice(0, 200)));
}
