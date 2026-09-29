/**
 * Paste identifiers.
 *
 * 128 bits from the platform CSPRNG, rendered as 22 base64url characters.
 *
 * The id is chosen by the server and is *unrelated* to the decryption key. That
 * separation is worth stating because the tempting alternative — deriving the id
 * from the key with a hash — looks elegant and saves a few characters of URL. It
 * also means the id and the key are two views of one secret, so any future change
 * that weakens the derivation, or any place the id is logged alongside a hint of
 * the key, links them. Independent values cost nothing and cannot be correlated
 * at all: the server's id space and the client's key space never touch.
 *
 * 128 bits also makes enumeration hopeless, which matters because an id is the
 * only thing standing between an attacker and the ciphertext of every paste.
 *
 * @module
 */

const ID_BYTES = 16;
const ID_PATTERN = /^[A-Za-z0-9_-]{22}$/;

export function generateId(): string {
  const bytes = new Uint8Array(ID_BYTES);
  crypto.getRandomValues(bytes);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Validate an id from a URL path.
 *
 * Checked with an exact-length allow-list pattern rather than by handing the
 * string to the database and hoping the parameter binding saves us. A
 * strict-shape gate this early means a path segment never reaches the storage
 * layer, the R2 key builder, or a log line in a form its author did not expect.
 */
export function isValidId(value: string): boolean {
  return ID_PATTERN.test(value);
}
