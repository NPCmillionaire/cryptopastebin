/**
 * Calls to the paste API.
 *
 * Envelopes travel as raw `application/octet-stream` bodies rather than base64 in
 * JSON: base64 would add a third to every upload for no benefit, since the bytes
 * are already opaque.
 *
 * @module
 */

export interface ServerConfig {
  maxEnvelopeBytes: number;
  expiryOptions: number[];
  defaultExpiry: number;
  rateLimit: { windowSeconds: number; maxWrites: number };
}

export class ApiError extends Error {
  constructor(readonly status: number, message: string, readonly retryAfter?: number) {
    super(message);
    this.name = 'ApiError';
  }
}

async function errorFrom(response: Response): Promise<ApiError> {
  let message = `request failed with status ${response.status}`;
  let retryAfter: number | undefined;
  try {
    const body = (await response.json()) as { error?: string; retryAfter?: number };
    if (typeof body.error === 'string') message = body.error;
    if (typeof body.retryAfter === 'number') retryAfter = body.retryAfter;
  } catch {
    // Non-JSON error body; the status-derived message stands.
  }
  return new ApiError(response.status, message, retryAfter);
}

export async function fetchConfig(): Promise<ServerConfig> {
  const response = await fetch('/api/config', { headers: { Accept: 'application/json' } });
  if (!response.ok) throw await errorFrom(response);
  return (await response.json()) as ServerConfig;
}

export interface UploadResult {
  id: string;
  burn: boolean;
  expiresAt: number;
  size: number;
}

export async function uploadEnvelope(
  envelope: Uint8Array,
  options: { expiresIn: number; burn: boolean },
): Promise<UploadResult> {
  const query = new URLSearchParams({ expiresIn: String(options.expiresIn) });
  if (options.burn) query.set('burn', '1');

  const response = await fetch(`/api/pastes?${query.toString()}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: envelope as unknown as BodyInit,
    // The key is in the fragment and never sent, but this also keeps the paste id
    // out of any referrer for good measure.
    referrerPolicy: 'no-referrer',
    cache: 'no-store',
  });
  if (!response.ok) throw await errorFrom(response);
  return (await response.json()) as UploadResult;
}

export interface FetchedPaste {
  envelope: Uint8Array;
  burned: boolean;
  expiresAt: number | null;
}

export async function fetchEnvelope(id: string): Promise<FetchedPaste> {
  const response = await fetch(`/api/pastes/${encodeURIComponent(id)}`, {
    headers: { Accept: 'application/octet-stream' },
    referrerPolicy: 'no-referrer',
    cache: 'no-store',
  });
  if (!response.ok) throw await errorFrom(response);
  const expiresAt = Number(response.headers.get('X-Paste-Expires-At'));
  return {
    envelope: new Uint8Array(await response.arrayBuffer()),
    burned: response.headers.get('X-Paste-Burn') === '1',
    expiresAt: Number.isFinite(expiresAt) && expiresAt > 0 ? expiresAt : null,
  };
}

/**
 * Check whether a paste exists without consuming it.
 *
 * Used before the viewer fetches a burn paste so the user can be warned that
 * opening it destroys it, rather than discovering that after the fact.
 */
export async function probePaste(id: string): Promise<{ exists: boolean; burn: boolean; size: number }> {
  const response = await fetch(`/api/pastes/${encodeURIComponent(id)}`, {
    method: 'HEAD',
    referrerPolicy: 'no-referrer',
    cache: 'no-store',
  });
  if (!response.ok) return { exists: false, burn: false, size: 0 };
  return {
    exists: true,
    burn: response.headers.get('X-Paste-Burn') === '1',
    size: Number(response.headers.get('Content-Length') ?? 0),
  };
}
