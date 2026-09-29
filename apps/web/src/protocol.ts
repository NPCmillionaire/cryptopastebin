/**
 * Message protocol between the page and the crypto worker.
 *
 * The heavy operations run off the main thread for one concrete reason: Argon2id
 * at the default cost takes roughly two seconds of straight-line computation, and
 * on the main thread that is two seconds of a frozen tab with no spinner, no
 * cancel, and a "page unresponsive" prompt on slower phones. Moving it to a worker
 * also keeps ML-KEM and ML-DSA off the main thread, which matters when a paste is
 * addressed to several recipients.
 *
 * @module
 */
import type { RenderMode } from '@cryptopaste/crypto';

export interface WireAttachment {
  name: string;
  mime: string;
  bytes: Uint8Array;
}

export interface SealRequest {
  body: string;
  lang: string | null;
  render: RenderMode;
  attachments: WireAttachment[];
  /** Encoded `cpb1pub_…` strings. */
  recipients: string[];
  linkAccess: boolean;
  password: string | null;
  /** Master seed of the signing identity, or null to leave the paste unsigned. */
  signSeed: Uint8Array | null;
  compress: boolean | null;
}

export interface SealResponse {
  envelope: Uint8Array;
  fragment: string | null;
}

export interface OpenRequest {
  envelope: Uint8Array;
  fragment: string | null;
  /** Master seed of a recipient identity, used when `fragment` is null. */
  identitySeed: Uint8Array | null;
  password: string | null;
}

export interface OpenResponse {
  body: string;
  lang: string | null;
  render: RenderMode;
  attachments: WireAttachment[];
  /** Fingerprint of the verified author, or null when the paste was unsigned. */
  authorFingerprint: string | null;
  passwordProtected: boolean;
}

export type WorkerRequest =
  | { id: number; op: 'seal'; payload: SealRequest }
  | { id: number; op: 'open'; payload: OpenRequest }
  | { id: number; op: 'newIdentity' }
  | { id: number; op: 'describeIdentity'; payload: { seed: Uint8Array } };

export interface IdentityDescription {
  fingerprint: string;
  publicIdentity: string;
}

/** Error categories the UI distinguishes. Anything cryptographic collapses to `decrypt`. */
export type ErrorKind = 'decrypt' | 'format' | 'usage' | 'unknown';

export type WorkerResponse =
  | { id: number; ok: true; op: 'seal'; result: SealResponse }
  | { id: number; ok: true; op: 'open'; result: OpenResponse }
  | { id: number; ok: true; op: 'newIdentity'; result: IdentityDescription & { seed: Uint8Array } }
  | { id: number; ok: true; op: 'describeIdentity'; result: IdentityDescription }
  | { id: number; ok: false; kind: ErrorKind; message: string };
