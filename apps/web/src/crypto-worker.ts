/**
 * The crypto worker. Every key operation happens here and nowhere else.
 *
 * @module
 */
import {
  createPaste,
  decodePublicIdentity,
  DecryptError,
  encodePublicIdentity,
  fingerprint,
  FormatError,
  generateIdentity,
  identityFromSeed,
  readPaste,
  UsageError,
  type PublicIdentity,
} from '@cryptopaste/crypto';
import type { ErrorKind, WorkerRequest, WorkerResponse } from './protocol.js';

function classify(error: unknown): { kind: ErrorKind; message: string } {
  if (error instanceof DecryptError) return { kind: 'decrypt', message: error.message };
  if (error instanceof FormatError) return { kind: 'format', message: error.message };
  if (error instanceof UsageError) return { kind: 'usage', message: error.message };
  return { kind: 'unknown', message: error instanceof Error ? error.message : 'unexpected error' };
}

async function handle(request: WorkerRequest): Promise<WorkerResponse> {
  try {
    switch (request.op) {
      case 'seal': {
        const p = request.payload;
        const recipients: PublicIdentity[] = p.recipients.map(decodePublicIdentity);
        const created = await createPaste({
          body: p.body,
          lang: p.lang,
          render: p.render,
          attachments: p.attachments,
          recipients,
          linkAccess: p.linkAccess,
          password: p.password ?? undefined,
          signWith: p.signSeed !== null ? identityFromSeed(p.signSeed) : undefined,
          ...(p.compress !== null ? { compress: p.compress } : {}),
        });
        return {
          id: request.id,
          ok: true,
          op: 'seal',
          result: { envelope: created.envelope, fragment: created.fragment ?? null },
        };
      }

      case 'open': {
        const p = request.payload;
        const key =
          p.fragment !== null
            ? ({ kind: 'fragment', fragment: p.fragment } as const)
            : ({ kind: 'identity', identity: identityFromSeed(p.identitySeed!) } as const);
        const read = await readPaste(p.envelope, key, { password: p.password ?? undefined });
        return {
          id: request.id,
          ok: true,
          op: 'open',
          result: {
            body: read.content.body,
            lang: read.content.lang,
            render: read.content.render,
            attachments: read.content.attachments.map((a) => ({ name: a.name, mime: a.mime, bytes: a.bytes })),
            authorFingerprint:
              read.author !== undefined
                ? // A fingerprint over the signing key alone is not comparable to an
                  // identity's full fingerprint, which covers both keys. The UI shows
                  // it only as an opaque value to compare against a known author's,
                  // so it is derived the same way with the KEM half left empty.
                  fingerprint({ kemPublicKey: new Uint8Array(0), signPublicKey: read.author.signPublicKey })
                : null,
            passwordProtected: read.passwordProtected,
          },
        };
      }

      case 'newIdentity': {
        const identity = generateIdentity();
        return {
          id: request.id,
          ok: true,
          op: 'newIdentity',
          result: {
            seed: identity.masterSeed,
            fingerprint: fingerprint(identity),
            publicIdentity: encodePublicIdentity(identity),
          },
        };
      }

      case 'describeIdentity': {
        const identity = identityFromSeed(request.payload.seed);
        return {
          id: request.id,
          ok: true,
          op: 'describeIdentity',
          result: { fingerprint: fingerprint(identity), publicIdentity: encodePublicIdentity(identity) },
        };
      }
    }
  } catch (error) {
    const { kind, message } = classify(error);
    return { id: request.id, ok: false, kind, message };
  }
}

self.addEventListener('message', (event: MessageEvent<WorkerRequest>) => {
  void handle(event.data).then((response) => {
    (self as unknown as Worker).postMessage(response);
  });
});
