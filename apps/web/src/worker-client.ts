/**
 * Typed request/response wrapper around the crypto worker.
 *
 * @module
 */
import type {
  ErrorKind,
  IdentityDescription,
  OpenRequest,
  OpenResponse,
  SealRequest,
  SealResponse,
  WorkerRequest,
  WorkerResponse,
} from './protocol.js';

export class CryptoError extends Error {
  constructor(readonly kind: ErrorKind, message: string) {
    super(message);
    this.name = 'CryptoError';
  }
}

/**
 * Distributive Omit: applied to a discriminated union, the built-in `Omit`
 * collapses the members into one object type and loses the discriminant's
 * correlation with `payload`. Mapping over the union preserves each variant.
 */
type UnsentRequest = WorkerRequest extends infer T ? (T extends { id: number } ? Omit<T, 'id'> : never) : never;

type Pending = { resolve: (value: never) => void; reject: (error: Error) => void };

class CryptoClient {
  private worker: Worker | undefined;
  private nextId = 1;
  private readonly pending = new Map<number, Pending>();

  private ensure(): Worker {
    if (this.worker === undefined) {
      this.worker = new Worker(new URL('./crypto-worker.ts', import.meta.url), { type: 'module' });
      this.worker.addEventListener('message', (event: MessageEvent<WorkerResponse>) => {
        const response = event.data;
        const entry = this.pending.get(response.id);
        if (entry === undefined) return;
        this.pending.delete(response.id);
        if (response.ok) entry.resolve(response.result as never);
        else entry.reject(new CryptoError(response.kind, response.message));
      });
      this.worker.addEventListener('error', () => {
        for (const [, entry] of this.pending) entry.reject(new Error('crypto worker failed'));
        this.pending.clear();
        // Drop the handle so the next call starts a fresh worker rather than
        // queueing against a dead one.
        this.worker?.terminate();
        this.worker = undefined;
      });
    }
    return this.worker;
  }

  private call<T>(message: UnsentRequest): Promise<T> {
    const worker = this.ensure();
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (value: never) => void, reject });
      worker.postMessage({ ...message, id } as WorkerRequest);
    });
  }

  seal(payload: SealRequest): Promise<SealResponse> {
    return this.call<SealResponse>({ op: 'seal', payload });
  }

  open(payload: OpenRequest): Promise<OpenResponse> {
    return this.call<OpenResponse>({ op: 'open', payload });
  }

  newIdentity(): Promise<IdentityDescription & { seed: Uint8Array }> {
    return this.call<IdentityDescription & { seed: Uint8Array }>({ op: 'newIdentity' });
  }

  describeIdentity(seed: Uint8Array): Promise<IdentityDescription> {
    return this.call<IdentityDescription>({ op: 'describeIdentity', payload: { seed } });
  }
}

export const cryptoClient = new CryptoClient();
