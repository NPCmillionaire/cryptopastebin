/**
 * Typed request/response wrapper around the crypto worker.
 *
 * @module
 */
import type { ErrorKind, IdentityDescription, OpenRequest, OpenResponse, SealRequest, SealResponse } from './protocol.js';
export declare class CryptoError extends Error {
    readonly kind: ErrorKind;
    constructor(kind: ErrorKind, message: string);
}
declare class CryptoClient {
    private worker;
    private nextId;
    private readonly pending;
    private ensure;
    private call;
    seal(payload: SealRequest): Promise<SealResponse>;
    open(payload: OpenRequest): Promise<OpenResponse>;
    newIdentity(): Promise<IdentityDescription & {
        seed: Uint8Array;
    }>;
    describeIdentity(seed: Uint8Array): Promise<IdentityDescription>;
}
export declare const cryptoClient: CryptoClient;
export {};
//# sourceMappingURL=worker-client.d.ts.map