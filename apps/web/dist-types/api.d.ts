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
    rateLimit: {
        windowSeconds: number;
        maxWrites: number;
    };
}
export declare class ApiError extends Error {
    readonly status: number;
    readonly retryAfter?: number | undefined;
    constructor(status: number, message: string, retryAfter?: number | undefined);
}
export declare function fetchConfig(): Promise<ServerConfig>;
export interface UploadResult {
    id: string;
    burn: boolean;
    expiresAt: number;
    size: number;
}
export declare function uploadEnvelope(envelope: Uint8Array, options: {
    expiresIn: number;
    burn: boolean;
}): Promise<UploadResult>;
export interface FetchedPaste {
    envelope: Uint8Array;
    burned: boolean;
    expiresAt: number | null;
}
export declare function fetchEnvelope(id: string): Promise<FetchedPaste>;
/**
 * Check whether a paste exists without consuming it.
 *
 * Used before the viewer fetches a burn paste so the user can be warned that
 * opening it destroys it, rather than discovering that after the fact.
 */
export declare function probePaste(id: string): Promise<{
    exists: boolean;
    burn: boolean;
    size: number;
}>;
//# sourceMappingURL=api.d.ts.map