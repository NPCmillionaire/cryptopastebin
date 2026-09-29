export interface StoredContact {
    label: string;
    /** Encoded `cpb1pub_…` public identity. */
    publicIdentity: string;
    fingerprint: string;
}
/** The stored master seed, or null when none is set. */
export declare function loadSeed(): Uint8Array | null;
export declare function saveSeed(seed: Uint8Array): boolean;
export declare function clearSeed(): void;
/** Saved recipients, so a public key need not be pasted in every time. */
export declare function loadContacts(): StoredContact[];
export declare function saveContacts(contacts: readonly StoredContact[]): boolean;
//# sourceMappingURL=identity-store.d.ts.map