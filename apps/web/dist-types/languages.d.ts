/**
 * A curated highlight.js language set.
 *
 * Registered explicitly rather than importing the full bundle, which is around a
 * megabyte for roughly 190 grammars. On a page whose first job is to decrypt
 * something, shipping 190 grammars to highlight one is the wrong trade.
 *
 * @module
 */
import hljs from 'highlight.js/lib/core';
/** Wire value → display label. The wire value is what goes in the manifest. */
export declare const LANGUAGES: ReadonlyArray<readonly [string, string]>;
export declare function ensureLanguages(): typeof hljs;
export declare function isKnownLanguage(name: string | null): boolean;
//# sourceMappingURL=languages.d.ts.map