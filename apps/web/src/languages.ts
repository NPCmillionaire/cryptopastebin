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

import bash from 'highlight.js/lib/languages/bash';
import c from 'highlight.js/lib/languages/c';
import cpp from 'highlight.js/lib/languages/cpp';
import csharp from 'highlight.js/lib/languages/csharp';
import css from 'highlight.js/lib/languages/css';
import diff from 'highlight.js/lib/languages/diff';
import dockerfile from 'highlight.js/lib/languages/dockerfile';
import go from 'highlight.js/lib/languages/go';
import graphql from 'highlight.js/lib/languages/graphql';
import ini from 'highlight.js/lib/languages/ini';
import java from 'highlight.js/lib/languages/java';
import javascript from 'highlight.js/lib/languages/javascript';
import json from 'highlight.js/lib/languages/json';
import kotlin from 'highlight.js/lib/languages/kotlin';
import lua from 'highlight.js/lib/languages/lua';
import markdown from 'highlight.js/lib/languages/markdown';
import nix from 'highlight.js/lib/languages/nix';
import php from 'highlight.js/lib/languages/php';
import plaintext from 'highlight.js/lib/languages/plaintext';
import powershell from 'highlight.js/lib/languages/powershell';
import python from 'highlight.js/lib/languages/python';
import ruby from 'highlight.js/lib/languages/ruby';
import rust from 'highlight.js/lib/languages/rust';
import scala from 'highlight.js/lib/languages/scala';
import sql from 'highlight.js/lib/languages/sql';
import swift from 'highlight.js/lib/languages/swift';
import typescript from 'highlight.js/lib/languages/typescript';
import xml from 'highlight.js/lib/languages/xml';
import yaml from 'highlight.js/lib/languages/yaml';

/** Wire value → display label. The wire value is what goes in the manifest. */
export const LANGUAGES: ReadonlyArray<readonly [string, string]> = [
  ['plaintext', 'Plain text'],
  ['bash', 'Bash / Shell'],
  ['c', 'C'],
  ['cpp', 'C++'],
  ['csharp', 'C#'],
  ['css', 'CSS'],
  ['diff', 'Diff / patch'],
  ['dockerfile', 'Dockerfile'],
  ['go', 'Go'],
  ['graphql', 'GraphQL'],
  ['ini', 'INI / TOML'],
  ['java', 'Java'],
  ['javascript', 'JavaScript'],
  ['json', 'JSON'],
  ['kotlin', 'Kotlin'],
  ['lua', 'Lua'],
  ['markdown', 'Markdown'],
  ['nix', 'Nix'],
  ['php', 'PHP'],
  ['powershell', 'PowerShell'],
  ['python', 'Python'],
  ['ruby', 'Ruby'],
  ['rust', 'Rust'],
  ['scala', 'Scala'],
  ['sql', 'SQL'],
  ['swift', 'Swift'],
  ['typescript', 'TypeScript'],
  ['xml', 'HTML / XML'],
  ['yaml', 'YAML'],
];

let registered = false;

export function ensureLanguages(): typeof hljs {
  if (registered) return hljs;
  const grammars: Record<string, Parameters<typeof hljs.registerLanguage>[1]> = {
    bash, c, cpp, csharp, css, diff, dockerfile, go, graphql, ini, java, javascript,
    json, kotlin, lua, markdown, nix, php, plaintext, powershell, python, ruby,
    rust, scala, sql, swift, typescript, xml, yaml,
  };
  for (const [name, grammar] of Object.entries(grammars)) hljs.registerLanguage(name, grammar);
  hljs.configure({ classPrefix: 'hljs-', ignoreUnescapedHTML: false, throwUnescapedHTML: false });
  registered = true;
  return hljs;
}

export function isKnownLanguage(name: string | null): boolean {
  return name !== null && LANGUAGES.some(([value]) => value === name);
}
