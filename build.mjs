#!/usr/bin/env node
/**
 * Bundle src/main.ts (+ the local copy of the SDK, which it imports as './sdk')
 * into dist/pack.mjs for the marketplace.
 *
 * The SDK is inlined on purpose: the module is fetched by URL and runs in a worker
 * with no import map, so any bare specifier left in it would fail to resolve.
 *
 * Usage: node build.mjs
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, 'dist');
mkdirSync(outDir, { recursive: true });

// tldts and tldts-core are inlined into the bundle, and their MIT licence requires its copyright and
// permission notice in every copy. The bundle is fetched on its own by URL, so the notice goes at
// its top, read from the installed package so it follows the version actually bundled.
// THIRD_PARTY_NOTICES.md carries the same text for anyone reading the repo.
const tldtsDir = join(here, 'node_modules', 'tldts');
const tldtsVersion = JSON.parse(readFileSync(join(tldtsDir, 'package.json'), 'utf8')).version;
const tldtsLicense = readFileSync(join(tldtsDir, 'LICENSE'), 'utf8').trim();
const banner = [
    '/*!',
    ` * Includes tldts and tldts-core ${tldtsVersion} (https://github.com/remusao/tldts), MIT licence:`,
    ' *',
    ...tldtsLicense.split('\n').map((l) => ` * ${l}`.trimEnd()),
    ' *',
    ' * tldts embeds the Public Suffix List (https://publicsuffix.org/), MPL-2.0;',
    ' * source: https://publicsuffix.org/list/public_suffix_list.dat',
    ' */',
].join('\n');

execFileSync(
    'npx',
    [
        'esbuild',
        join(here, 'src', 'main.ts'),
        '--bundle',
        '--format=esm',
        '--target=es2022',
        '--platform=browser',
        '--minify',
        '--legal-comments=inline',
        `--banner:js=${banner}`,
        '--log-level=warning',
        `--outfile=${join(outDir, 'pack.mjs')}`,
    ],
    { stdio: 'inherit', cwd: here },
);

console.log('Built dist/pack.mjs');

// ---- plugins/otx.manifest.json -------------------------------------------------------
//
// Generated from the bundle rather than hand-written. The manifest and the code state the same
// facts twice — identifier, version, io types, scopes — and a hand-maintained copy drifts the
// moment one of them changes. The registry pins a commit and CI re-fetches the manifest to check
// it, so a drifted manifest is not a cosmetic problem: it is the document the marketplace shows
// and the install plan reads, describing code that does something else.
import { writeFileSync } from 'node:fs';

const pack = (await import(join(outDir, 'pack.mjs'))).default;
// `author` is a PACK-level field; the schema rejects it on a nested plugin. It stays in the
// source manifests because definePlugin's type carries it and it documents the plugin in place.
const member = ({ author, ...m }) => m;

const first = pack.plugins[0].manifest;
const manifest = {
    identifier: pack.identifier,
    content_type: 'vineyard:pluginpack',
    name: pack.name,
    version: pack.version,
    description: pack.description,
    author: first.author,
    license: first.license,
    icon: 'radar',
    platforms: first.platforms,
    plugins: pack.plugins.map((p) => member(p.manifest)),
};

const manifestPath = join(here, 'plugins', 'otx.manifest.json');
writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Wrote plugins/otx.manifest.json (${manifest.plugins.length} plugins, v${manifest.version})`);
