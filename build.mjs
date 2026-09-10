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
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, 'dist');
mkdirSync(outDir, { recursive: true });

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
//
// The one field the source cannot supply is `entry`: in-source it reads 'inline' because the
// plugin is defined in the same module, while the published manifest must point at the built
// bundle the loader fetches.
import { writeFileSync } from 'node:fs';

const pack = (await import(join(outDir, 'pack.mjs'))).default;
const ENTRY = 'dist/pack.mjs';
// `author` is a PACK-level field; the schema rejects it on a nested plugin. It stays in the
// source manifests because definePlugin's type carries it and it documents the plugin in place.
const withEntry = ({ author, ...m }) => ({
    ...m,
    platforms: {
        ...m.platforms,
        web: { ...m.platforms.web, entry: ENTRY },
        desktop: { ...m.platforms.desktop, entry: ENTRY },
    },
});

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
    platforms: withEntry(first).platforms,
    distribution: {
        kind: 'git',
        repository: 'https://github.com/Vineyard-Intelligence/pluginpack-otx',
        ref: `v${pack.version}`,
        path: 'plugins/otx.manifest.json',
    },
    plugins: pack.plugins.map((p) => withEntry(p.manifest)),
};

const manifestPath = join(here, 'plugins', 'otx.manifest.json');
writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Wrote plugins/otx.manifest.json (${manifest.plugins.length} plugins, v${manifest.version})`);
