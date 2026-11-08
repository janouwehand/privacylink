import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packageRoot = process.argv[2]
  ? path.resolve(process.cwd(), process.argv[2])
  : path.join(repositoryRoot, 'src', 'PrivacyLink.Web', 'dist', 'privacy-link-extension', 'browser');
const expectedVersion = process.argv[3];
const manifest = JSON.parse(await readFile(path.join(packageRoot, 'manifest.json'), 'utf8'));

assert.equal(manifest.manifest_version, 3, 'extension must use Manifest V3');
assert.match(manifest.version, /^\d+\.\d+\.\d+(?:\.\d+)?$/, 'extension version must be a Chrome-compatible version');
if (expectedVersion) {
  assert.equal(manifest.version, expectedVersion, 'extension package version must match the selected release tag');
}
assert.deepEqual(manifest.permissions, ['clipboardWrite'], 'extension permissions must remain minimal');
assert.deepEqual(manifest.host_permissions, ['https://privacylink.nl/*'], 'host access must be limited to the PrivacyLink origin');
assert.deepEqual(manifest.content_scripts, [{
  matches: ['https://privacylink.nl/s/*'],
  js: ['recipient-content.js'],
  run_at: 'document_start',
  all_frames: false,
  world: 'ISOLATED'
}], 'recipient handling must run only in the top frame of PrivacyLink share routes');
assert.equal(manifest.action.default_popup, undefined, 'toolbar action must open a persistent extension tab');
assert.deepEqual(manifest.background, { service_worker: 'background.js' });
assert.equal(manifest.web_accessible_resources, undefined, 'website pages must not load extension resources directly');
assert.ok(await readFile(path.join(packageRoot, 'recipient-content.js')), 'packaged recipient content script must exist');

assert.ok(await readFile(path.join(packageRoot, manifest.background.service_worker)), 'packaged background service worker must exist');
const html = await readFile(path.join(packageRoot, 'index.html'), 'utf8');
const executableFiles = [...html.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi)].map(match => match[1]);
assert.ok(executableFiles.length > 0, 'extension page must load its packaged executable bundle');
for (const source of executableFiles) {
  assert.ok(!/^(?:https?:)?\/\//i.test(source), `extension page script must be local: ${source}`);
  assert.ok(await readFile(path.join(packageRoot, source)), `extension page script must exist in package: ${source}`);
}
assert.doesNotMatch(html, /<script\b[^>]*>\s*[^<]/i, 'extension page must not contain inline executable code');

const files = await readdir(packageRoot, { recursive: true });
assert.ok(files.some(file => file.endsWith('.js')), 'compiled JavaScript must ship with the extension');
assert.ok(files.some(file => file.endsWith('.css')), 'extension page stylesheet must ship with the extension');
console.log('Extension package verified: local executable bundle and restricted manifest permissions.');
const provenance = JSON.parse(await readFile(path.join(packageRoot, 'ui-provenance.json'), 'utf8'));
assert.match(provenance.sourceRevision, /^[0-9a-f]{40}$/i, 'package must record its source revision');
assert.match(provenance.sharedUiVersion, /^sha256:[0-9a-f]{64}$/i, 'package must record the shared UI content version');
assert.equal(typeof provenance.sourceDirty, 'boolean', 'package must say whether its source tree was dirty');
assert.match(provenance.sourceTreeHash, /^sha256:[0-9a-f]{64}$/i, 'package must identify the complete source tree');
assert.ok(Array.isArray(provenance.dirtyPaths), 'package must list source changes when present');
assert.equal(provenance.sourceDirty, provenance.dirtyPaths.length > 0, 'dirty state must agree with the recorded changed paths');
