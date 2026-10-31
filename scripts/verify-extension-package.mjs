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
assert.equal(manifest.action.default_popup, 'index.html');
assert.equal(manifest.background, undefined, 'recipient handoff must not require a background worker');
assert.equal(manifest.web_accessible_resources, undefined, 'website pages must not load extension resources directly');
assert.ok(await readFile(path.join(packageRoot, 'recipient-content.js')), 'packaged recipient content script must exist');

const html = await readFile(path.join(packageRoot, manifest.action.default_popup), 'utf8');
const executableFiles = [...html.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi)].map(match => match[1]);
assert.ok(executableFiles.length > 0, 'popup must load its packaged executable bundle');
for (const source of executableFiles) {
  assert.ok(!/^(?:https?:)?\/\//i.test(source), `popup script must be local: ${source}`);
  assert.ok(await readFile(path.join(packageRoot, source)), `popup script must exist in package: ${source}`);
}
assert.doesNotMatch(html, /<script\b[^>]*>\s*[^<]/i, 'popup must not contain inline executable code');

const files = await readdir(packageRoot, { recursive: true });
assert.ok(files.some(file => file.endsWith('.js')), 'compiled JavaScript must ship with the extension');
assert.ok(files.some(file => file.endsWith('.css')), 'popup stylesheet must ship with the extension');
console.log('Extension package verified: local executable bundle and restricted manifest permissions.');
