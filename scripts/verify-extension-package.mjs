import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packageRoot = path.join(repositoryRoot, 'src', 'PrivacyLink.Web', 'dist', 'privacy-link-extension', 'browser');
const manifest = JSON.parse(await readFile(path.join(packageRoot, 'manifest.json'), 'utf8'));

assert.equal(manifest.manifest_version, 3, 'extension must use Manifest V3');
assert.deepEqual(manifest.permissions, ['clipboardWrite'], 'extension permissions must remain minimal');
assert.deepEqual(manifest.host_permissions, ['https://privacylink.nl/*'], 'host access must be limited to the PrivacyLink origin');
assert.equal(manifest.content_scripts, undefined, 'extension must not install content scripts');
assert.equal(manifest.action.default_popup, 'index.html');

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
