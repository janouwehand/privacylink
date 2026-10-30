import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifestPath = path.join(repositoryRoot, 'src', 'PrivacyLink.Web', 'extension', 'manifest.json');

test('extension manifest grants only clipboard write and the PrivacyLink host', async () => {
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));

  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual(manifest.permissions, ['clipboardWrite']);
  assert.deepEqual(manifest.host_permissions, ['https://privacylink.nl/*']);
  assert.equal(manifest.content_scripts, undefined);
  assert.equal(manifest.web_accessible_resources, undefined);
  assert.equal(manifest.background, undefined);
  assert.equal(manifest.action.default_popup, 'index.html');
  assert.doesNotMatch(JSON.stringify(manifest), /<all_urls>|webNavigation|history|"tabs"/i);
});
