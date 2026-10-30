import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const workflow = await readFile(path.join(repositoryRoot, '.github', 'workflows', 'extension-release.yml'), 'utf8');
const storeClient = await readFile(path.join(repositoryRoot, 'scripts', 'chrome-web-store.mjs'), 'utf8');
const releaseDocs = await readFile(path.join(repositoryRoot, 'docs', 'chrome-extension-release.md'), 'utf8');

test('extension releases run only for the intended release tag shape', () => {
  assert.match(workflow, /tags:\s*\n\s*- ['"]extension-v\*['"]/);
  const releaseJobs = workflow.split(/\n  submit:\n/);
  assert.equal(releaseJobs.length, 2, 'workflow must have one uncredentialed package job and one gated submit job');
  for (const job of releaseJobs) {
    assert.match(job, /if: github\.ref_type == 'tag' && startsWith\(github\.ref, 'refs\/tags\/extension-v'\)/);
  }
  assert.match(workflow, /version="\$\{GITHUB_REF_NAME#extension-v\}"/);
  assert.match(workflow, /\^\[0-9\]\+\\\.\[0-9\]\+\\\.\[0-9\]\+/);
});

test('Store secrets exist only in the environment-protected release job', () => {
  const [packageJob, submitJob] = workflow.split(/\n  submit:\n/);
  assert.doesNotMatch(packageJob, /\$\{\{\s*secrets\./);
  assert.match(submitJob, /environment:\s*\n\s+name: chrome-web-store-release/);
  assert.match(submitJob, /VERIFIED_CRX_PRIVATE_KEY:\s*\$\{\{\s*secrets\.VERIFIED_CRX_PRIVATE_KEY\s*\}\}/);
  assert.match(submitJob, /CWS_OAUTH_REFRESH_TOKEN:\s*\$\{\{\s*secrets\.CWS_OAUTH_REFRESH_TOKEN\s*\}\}/);
});

test('release build verifies the versioned local package and records commit provenance', () => {
  assert.match(workflow, /npm run build:extension/);
  assert.match(workflow, /scripts\/verify-extension-package\.mjs[^\n]+\$RELEASE_VERSION/);
  assert.match(workflow, /actions\/attest-build-provenance@v\d+/);
  assert.match(workflow, /subject-path: \$\{\{ steps\.archive\.outputs\.path \}\}/);
  assert.match(workflow, /actions\/upload-artifact@v\d+/);
  assert.match(workflow, /Check downloaded package checksum/);
});

test('signing, upload, and submission have distinct failure boundaries and statuses', () => {
  assert.match(workflow, /name: Sign package with configured Verified CRX key/);
  assert.match(workflow, /name: Upload signed CRX to Chrome Web Store/);
  assert.match(workflow, /name: Submit uploaded package for Chrome Web Store review/);
  assert.match(storeClient, /Chrome Web Store upload failed/);
  assert.match(storeClient, /Chrome Web Store submission failed/);
  assert.match(storeClient, /Store did not confirm submission acceptance/);
  assert.match(storeClient, /this workflow reports request acceptance only/);
  assert.match(workflow, /This records a submission only; it does not mean Store review passed or that the version is live\./);
  assert.doesNotMatch(storeClient, /console\.log\([^\n]*\bwas published\b/i);
});

test('release setup documents environment approval and leaves unknown Store identity unconfigured', () => {
  assert.match(releaseDocs, /approval from designated reviewers/i);
  assert.match(releaseDocs, /extension-v\*/);
  assert.match(releaseDocs, /Store ID and matching public key are unknown/i);
  assert.match(releaseDocs, /Security__ChromeExtensionOrigin.*unset/i);
  assert.match(releaseDocs, /No Store upload or publication is performed while validating this workflow/i);
  assert.match(workflow, /CWS_EXTENSION_ID:\s*\$\{\{\s*secrets\.CWS_EXTENSION_ID\s*\}\}/);
  assert.doesNotMatch(workflow, /chrome-extension:\/\/[a-p]{32}/);
});
