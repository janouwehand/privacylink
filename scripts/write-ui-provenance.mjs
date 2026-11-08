import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outputDirectory = path.resolve(process.cwd(), process.argv[2]);
async function filesBelow(directory) {
  const result = [];
  for (const entry of await readdir(path.join(repositoryRoot, directory), { withFileTypes: true })) {
    const relative = path.posix.join(directory, entry.name);
    if (entry.isDirectory()) result.push(...await filesBelow(relative));
    else if (entry.isFile() && !/\.(spec|test)\.[^.]+$/.test(entry.name)) result.push(relative);
  }
  return result;
}

const sharedFiles = [
  ...await filesBelow('src/PrivacyLink.Web/src/app'),
  ...await filesBelow('src/PrivacyLink.Web/public'),
  'src/PrivacyLink.Web/src/styles.css'
].sort();
const hash = createHash('sha256');
for (const file of sharedFiles) hash.update(file).update(await readFile(path.join(repositoryRoot, file)));
let sourceRevision = 'unknown';
try { sourceRevision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repositoryRoot, encoding: 'utf8' }).trim(); } catch { /* Build can run from a source archive. */ }
let sourceDirty = null;
let dirtyPaths = [];
let sourceTreeHash = null;
try {
  const status = execFileSync('git', ['status', '--porcelain=v1', '--untracked-files=all'], { cwd: repositoryRoot, encoding: 'utf8' });
  dirtyPaths = status.split(/\r?\n/).filter(Boolean).map(line => line.slice(3).trim());
  sourceDirty = dirtyPaths.length > 0;
  const sourcePaths = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], { cwd: repositoryRoot, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }).split('\0').filter(Boolean).sort();
  const tree = createHash('sha256');
  for (const file of sourcePaths) {
    try { tree.update(file).update(await readFile(path.join(repositoryRoot, file))); }
    catch { tree.update(file).update('<missing>'); }
  }
  sourceTreeHash = `sha256:${tree.digest('hex')}`;
} catch { /* Git metadata is unavailable in source archives. */ }
const provenance = {
  sourceRevision,
  sourceDirty,
  dirtyPaths,
  sourceTreeHash,
  sharedUiVersion: `sha256:${hash.digest('hex')}`
};
await mkdir(outputDirectory, { recursive: true });
await writeFile(path.join(outputDirectory, 'ui-provenance.json'), `${JSON.stringify(provenance, null, 2)}\n`);
console.log(`Recorded UI provenance for ${outputDirectory}: ${provenance.sharedUiVersion}`);
