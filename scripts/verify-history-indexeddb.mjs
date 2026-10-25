import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join } from 'node:path';

const browser = await findBrowser();
const page = await readFile(new URL('./history-indexeddb-check.html', import.meta.url), 'utf8');
const profile = await mkdtemp(join(process.cwd(), '.history-browser-check-'));
const server = createServer((request, response) => {
  response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  response.end(page);
});

await new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', resolve);
});

const address = server.address();
if (!address || typeof address === 'string') throw new Error('Could not start the temporary local check server');
const baseUrl = 'http://127.0.0.1:' + address.port;

try {
  const written = runBrowser(browser, profile, baseUrl + '/write');
  if (!written.includes('data-result="written"') || !written.includes('data-export-rejected="true"')) {
    throw new Error('Browser did not complete the IndexedDB write step.\n' + written.slice(-2000));
  }

  // A second browser process recreates both the document and its JavaScript context.
  const reloaded = runBrowser(browser, profile, baseUrl + '/read');
  if (!reloaded.includes('data-result="passed"') || !reloaded.includes('data-export-rejected="true"')) {
    throw new Error('Browser could not reload and decrypt the IndexedDB record.\n' + reloaded.slice(-2000));
  }

  console.log('Real-browser IndexedDB CryptoKey persistence passed. The reloaded page decrypted the saved entry, and CryptoKey export was rejected.');
} finally {
  await new Promise(resolve => server.close(resolve));
  await rm(profile, { recursive: true, force: true });
}

async function findBrowser() {
  const candidates = [
    process.env.CHROME_BIN,
    process.env.EDGE_BIN,
    process.env.BROWSER,
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/microsoft-edge'
  ].filter(Boolean);

  for (const candidate of candidates) {
    try {
      execFileSync(candidate, ['--version'], { stdio: 'ignore', timeout: 5000 });
      return candidate;
    } catch {}
  }

  throw new Error('A Chromium or Edge browser was not found. Set CHROME_BIN or EDGE_BIN to run this check.');
}

function runBrowser(executable, userDataDir, url) {
  const args = [
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-background-networking',
    '--user-data-dir=' + userDataDir,
    '--virtual-time-budget=10000',
    '--dump-dom',
    url
  ];
  if (process.platform !== 'win32') args.unshift('--no-sandbox');
  try {
    return execFileSync(executable, args, { encoding: 'utf8', timeout: 30000, maxBuffer: 2 * 1024 * 1024 });
  } catch (error) {
    const output = error?.stdout?.toString?.() ?? '';
    const diagnostics = error?.stderr?.toString?.() ?? '';
    if (output) return output + diagnostics;
    throw new Error('Could not run the headless browser check: ' + diagnostics, { cause: error });
  }
}
