import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { marked } from '../src/PrivacyLink.Web/node_modules/marked/lib/marked.esm.js';

const repoRoot = resolve(import.meta.dirname, '..');
const sourcePath = resolve(repoRoot, 'docs/security-whitepaper.md');
const outputPath = resolve(repoRoot, 'src/PrivacyLink.Web/public/security/security-whitepaper.html');

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[character]);
}

const markdown = await readFile(sourcePath, 'utf8');
const renderer = new marked.Renderer();
renderer.html = ({ text }) => escapeHtml(text);
renderer.image = ({ text }) => escapeHtml(text);
renderer.link = function ({ href, tokens }) {
  const label = this.parser.parseInline(tokens);
  if (!href || !/^https:\/\/github\.com\/janouwehand\/privacylink\//i.test(href)) return label;
  return `<a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer">${label}</a>`;
};

const html = marked.parse(markdown, { gfm: true, renderer });

const article = html.replace(/^<h1>[\s\S]*?<\/h1>\s*/, '');

await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, article, 'utf8');
process.stdout.write(`Rendered ${sourcePath} to ${outputPath}\n`);
