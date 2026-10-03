const origin = process.argv[2] ?? 'http://localhost:4200';
const deepLink = origin + '/s/C-4ByYpPwt-yjCTibH7UkA';
const html = await (await fetch(deepLink)).text();

if (!html.includes('<base href="/">')) throw new Error('Deep-link response has no root base href.');
if (!html.includes("base-uri 'self'")) throw new Error("Deep-link CSP does not allow the root base URI.");
if (html.includes("base-uri 'none'")) throw new Error("Deep-link CSP still blocks the root base URI.");

const asset = await fetch(origin + '/main.js');
if (!asset.ok) throw new Error('Root JavaScript asset returned HTTP ' + asset.status + '.');

console.log('SPA deep-link assets passed.');
