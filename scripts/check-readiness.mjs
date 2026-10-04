#!/usr/bin/env node
// Wait for the public readiness endpoint without following redirects.

const target = new URL(process.argv[2] ?? 'https://privacylink.nl');
if (target.protocol !== 'https:' || target.username || target.password || target.search || target.hash) {
  throw new Error('Expected a plain HTTPS base URL');
}

const readinessUrl = new URL('/health/ready', target);
for (let attempt = 0; attempt < 30; attempt++) {
  try {
    const response = await fetch(readinessUrl, { redirect: 'manual', signal: AbortSignal.timeout(5000) });
    if (response.status === 200) {
      console.log(`PASS: production readiness at ${target.origin}`);
      process.exit(0);
    }
  } catch {
    // The app may still be starting or Caddy may still be forwarding to it.
  }
  await new Promise(resolve => setTimeout(resolve, 2000));
}

console.error(`FAIL: readiness check did not succeed at ${target.origin}`);
process.exit(1);

