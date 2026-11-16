import { readFileSync } from 'node:fs';

const read = (f: string) => readFileSync(new URL(`./admin/${f}`, import.meta.url));
const html = read('index.html'), js = read('app.js'), css = read('app.css');

export const ADMIN_ROUTES: Record<string, { type: string; body: Buffer }> = {
  '/admin': { type: 'text/html; charset=utf-8', body: html },
  '/admin/': { type: 'text/html; charset=utf-8', body: html },
  '/admin/app.js': { type: 'text/javascript; charset=utf-8', body: js },
  '/admin/app.css': { type: 'text/css; charset=utf-8', body: css },
};

// Strict CSP: only our own two files may run/style; no inline script, no third parties, no framing, no form posts.
export const ADMIN_HEADERS = {
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'cross-origin-opener-policy': 'same-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
  'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'strict-transport-security': 'max-age=63072000; includeSubDomains',
};
