import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

// Application-layer encryption between a client and the Guardian, on top of TLS.
// Even a TLS-terminating proxy, CDN or log collector only ever sees ciphertext in the body.
const SALT = Buffer.from('guardian-e2e-salt-v1');
const INFO = Buffer.from('guardian/e2e/v1');

/** Per-person encryption key, derived (HKDF-SHA256) from that person's/service's secret. Same derivation runs in the browser. */
export function deriveE2eKey(secret: string): Buffer {
  return Buffer.from(hkdfSync('sha256', Buffer.from(secret, 'utf8'), SALT, INFO, 32));
}

/** AES-256-GCM. `aad` binds the ciphertext to one request/response (route + timestamp + nonce). Format: v1.e.<iv>.<ct>.<tag> */
export function e2eSeal(key: Buffer, plaintext: string, aad: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(Buffer.from(plaintext, 'utf8')), c.final()]);
  const b = (x: Buffer) => x.toString('base64url');
  return `v1.e.${b(iv)}.${b(ct)}.${b(c.getAuthTag())}`;
}

export function e2eOpen(key: Buffer, sealed: string, aad: string): string {
  const p = sealed.split('.');
  if (p.length !== 5 || p[0] !== 'v1' || p[1] !== 'e') throw new Error('bad_envelope');
  try {
    const d = createDecipheriv('aes-256-gcm', key, Buffer.from(p[2]!, 'base64url'));
    d.setAAD(Buffer.from(aad));
    d.setAuthTag(Buffer.from(p[4]!, 'base64url'));
    return Buffer.concat([d.update(Buffer.from(p[3]!, 'base64url')), d.final()]).toString('utf8');
  } catch { throw new Error('bad_envelope'); }
}
