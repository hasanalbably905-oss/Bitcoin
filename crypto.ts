import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

/** Set of 256-bit keys with ids, so keys can be rotated without losing old data. */
export class Keyring {
  #keys = new Map<string, Buffer>();
  #current: string;
  constructor(keys: Record<string, string>, current: string) {
    for (const [id, hex] of Object.entries(keys)) {
      if (!/^[A-Za-z0-9_-]{1,16}$/.test(id)) throw new Error('invalid key id');
      if (!/^[0-9a-f]{64}$/i.test(hex)) throw new Error(`key "${id}" must be 64 hex characters (32 bytes). Generate: openssl rand -hex 32`);
      this.#keys.set(id, Buffer.from(hex, 'hex'));
    }
    if (!this.#keys.has(current)) throw new Error('current key id is not in the keyring');
    this.#current = current;
  }
  get currentId(): string { return this.#current; }
  get(id: string): Buffer | undefined { return this.#keys.get(id); }
}

/** AES-256-GCM. `aad` binds the ciphertext to its purpose/location (a file name, a log position). Format: v1.<kid>.<iv>.<ct>.<tag> */
export function seal(ring: Keyring, plaintext: string | Uint8Array, aad: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', ring.get(ring.currentId)!, iv);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(typeof plaintext === 'string' ? Buffer.from(plaintext) : plaintext), c.final()]);
  const b = (x: Buffer) => x.toString('base64url');
  return `v1.${ring.currentId}.${b(iv)}.${b(ct)}.${b(c.getAuthTag())}`;
}

export function open(ring: Keyring, sealed: string, aad: string): Buffer {
  const p = sealed.trim().split('.');
  const key = p.length === 5 && p[0] === 'v1' ? ring.get(p[1]!) : undefined;
  if (!key) throw new Error('decryption failed');
  try {
    const d = createDecipheriv('aes-256-gcm', key, Buffer.from(p[2]!, 'base64url'));
    d.setAAD(Buffer.from(aad));
    d.setAuthTag(Buffer.from(p[4]!, 'base64url'));
    return Buffer.concat([d.update(Buffer.from(p[3]!, 'base64url')), d.final()]);
  } catch { throw new Error('decryption failed'); } // wrong key, wrong place and tampering look the same
}
