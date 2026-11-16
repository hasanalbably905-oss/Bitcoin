import { scrypt, randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import { Keyring, open, seal } from './crypto.ts';

const scryptAsync = promisify(scrypt) as (pw: string, salt: Buffer, len: number, o: object) => Promise<Buffer>;
const KDF = { N: 2 ** 17, r: 8, p: 1 }; // 128 MB, a few hundred ms: only paid once at startup
export const MIN_PASSPHRASE = 16;

async function derive(passphrase: string, salt: Buffer, k: { N: number; r: number; p: number }): Promise<Keyring> {
  if (!(k.N >= 2 ** 15 && k.N <= 2 ** 20 && (k.N & (k.N - 1)) === 0 && k.r >= 1 && k.r <= 16 && k.p >= 1 && k.p <= 4)) throw new Error('unsupported key-derivation parameters');
  const key = await scryptAsync(passphrase.normalize('NFKC'), salt, 32, { ...k, maxmem: 512 * 1024 * 1024 });
  return new Keyring({ w: key.toString('hex') }, 'w');
}

/** Encrypts the master keys under a passphrase, so no master key is ever stored in plaintext on disk. */
export async function wrapKeys(keys: Record<string, string>, current: string, passphrase: string): Promise<string> {
  if (passphrase.length < MIN_PASSPHRASE) throw new Error(`passphrase must be at least ${MIN_PASSPHRASE} characters`);
  new Keyring(keys, current); // validates before wrapping
  const salt = randomBytes(16);
  const ring = await derive(passphrase, salt, KDF);
  const aad = `keywrap|${KDF.N}|${KDF.r}|${KDF.p}|${salt.toString('hex')}`; // parameters are authenticated
  return JSON.stringify({ v: 1, ...KDF, salt: salt.toString('hex'), sealed: seal(ring, JSON.stringify({ keys, current }), aad) });
}

export async function unwrapKeys(blob: string, passphrase: string): Promise<Keyring> {
  let j: any;
  try { j = JSON.parse(blob); } catch { throw new Error('wrapped keys are corrupt'); }
  if (j?.v !== 1 || typeof j.salt !== 'string' || typeof j.sealed !== 'string') throw new Error('wrapped keys are corrupt');
  const ring = await derive(passphrase, Buffer.from(j.salt, 'hex'), { N: j.N, r: j.r, p: j.p });
  try {
    const { keys, current } = JSON.parse(open(ring, j.sealed, `keywrap|${j.N}|${j.r}|${j.p}|${j.salt}`).toString('utf8'));
    return new Keyring(keys, current);
  } catch { throw new Error('wrong passphrase or corrupted key file'); }
}
