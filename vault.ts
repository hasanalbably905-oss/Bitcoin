import { scryptAsync } from '@noble/hashes/scrypt.js';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { WalletError } from './errors.js';

export interface KdfParams { N: number; r: number; p: number }
/** 128 MB per unlock (OWASP minimum for scrypt). Params are stored in each blob, so older vaults keep working. */
export const DEFAULT_KDF: KdfParams = { N: 2 ** 17, r: 8, p: 1 };
export const MIN_PASSWORD_LENGTH = 10;

export interface VaultBlob {
  v: 1; kdf: 'scrypt'; N: number; r: number; p: number;
  salt: string; nonce: string; ct: string;
}

const enc = new TextEncoder();
const aad = (k: KdfParams) => enc.encode(`btc-wallet-vault|v1|scrypt|${k.N}|${k.r}|${k.p}`);

// Bounds stop a tampered blob from forcing huge memory use (DoS).
function assertKdfParams({ N, r, p }: KdfParams): void {
  const ok =
    Number.isInteger(N) && N >= 2 ** 14 && N <= 2 ** 20 && (N & (N - 1)) === 0 &&
    Number.isInteger(r) && r >= 1 && r <= 16 &&
    Number.isInteger(p) && p >= 1 && p <= 4;
  if (!ok) throw new WalletError('BAD_VAULT', 'Unsupported key-derivation parameters');
}

async function deriveKey(password: string, salt: Uint8Array, k: KdfParams): Promise<Uint8Array> {
  return scryptAsync(enc.encode(password.normalize('NFKC')), salt, { N: k.N, r: k.r, p: k.p, dkLen: 32 });
}

export async function encryptSecret(
  secret: Uint8Array, password: string, params: KdfParams = DEFAULT_KDF,
): Promise<VaultBlob> {
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new WalletError('WEAK_PASSWORD', `Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  assertKdfParams(params);
  const salt = randomBytes(16);
  const nonce = randomBytes(24);
  const key = await deriveKey(password, salt, params);
  try {
    const ct = xchacha20poly1305(key, nonce, aad(params)).encrypt(secret);
    return { v: 1, kdf: 'scrypt', ...params, salt: bytesToHex(salt), nonce: bytesToHex(nonce), ct: bytesToHex(ct) };
  } finally {
    key.fill(0);
  }
}

export async function decryptSecret(blob: VaultBlob, password: string): Promise<Uint8Array> {
  if (!blob || blob.v !== 1 || blob.kdf !== 'scrypt') throw new WalletError('BAD_VAULT', 'Unknown vault format');
  assertKdfParams(blob);
  let salt: Uint8Array, nonce: Uint8Array, ct: Uint8Array;
  try {
    salt = hexToBytes(blob.salt); nonce = hexToBytes(blob.nonce); ct = hexToBytes(blob.ct);
  } catch {
    throw new WalletError('BAD_VAULT', 'Vault data is corrupt');
  }
  if (salt.length !== 16 || nonce.length !== 24) throw new WalletError('BAD_VAULT', 'Vault data is corrupt');
  const key = await deriveKey(password, salt, blob);
  try {
    return xchacha20poly1305(key, nonce, aad(blob)).decrypt(ct);
  } catch {
    // Wrong password and tampering are deliberately indistinguishable.
    throw new WalletError('WRONG_PASSWORD_OR_CORRUPT', 'Wrong password or corrupted vault');
  } finally {
    key.fill(0);
  }
}
