import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { WalletError } from './errors.js';
import type { SecureStorage } from './storage.js';

/**
 * Encrypts every value before it reaches the underlying store (SQLite, AsyncStorage, files...).
 * Use it for transaction history, labels, address caches, contacts: data that is private but too big for the Keychain.
 * `dataKey` (32 random bytes) must itself live in the Keychain/Keystore, never next to the data.
 * The key name is bound as AAD, so values cannot be swapped between keys.
 */
export class EncryptedStorage implements SecureStorage {
  #inner: SecureStorage; #key: Uint8Array;
  constructor(inner: SecureStorage, dataKey: Uint8Array) {
    if (dataKey.length !== 32) throw new WalletError('BAD_VAULT', 'dataKey must be 32 bytes');
    this.#inner = inner; this.#key = dataKey.slice();
  }
  static generateKey(): Uint8Array { return randomBytes(32); }
  /** Wipes the in-memory key (call when the app locks). The wrapper is unusable afterwards. */
  destroy(): void { this.#key.fill(0); }

  async get(key: string): Promise<string | null> {
    const raw = await this.#inner.get(key);
    if (raw === null) return null;
    const [v, nonce, ct] = raw.split('.');
    if (v !== 'e1' || !nonce || !ct) throw new WalletError('BAD_VAULT', 'Stored value is corrupt');
    try {
      return new TextDecoder().decode(xchacha20poly1305(this.#key, hexToBytes(nonce), new TextEncoder().encode(key)).decrypt(hexToBytes(ct)));
    } catch { throw new WalletError('WRONG_PASSWORD_OR_CORRUPT', 'Stored value failed integrity check'); }
  }
  async set(key: string, value: string): Promise<void> {
    const nonce = randomBytes(24);
    const ct = xchacha20poly1305(this.#key, nonce, new TextEncoder().encode(key)).encrypt(new TextEncoder().encode(value));
    await this.#inner.set(key, `e1.${bytesToHex(nonce)}.${bytesToHex(ct)}`);
  }
  delete(key: string): Promise<void> { return this.#inner.delete(key); }
}
