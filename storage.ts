/**
 * Implement this on top of iOS Keychain (ThisDeviceOnly) / Android Keystore.
 * NEVER back it with AsyncStorage, localStorage, or plain files.
 */
export interface SecureStorage {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}

/** For tests only. */
export class MemoryStorage implements SecureStorage {
  #m = new Map<string, string>();
  async get(k: string) { return this.#m.get(k) ?? null; }
  async set(k: string, v: string) { this.#m.set(k, v); }
  async delete(k: string) { this.#m.delete(k); }
}
