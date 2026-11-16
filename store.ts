import { chmod, mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { open, seal } from './crypto.ts';
import type { Keyring } from './crypto.ts';
import type { DeviceStore } from './notifiers.ts';

/** JSON values encrypted at rest. Files are 0600 in a 0700 directory, written atomically, and bound to their name via AAD. */
export class EncryptedFileStore {
  #dir: string; #ring: Keyring;
  constructor(dir: string, ring: Keyring) { this.#dir = dir; this.#ring = ring; }
  async init(): Promise<void> { await mkdir(this.#dir, { recursive: true, mode: 0o700 }); await chmod(this.#dir, 0o700); }
  #path(name: string): string {
    if (!/^[a-z0-9_.-]{1,64}$/i.test(name) || name.startsWith('.')) throw new Error('invalid store key');
    return join(this.#dir, `${name}.enc`);
  }
  async get<T>(name: string): Promise<T | null> {
    let raw: string;
    try { raw = await readFile(this.#path(name), 'utf8'); }
    catch (e) { if ((e as { code?: string }).code === 'ENOENT') return null; throw e; }
    return JSON.parse(open(this.#ring, raw, name).toString('utf8')) as T;
  }
  async set(name: string, value: unknown): Promise<void> {
    const path = this.#path(name);
    const tmp = `${path}.${randomBytes(6).toString('hex')}.tmp`;
    await writeFile(tmp, seal(this.#ring, JSON.stringify(value), name), { mode: 0o600 });
    await rename(tmp, path); // atomic: readers never see half a file
  }
  async delete(name: string): Promise<void> { await rm(this.#path(name), { force: true }); }
  /** Re-encrypts every file with the current key. Run after adding a new key, then drop the old one. */
  async rotate(): Promise<number> {
    let n = 0;
    for (const f of await readdir(this.#dir)) {
      if (!f.endsWith('.enc')) continue;
      const name = f.slice(0, -4);
      await this.set(name, await this.get(name)); n++;
    }
    return n;
  }
}

/** FCM tokens of the owner's phones, encrypted at rest. */
export class EncryptedDeviceStore implements DeviceStore {
  #s: EncryptedFileStore; #m = new Map<string, string>();
  constructor(store: EncryptedFileStore) { this.#s = store; }
  static async open(store: EncryptedFileStore): Promise<EncryptedDeviceStore> {
    const d = new EncryptedDeviceStore(store);
    const saved = await store.get<Record<string, string>>('devices');
    if (saved) d.#m = new Map(Object.entries(saved));
    return d;
  }
  #save() { return this.#s.set('devices', Object.fromEntries(this.#m)); }
  async list() { return [...this.#m.keys()]; }
  async add(owner: string, token: string) { if (token) { this.#m.set(token, owner); await this.#save(); } }
  async remove(token: string) { this.#m.delete(token); await this.#save(); }
}
