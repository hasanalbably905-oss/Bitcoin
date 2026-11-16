import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { open, seal } from './crypto.ts';
import type { Keyring } from './crypto.ts';
import type { BreakerName } from './types.ts';

/** Must be backed by a separate trust domain and provide durable atomic compare-and-set. */
export interface SequenceAnchor {
  get(name: BreakerName): Promise<number>;
  /** Atomically change expected -> next; return false if the stored value differs. */
  advance(name: BreakerName, expected: number, next: number): Promise<boolean>;
}

/** HTTPS adapter contract: GET /v1/sequence/:name -> {seq}; PUT same URL {expected,next} -> {advanced:boolean}.
 * The remote service MUST persist values durably and implement atomic CAS. Keep it outside Guardian's host/account.
 */
export class HttpSequenceAnchor implements SequenceAnchor {
  #base: URL; #token: string;
  constructor(base: string, token: string) {
    this.#base = new URL(base);
    if (this.#base.protocol !== 'https:') throw new Error('FLAG_ANCHOR_URL must use HTTPS');
    if (this.#base.username || this.#base.password || this.#base.search || this.#base.hash) throw new Error('Invalid FLAG_ANCHOR_URL');
    if (token.length < 32) throw new Error('FLAG_ANCHOR_TOKEN must be at least 32 characters');
    this.#token = token;
  }
  async #request(path: string, init?: RequestInit): Promise<any> {
    const r = await fetch(new URL(path, this.#base), { ...init, signal: AbortSignal.timeout(5000), headers: { authorization: `Bearer ${this.#token}`, accept: 'application/json', ...(init?.body ? { 'content-type': 'application/json' } : {}), ...init?.headers } });
    if (!r.ok) throw new Error(`Sequence anchor unavailable (${r.status})`);
    return r.json();
  }
  async get(name: BreakerName): Promise<number> {
    const v = await this.#request(`v1/sequence/${encodeURIComponent(name)}`);
    if (!Number.isSafeInteger(v?.seq) || v.seq < 0) throw new Error('Invalid sequence anchor response');
    return v.seq;
  }
  async advance(name: BreakerName, expected: number, next: number): Promise<boolean> {
    if (next !== expected + 1) throw new Error('Sequence must advance by exactly one');
    const v = await this.#request(`v1/sequence/${encodeURIComponent(name)}`, { method: 'PUT', body: JSON.stringify({ expected, next }) });
    if (typeof v?.advanced !== 'boolean') throw new Error('Invalid sequence anchor response');
    return v.advanced;
  }
}

/** Sealed flags are bound to their name and to a durable sequence held in a separate trust domain. */
export class FlagStore {
  #dir: string; #ring: Keyring; #anchor: SequenceAnchor;
  constructor(dir: string, ring: Keyring, anchor: SequenceAnchor) { this.#dir = dir; this.#ring = ring; this.#anchor = anchor; }
  #path(n: BreakerName) { return join(this.#dir, `${n}.flag`); }

  async init(): Promise<void> { await mkdir(this.#dir, { recursive: true, mode: 0o750 }); await chmod(this.#dir, 0o750); }

  async write(name: BreakerName, frozen: boolean): Promise<void> {
    const current = await this.#anchor.get(name);
    if (!Number.isSafeInteger(current) || current < 0 || current >= Number.MAX_SAFE_INTEGER) throw new Error('Invalid sequence anchor');
    const seq = current + 1;
    // Advance the independent anchor first. A crash after this point leaves a mismatch and therefore freezes, never unfreezes.
    if (!await this.#anchor.advance(name, current, seq)) throw new Error('Concurrent or stale freeze update; refusing to write');
    const path = this.#path(name);
    const tmp = `${path}.${randomBytes(6).toString('hex')}.tmp`;
    await writeFile(tmp, seal(this.#ring, JSON.stringify({ frozen, seq, ts: Date.now() }), `flag:${name}`), { mode: 0o640 });
    await rename(tmp, path);
  }

  async status(name: BreakerName): Promise<{ frozen: boolean; reason: string }> {
    let anchored: number;
    try { anchored = await this.#anchor.get(name); }
    catch { return { frozen: true, reason: 'sequence anchor unavailable' }; }
    let raw: string;
    try { raw = await readFile(this.#path(name), 'utf8'); }
    catch (e) {
      if ((e as { code?: string }).code === 'ENOENT') return anchored === 0 ? { frozen: false, reason: 'never set' } : { frozen: true, reason: 'flag missing or deleted' };
      return { frozen: true, reason: 'unreadable' };
    }
    try {
      const f = JSON.parse(open(this.#ring, raw, `flag:${name}`).toString('utf8')) as { frozen: boolean; seq: number };
      if (!Number.isSafeInteger(f.seq) || f.seq < 1 || typeof f.frozen !== 'boolean') return { frozen: true, reason: 'malformed' };
      if (f.seq < anchored) return { frozen: true, reason: 'rollback' };
      if (f.seq > anchored) return { frozen: true, reason: 'uncommitted flag' };
      return { frozen: f.frozen, reason: 'ok' };
    } catch { return { frozen: true, reason: 'forged or corrupted' }; }
  }
  async isFrozen(name: BreakerName): Promise<boolean> { return (await this.status(name)).frozen; }
}
