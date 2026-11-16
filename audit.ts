import { createHash } from 'node:crypto';
import { appendFile, readFile } from 'node:fs/promises';
import { open, seal } from './crypto.ts';
import type { Keyring } from './crypto.ts';

const GENESIS = '0'.repeat(64);
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

export interface AuditVerdict { ok: boolean; entries: number; head: string; badLine?: number }

/**
 * Append-only log: every line is encrypted AND chained to the previous one (hash chain, position bound via AAD).
 * Editing, deleting, reordering or inserting a line is detected. Truncating the END is only detectable if you
 * keep the latest `head()` somewhere else (send it to the owner daily).
 */
export class AuditLog {
  #file: string; #ring: Keyring; #head = GENESIS; #n = 0; #chain: Promise<unknown> = Promise.resolve();
  constructor(file: string, ring: Keyring) { this.#file = file; this.#ring = ring; }

  static async verify(file: string, ring: Keyring): Promise<AuditVerdict> {
    let text = '';
    try { text = await readFile(file, 'utf8'); } catch (e) { if ((e as { code?: string }).code !== 'ENOENT') throw e; }
    let prev = GENESIS; let n = 0;
    for (const line of text.split('\n').filter(Boolean)) {
      try {
        const { h, c } = JSON.parse(line);
        const pt = open(ring, c, `audit:${n}`).toString('utf8');
        if (h !== sha(`${prev}:${pt}`)) throw new Error('chain');
        prev = h; n++;
      } catch { return { ok: false, entries: n, head: prev, badLine: n + 1 }; }
    }
    return { ok: true, entries: n, head: prev };
  }

  async init(): Promise<void> {
    const v = await AuditLog.verify(this.#file, this.#ring);
    if (!v.ok) throw new Error(`audit log tampered or unreadable at line ${v.badLine}`);
    this.#head = v.head; this.#n = v.entries;
  }
  head(): string { return this.#head; }

  /** Last `n` decrypted entries (for the admin page). */
  async tail(n = 50): Promise<{ n: number; ts: number; entry: unknown }[]> {
    let text = '';
    try { text = await readFile(this.#file, 'utf8'); } catch { return []; }
    const lines = text.split('\n').filter(Boolean);
    const out: { n: number; ts: number; entry: unknown }[] = [];
    for (let i = Math.max(0, lines.length - n); i < lines.length; i++)
      out.push(JSON.parse(open(this.#ring, JSON.parse(lines[i]!).c, `audit:${i}`).toString('utf8')));
    return out;
  }

  append(entry: unknown): Promise<string> {
    const run = this.#chain.then(async () => {
      const pt = JSON.stringify({ n: this.#n, ts: Date.now(), entry });
      const h = sha(`${this.#head}:${pt}`);
      await appendFile(this.#file, JSON.stringify({ h, c: seal(this.#ring, pt, `audit:${this.#n}`) }) + '\n', { mode: 0o600 });
      this.#head = h; this.#n++;
      return h;
    });
    this.#chain = run.catch(() => {});
    return run;
  }
}
