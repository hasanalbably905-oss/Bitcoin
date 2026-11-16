import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { signRequest } from './auth.ts';
import { deriveE2eKey, e2eSeal } from './e2e.ts';
import type { BreakerName } from './types.ts';

/** Production guards must read the authenticated FlagStore; plaintext path flags are intentionally unsupported. */
export interface VerifiedFreezeSource { isFrozen(n: BreakerName): Promise<boolean> }

export class FrozenError extends Error {
  breaker: BreakerName;
  constructor(b: BreakerName) { super(`${b} is frozen by the security team`); this.name = 'FrozenError'; this.breaker = b; }
}

/** Use inside your API: `await guard.assertNotFrozen('SENDS')` before broadcasting or signing anything. */
export function createFrozenGuard(source: VerifiedFreezeSource) {
  if (!source || typeof source.isFrozen !== 'function') throw new TypeError('A verified FlagStore is required; plaintext flag paths are forbidden');
  const check = (n: BreakerName) => source.isFrozen(n);
  const assertNotFrozen = async (...names: BreakerName[]): Promise<void> => {
    for (const n of names) if (await check(n)) throw new FrozenError(n);
  };
  /** Express/Connect-style middleware. Put `middleware('SERVICE')` first on every route except /health. */
  const middleware = (...names: BreakerName[]) =>
    async (_req: unknown, res: any, next: (e?: unknown) => void) => {
      try { await assertNotFrozen(...names); next(); }
      catch (e) {
        if (e instanceof FrozenError) { res.statusCode = 503; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ error: 'temporarily_unavailable' })); }
        else next(e);
      }
    };
  return { isFrozen: check, assertNotFrozen, middleware };
}

/** Sends signed events from your services to the Guardian. */
export class GuardianReporter {
  #url: string; #keyId: string; #secret: string; #e2e: Buffer | undefined;
  /** `encrypt` (default true) wraps every request body in an end-to-end encrypted envelope on top of TLS. */
  constructor(o: { url: string; keyId: string; secret: string; encrypt?: boolean }) {
    this.#url = o.url; this.#keyId = o.keyId; this.#secret = o.secret;
    this.#e2e = o.encrypt === false ? undefined : deriveE2eKey(o.secret);
  }
  async report(source: string, type: string, data?: Record<string, unknown>, extra: { actor?: string; ip?: string } = {}): Promise<void> {
    const ts = Date.now(); const nonce = randomUUID();
    const plain = JSON.stringify({ source, type, data, ...extra });
    const body = this.#e2e ? e2eSeal(this.#e2e, plain, `req|POST /ingest|${ts}|${nonce}`) : plain;
    const res = await fetch(`${this.#url}/ingest`, {
      method: 'POST', body, signal: AbortSignal.timeout(5000),
      headers: { 'accept-encoding': 'identity', 'x-key-id': this.#keyId, 'x-ts': String(ts), 'x-nonce': nonce, 'x-sig': signRequest(this.#secret, ts, nonce, 'POST /ingest', body), ...(this.#e2e ? { 'x-enc': '1' } : {}) },
    });
    if (!res.ok) throw new Error(`guardian responded ${res.status}`);
  }
  /** Fire-and-forget: monitoring must never break the app. */
  emit(source: string, type: string, data?: Record<string, unknown>, extra: { actor?: string; ip?: string } = {}): void {
    this.report(source, type, data, extra).catch(() => {});
  }
  /** Call every 30-60s from each service listed in `expectedSources`. */
  heartbeat(source: string): void { this.emit(source, 'heartbeat'); }
}
