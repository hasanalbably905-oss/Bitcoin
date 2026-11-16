import { createHmac, timingSafeEqual } from 'node:crypto';
import { deriveE2eKey } from './e2e.ts';

export function signRequest(secret: string, ts: number, nonce: string, route: string, body: string): string {
  return createHmac('sha256', secret).update(`${ts}.${nonce}.${route}.${body}`).digest('hex');
}

export interface SignedHeaders { keyId: string; ts: number; nonce: string; sig: string }

/** HMAC-signed requests with timestamp window and nonce replay protection. */
export class RequestVerifier {
  #keys: Map<string, string>; #seen = new Map<string, number>(); #skewMs: number;
  constructor(keys: Record<string, string>, skewMs = 60_000) { this.#keys = new Map(Object.entries(keys)); this.#skewMs = skewMs; }

  deriveKey(keyId: string): Buffer | undefined { const s = this.#keys.get(keyId); return s ? deriveE2eKey(s) : undefined; }

  verify(h: SignedHeaders, route: string, body: string, now: number): boolean {
    const secret = this.#keys.get(h.keyId);
    if (!secret || !Number.isFinite(h.ts) || Math.abs(now - h.ts) > this.#skewMs) return false;
    if (h.nonce.length < 8 || h.nonce.length > 64) return false;
    const want = Buffer.from(signRequest(secret, h.ts, h.nonce, route, body), 'hex');
    const got = Buffer.from(h.sig, 'hex');
    if (got.length !== want.length || !timingSafeEqual(got, want)) return false;
    for (const [n, t] of this.#seen) if (now - t > this.#skewMs * 2) this.#seen.delete(n);
    const k = `${h.keyId}:${h.nonce}`;
    if (this.#seen.has(k)) return false;
    this.#seen.set(k, now);
    return true;
  }
}
