/** Token bucket per key. Memory is bounded: stale keys are evicted, and the map is reset if still full. */
export class RateLimiter {
  #b = new Map<string, { tokens: number; last: number }>();
  #cap: number; #perMs: number; #max: number;
  constructor(capacity: number, refillPerSec: number, maxKeys = 10_000) {
    this.#cap = capacity; this.#perMs = refillPerSec / 1000; this.#max = maxKeys;
  }
  #refill(k: string, now: number) {
    const b = this.#b.get(k);
    if (!b) return undefined;
    b.tokens = Math.min(this.#cap, b.tokens + (now - b.last) * this.#perMs);
    b.last = now;
    return b;
  }
  /** Tokens left right now, without consuming one. */
  peek(key: string, now: number): number { return this.#refill(key, now)?.tokens ?? this.#cap; }
  /** Consumes one token; false means the caller is over the limit. */
  allow(key: string, now: number): boolean {
    let b = this.#refill(key, now);
    if (!b) {
      if (this.#b.size >= this.#max) {
        for (const [k, v] of this.#b) if (now - v.last > 60_000) this.#b.delete(k);
        if (this.#b.size >= this.#max) this.#b.clear();
      }
      b = { tokens: this.#cap, last: now };
      this.#b.set(key, b);
    }
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }
}
