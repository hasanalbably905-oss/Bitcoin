/** Exponentially-weighted mean/variance baseline. Learns "normal"; flags big deviations. */
export class Baseline {
  #n = 0;
  #mean = 0;
  #var = 0;
  #alpha: number;
  constructor(alpha = 0.02) { this.#alpha = alpha; }
  get samples(): number { return this.#n; }
  zscore(x: number): number {
    if (this.#n === 0) return 0;
    const sd = Math.max(Math.sqrt(this.#var), 0.05 * Math.abs(this.#mean), 1e-9);
    return (x - this.#mean) / sd;
  }
  update(x: number): void {
    if (this.#n === 0) { this.#mean = x; this.#var = 0; }
    else {
      const diff = x - this.#mean;
      const incr = this.#alpha * diff;
      this.#mean += incr;
      this.#var = (1 - this.#alpha) * (this.#var + diff * incr);
    }
    this.#n++;
  }
}

export type AnomalyLevel = 'ok' | 'warning' | 'critical';

export class AnomalyDetector {
  #b = new Map<string, Baseline>();
  #minSamples: number; #warnZ: number; #critZ: number;
  constructor(minSamples = 30, warnZ = 4, critZ = 6) { this.#minSamples = minSamples; this.#warnZ = warnZ; this.#critZ = critZ; }
  check(name: string, value: number): { z: number; level: AnomalyLevel } {
    let b = this.#b.get(name);
    if (!b) { if (this.#b.size >= 500) return { z: 0, level: 'ok' }; b = new Baseline(); this.#b.set(name, b); }
    const z = b.zscore(value);
    const a = Math.abs(z);
    const level: AnomalyLevel = b.samples < this.#minSamples ? 'ok' : a >= this.#critZ ? 'critical' : a >= this.#warnZ ? 'warning' : 'ok';
    if (level === 'ok') b.update(value); // never learn from anomalies (baseline poisoning)
    return { z, level };
  }
}
