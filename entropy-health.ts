/**
 * Sanity checks on raw random bytes. They cannot prove randomness, but they catch the catastrophic failures seen in real wallet
 * thefts (constant output, counters, repeating blocks, stuck bits, a PRNG that was never seeded): "Ill Bloom" (2026), Milk Sad and
 * Trust Wallet (2023), Randstorm. Pure and dependency-free, so it is unit-tested everywhere.
 */
export function assessEntropy(b: Uint8Array): { ok: boolean; reason: string } {
  const n = b.length;
  if (n < 16) return { ok: false, reason: 'too short' };
  if (b.every((x) => x === b[0])) return { ok: false, reason: 'constant bytes' };
  if (new Set(b).size < Math.ceil(n * 0.55)) return { ok: false, reason: 'too few distinct bytes' };
  for (let p = 1; p <= n / 2; p++) { // periodic output
    let same = true;
    for (let i = 0; i + p < n; i++) if (b[i] !== b[i + p]) { same = false; break; }
    if (same) return { ok: false, reason: `repeats every ${p} bytes` };
  }
  const d = (b[1]! - b[0]! + 256) % 256; // arithmetic sequence / counter
  if (b.every((x, i) => i === 0 || (x - b[i - 1]! + 256) % 256 === d)) return { ok: false, reason: 'counter-like sequence' };
  let ones = 0;
  for (const x of b) { let v = x; while (v) { ones += v & 1; v >>= 1; } }
  const bits = n * 8;
  if (Math.abs(ones - bits / 2) > 0.2 * bits) return { ok: false, reason: 'bit balance is implausible' };
  return { ok: true, reason: 'ok' };
}
