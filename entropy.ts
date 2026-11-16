import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, randomBytes } from '@noble/hashes/utils.js';
import { WalletError } from './errors.js';
import { assessEntropy } from './entropy-health.js';

const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const u64 = (n: number) => { const o = new Uint8Array(8); new DataView(o.buffer).setBigUint64(0, BigInt(n)); return o; };

/**
 * Wallet seed entropy: two independent draws from the platform CSPRNG, each health-checked, mixed with optional user-supplied
 * entropy (dice, touch timings) and the clock through SHA-256. Fails closed (never falls back to anything weaker).
 * On React Native the platform CSPRNG must be native-backed (react-native-get-random-values). `rng` is injectable for tests.
 */
export function secureEntropy(bytes: 16 | 32 = 32, extra: Uint8Array = new Uint8Array(0), rng: (n: number) => Uint8Array = randomBytes): Uint8Array {
  for (let attempt = 0; attempt < 4; attempt++) {
    const a = rng(32), b = rng(32);
    if (!assessEntropy(a).ok || !assessEntropy(b).ok || same(a, b)) continue;
    const out = sha256(concatBytes(new TextEncoder().encode('btc-wallet-entropy-v1'), a, b, extra, u64(Date.now()), u64(attempt))).slice(0, bytes);
    if (assessEntropy(out).ok) return out;
  }
  throw new WalletError('ENTROPY_UNHEALTHY', 'The random number generator failed its health check. Do not create a wallet on this device.');
}
