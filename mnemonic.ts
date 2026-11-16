import { entropyToMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { WalletError } from './errors.js';
import { secureEntropy } from './entropy.js';

export type WordCount = 12 | 24;
const BYTES: Record<WordCount, 16 | 32> = { 12: 16, 24: 32 };

/** Health-checked, mixed CSPRNG entropy (see entropy.ts). Fails closed. `extraEntropy` optionally adds user-supplied randomness. */
export function newMnemonic(words: WordCount = 24, extraEntropy?: Uint8Array): string {
  return entropyToMnemonic(secureEntropy(BYTES[words], extraEntropy), wordlist);
}

export function normalizeMnemonic(input: string): string {
  return input.normalize('NFKD').trim().toLowerCase().split(/\s+/).join(' ');
}

export function assertValidMnemonic(input: string): string {
  const m = normalizeMnemonic(input);
  if (!validateMnemonic(m, wordlist)) {
    throw new WalletError('INVALID_MNEMONIC', 'Recovery phrase is invalid');
  }
  return m;
}

/** 64-byte BIP39 seed. Wipe it (fill(0)) as soon as the HD root is built. */
export function mnemonicToSeed(mnemonic: string, bip39Passphrase = ''): Uint8Array {
  return mnemonicToSeedSync(assertValidMnemonic(mnemonic), bip39Passphrase);
}
