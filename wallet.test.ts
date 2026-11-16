import { describe, it, expect } from 'vitest';
import * as btc from '@scure/btc-signer';
import { WalletVault, MemoryStorage, newMnemonic, assertValidMnemonic, type UnlockedSession } from '../src/index.js';

const ABOUT = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const FAST = { N: 2 ** 14, r: 8, p: 1 }; // fast for tests only
const PW = 'correct horse battery staple';
const EXT = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'; // BIP173 vector, not ours

async function setup() {
  const store = new MemoryStorage();
  const v = new WalletVault(store, { kdf: FAST });
  await v.import(ABOUT, PW);
  return { store, v, s: await v.unlock(PW) };
}
const codeOf = async (fn: () => unknown) => {
  try { await fn(); return 'no-error'; } catch (e: any) { return e.code ?? String(e); }
};
const script = (addr: string) => btc.OutScript.encode(btc.Address(btc.NETWORK).decode(addr));
function prevTxFor(addr: string, amount: bigint) { // a full previous transaction paying `addr`
  const t = new btc.Transaction({ allowUnknownInputs: true });
  t.addInput({ txid: '33'.repeat(32), index: 0, witnessUtxo: { script: script(addr), amount: amount + 1_000n } });
  t.addOutput({ script: script(addr), amount });
  const raw = t.unsignedTx;
  return { raw, id: btc.Transaction.fromRaw(raw, { allowUnknownInputs: true }).id };
}
function psbt(s: UnlockedSession, inputAddr: string, out: bigint, change: bigint, lieAbout?: bigint) {
  const tx = new btc.Transaction();
  const prev = prevTxFor(inputAddr, 100_000n);
  tx.addInput({ txid: prev.id, index: 0, nonWitnessUtxo: prev.raw, ...(lieAbout !== undefined ? { witnessUtxo: { script: script(inputAddr), amount: lieAbout } } : {}) });
  tx.addOutputAddress(EXT, out, btc.NETWORK);
  tx.addOutputAddress(s.address(0, 1), change, btc.NETWORK);
  return tx.toPSBT();
}

describe('mnemonic', () => {
  it('generates valid 12/24 word phrases', () => {
    expect(newMnemonic(12).split(' ')).toHaveLength(12);
    expect(newMnemonic(24).split(' ')).toHaveLength(24);
  });
  it('rejects a bad checksum', () => {
    expect(() => assertValidMnemonic(ABOUT.replace('about', 'abandon'))).toThrow();
  });
});

describe('BIP84 derivation', () => {
  it('matches the official test vectors', async () => {
    const { s } = await setup();
    expect(s.address(0)).toBe('bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
    expect(s.address(1)).toBe('bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g');
    expect(s.address(0, 1)).toBe('bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el');
  });
});

describe('vault', () => {
  it('rejects a wrong password and a weak password', async () => {
    const { v } = await setup();
    expect(await codeOf(() => v.unlock('wrong password here'))).toBe('WRONG_PASSWORD_OR_CORRUPT');
    const v2 = new WalletVault(new MemoryStorage(), { kdf: FAST });
    expect(await codeOf(() => v2.import(ABOUT, 'short'))).toBe('WEAK_PASSWORD');
  });
  it('detects tampering', async () => {
    const { store, v } = await setup();
    const blob = JSON.parse((await store.get('btcwallet.vault.v1'))!);
    blob.ct = blob.ct.slice(0, -2) + (blob.ct.endsWith('00') ? '11' : '00');
    await store.set('btcwallet.vault.v1', JSON.stringify(blob));
    expect(await codeOf(() => v.unlock(PW))).toBe('WRONG_PASSWORD_OR_CORRUPT');
  });
  it('locks out after repeated failures', async () => {
    const { v } = await setup();
    for (let i = 0; i < 5; i++) await codeOf(() => v.unlock('wrong password here'));
    expect(await codeOf(() => v.unlock(PW))).toBe('LOCKED_OUT');
  });
  it('changes the password', async () => {
    const { v } = await setup();
    await v.changePassword(PW, 'a brand new password');
    expect(await v.revealMnemonic('a brand new password')).toBe(ABOUT);
  });
});

describe('session', () => {
  it('refuses to work after lock()', async () => {
    const { s } = await setup();
    s.lock();
    expect(s.isLocked).toBe(true);
    expect(await codeOf(() => s.address(0))).toBe('SESSION_LOCKED');
  });
});

describe('signPsbt', () => {
  const opts = (amt: bigint) => ({ expectedOutputs: [{ address: EXT, amountSats: amt }], maxFeeSats: 5_000n });
  it('signs an approved transaction', async () => {
    const { s } = await setup();
    const raw = s.signPsbt(psbt(s, s.address(0), 60_000n, 39_000n), opts(60_000n));
    expect(raw.length).toBeGreaterThan(100);
  });
  it('rejects an output the user did not approve', async () => {
    const { s } = await setup();
    const p = psbt(s, s.address(0), 60_000n, 39_000n);
    expect(await codeOf(() => s.signPsbt(p, opts(50_000n)))).toBe('UNEXPECTED_OUTPUT');
  });
  it('rejects an excessive fee', async () => {
    const { s } = await setup();
    const p = psbt(s, s.address(0), 60_000n, 1_000n);
    expect(await codeOf(() => s.signPsbt(p, opts(60_000n)))).toBe('FEE_TOO_HIGH');
  });
  it('refuses inputs that are not ours', async () => {
    const { s } = await setup();
    const p = psbt(s, EXT, 60_000n, 39_000n);
    expect(await codeOf(() => s.signPsbt(p, opts(60_000n)))).toBe('UNKNOWN_INPUT');
  });
});

describe('EncryptedStorage', () => {
  it('hides values, binds them to their key, and detects tampering', async () => {
    const { EncryptedStorage } = await import('../src/index.js');
    const inner = new MemoryStorage();
    const s = new EncryptedStorage(inner, EncryptedStorage.generateKey());
    await s.set('tx:1', 'sent 0.001 BTC to bc1q-secret-label');
    expect(await s.get('tx:1')).toBe('sent 0.001 BTC to bc1q-secret-label');
    expect(await inner.get('tx:1')).not.toContain('secret-label');
    await inner.set('tx:2', (await inner.get('tx:1'))!); // value moved to another key
    expect(await codeOf(() => s.get('tx:2'))).toBe('WRONG_PASSWORD_OR_CORRUPT');
    expect(await s.get('nothing')).toBeNull();
  });
});


describe('device wrapper (second layer)', () => {
  const fake = { // stands in for the Secure Enclave: XOR with a secret byte
    wrap: async (d: Uint8Array) => d.map((b) => b ^ 0x5a),
    unwrap: async (d: Uint8Array) => d.map((b) => b ^ 0x5a),
  };
  it('stores the vault wrapped, opens it with the wrapper, and refuses a downgrade', async () => {
    const store = new MemoryStorage();
    const v = new WalletVault(store, { kdf: FAST, deviceWrapper: fake });
    await v.import(ABOUT, PW);
    const raw = (await store.get('btcwallet.vault.v1'))!;
    expect(raw.startsWith('w1:')).toBe(true);
    expect(raw).not.toContain('ciphertext');
    expect((await v.unlock(PW)).address(0)).toBe('bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
    expect(await codeOf(() => new WalletVault(store, { kdf: FAST }).unlock(PW))).toBe('BAD_VAULT');
    const plainStore = new MemoryStorage();
    await new WalletVault(plainStore, { kdf: FAST }).import(ABOUT, PW);
    expect(await codeOf(() => new WalletVault(plainStore, { kdf: FAST, deviceWrapper: fake }).unlock(PW))).toBe('BAD_VAULT');
  });
});


describe('signPsbt: falsified input amounts (BIP-143 fee attack)', () => {
  const opts = { expectedOutputs: [{ address: EXT, amountSats: 60_000n }], maxFeeSats: 5_000n };
  it('signs when the previous transaction proves the amount', async () => {
    const { s } = await setup();
    expect(s.signPsbt(psbt(s, s.address(0), 60_000n, 39_000n), opts).length).toBeGreaterThan(100);
  });
  it('refuses an understated witnessUtxo amount', async () => {
    const { s } = await setup();
    expect(await codeOf(() => s.signPsbt(psbt(s, s.address(0), 60_000n, 39_000n, 61_000n), opts))).toBe('INVALID_PSBT');
  });
  it('refuses inputs without the full previous transaction', async () => {
    const { s } = await setup();
    const tx = new btc.Transaction();
    tx.addInput({ txid: '11'.repeat(32), index: 0, witnessUtxo: { script: script(s.address(0)), amount: 100_000n } });
    tx.addOutputAddress(EXT, 60_000n, btc.NETWORK); tx.addOutputAddress(s.address(0, 1), 39_000n, btc.NETWORK);
    expect(await codeOf(() => s.signPsbt(tx.toPSBT(), opts))).toBe('INVALID_PSBT');
  });
  it('refuses dust outputs', async () => {
    const { s } = await setup();
    expect(await codeOf(() => s.signPsbt(psbt(s, s.address(0), 100n, 99_000n), { expectedOutputs: [{ address: EXT, amountSats: 100n }], maxFeeSats: 5_000n }))).toBe('INVALID_PSBT');
  });
});

describe('secureEntropy', () => {
  it('rejects a dead or stuck generator and accepts a healthy one', async () => {
    const { secureEntropy } = await import('../src/index.js');
    expect(() => secureEntropy(32, undefined, (n) => new Uint8Array(n))).toThrow();
    expect(() => secureEntropy(32, undefined, (n) => Uint8Array.from({ length: n }, (_, i) => i))).toThrow();
    expect(secureEntropy(32)).toHaveLength(32);
    expect(secureEntropy(16, new Uint8Array([1, 2, 3]))).toHaveLength(16);
  });
});
