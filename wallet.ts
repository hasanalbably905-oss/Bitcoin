import { HDKey } from '@scure/bip32';
import * as btc from '@scure/btc-signer';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { WalletError } from './errors.js';
import { assertValidMnemonic, mnemonicToSeed, newMnemonic, type WordCount } from './mnemonic.js';
import { DEFAULT_KDF, decryptSecret, encryptSecret, type KdfParams, type VaultBlob } from './vault.js';
import type { SecureStorage } from './storage.js';

export type Network = 'mainnet' | 'testnet';
const VAULT_KEY = 'btcwallet.vault.v1';
const ATTEMPTS_KEY = 'btcwallet.attempts.v1';
const coinType = (n: Network) => (n === 'mainnet' ? 0 : 1);
const netParams = (n: Network) => (n === 'mainnet' ? btc.NETWORK : btc.TEST_NETWORK);

const DUST_SATS = 294n; // P2WPKH dust threshold: smaller outputs are uneconomical to spend

/** The input amount signed by SegWit v0 is NOT verifiable from witnessUtxo alone (BIP-143 flaw), so the full previous tx is required and checked. */
function verifyPrevTx(inp: any, i: number): void {
  const prev = inp.nonWitnessUtxo;
  if (!prev || inp.index === undefined || !inp.txid) throw new WalletError('INVALID_PSBT', `Input ${i} must include the full previous transaction`);
  let id: string;
  try { id = btc.Transaction.fromRaw(btc.RawTx.encode(prev), { allowUnknownOutputs: true, allowUnknownInputs: true, disableScriptCheck: true }).id; }
  catch { throw new WalletError('INVALID_PSBT', `Input ${i}: previous transaction cannot be verified`); }
  if (id !== bytesToHex(inp.txid)) throw new WalletError('INVALID_PSBT', `Input ${i}: previous transaction does not match its id`);
  const out = prev.outputs?.[inp.index];
  if (!out) throw new WalletError('INVALID_PSBT', `Input ${i}: referenced output does not exist`);
  const w = inp.witnessUtxo;
  if (w && (w.amount !== out.amount || bytesToHex(w.script) !== bytesToHex(out.script))) throw new WalletError('INVALID_PSBT', `Input ${i}: amount or script was falsified`);
}

export interface ExpectedOutput { address: string; amountSats: bigint }
export interface SignOptions {
  /** Exactly what the user confirmed on screen. Anything else (except our own change) is rejected. */
  expectedOutputs: ExpectedOutput[];
  /** Hard ceiling on the fee; required so integrators must choose one. */
  maxFeeSats: bigint;
  /** Addresses scanned per chain to recognise our own inputs/change. */
  scanLimit?: number;
  /** BIP-84 account index used for both derivation and signing. Defaults to account 0. */
  account?: number;
}

/** Holds the HD root in memory until lock(). Auto-locks after inactivity. */
export class UnlockedSession {
  #root: HDKey | null;
  #timer: ReturnType<typeof setTimeout> | undefined;

  constructor(seed: Uint8Array, private net: Network, private autoLockMs: number, private onLock?: () => void) {
    this.#root = HDKey.fromMasterSeed(seed);
    this.touch();
  }

  get isLocked(): boolean { return this.#root === null; }

  lock(): void {
    clearTimeout(this.#timer);
    this.#root?.wipePrivateData();
    this.#root = null;
    this.onLock?.();
  }

  /** Call on user activity to postpone auto-lock. */
  touch(): void {
    if (this.#root === null) return;
    clearTimeout(this.#timer);
    this.#timer = setTimeout(() => this.lock(), this.autoLockMs);
    (this.#timer as { unref?: () => void }).unref?.();
  }

  #account(account: number): HDKey {
    if (this.#root === null) throw new WalletError('SESSION_LOCKED', 'Wallet is locked');
    return this.#root.derive(`m/84'/${coinType(this.net)}'/${account}'`); // BIP84 native SegWit
  }

  #leaf(acct: HDKey, change: 0 | 1, index: number): HDKey {
    const chain = acct.deriveChild(change);
    try { return chain.deriveChild(index); } finally { chain.wipePrivateData(); }
  }

  /** bc1q… receive (change=0) or change (change=1) address. */
  address(index: number, change: 0 | 1 = 0, account = 0): string {
    this.touch();
    const acct = this.#account(account);
    try {
      const k = this.#leaf(acct, change, index);
      const addr = btc.p2wpkh(k.publicKey!, netParams(this.net)).address!;
      k.wipePrivateData();
      return addr;
    } finally { acct.wipePrivateData(); }
  }

  /** Watch-only key: can derive addresses, cannot spend. Safe to hand to a backend. */
  accountXpub(account = 0): string {
    const acct = this.#account(account);
    try { return acct.publicExtendedKey; } finally { acct.wipePrivateData(); }
  }

  /** Validates, signs and finalizes a PSBT. Returns the raw transaction bytes to broadcast. */
  signPsbt(psbt: Uint8Array, o: SignOptions): Uint8Array {
    this.touch();
    const net = netParams(this.net);
    const limit = o.scanLimit ?? 100;
    const account = o.account ?? 0;
    if (!Number.isSafeInteger(account) || account < 0 || account > 100_000) throw new WalletError('INVALID_PSBT', 'Invalid account index');
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) throw new WalletError('INVALID_PSBT', 'scanLimit must be between 1 and 10000');
    const acct = this.#account(account);
    const keys = new Map<string, HDKey>(); // our scriptPubKey (hex) -> key
    try {
      for (const change of [0, 1] as const) {
        for (let i = 0; i < limit; i++) {
          const k = this.#leaf(acct, change, i);
          keys.set(bytesToHex(btc.p2wpkh(k.publicKey!, net).script), k);
        }
      }

      let tx: btc.Transaction;
      try { tx = btc.Transaction.fromPSBT(psbt); } catch { throw new WalletError('INVALID_PSBT', 'Cannot parse PSBT'); }

      for (let i = 0; i < tx.inputsLength; i++) { // verify BEFORE any amount is trusted
        const inp = tx.getInput(i);
        const sh = inp.sighashType;
        if (sh !== undefined && sh !== 0 && sh !== 1) throw new WalletError('INVALID_PSBT', `Input ${i} asks for a non-default signature hash type`);
        verifyPrevTx(inp, i);
      }
      for (const e of o.expectedOutputs) if (e.amountSats < DUST_SATS) throw new WalletError('INVALID_PSBT', 'Output amount is below the dust threshold');

      let fee: bigint;
      try { fee = tx.fee; } catch { throw new WalletError('INVALID_PSBT', 'Input amounts are missing'); }
      if (fee < 0n) throw new WalletError('INVALID_PSBT', 'Outputs exceed inputs');
      if (fee > o.maxFeeSats) throw new WalletError('FEE_TOO_HIGH', `Fee ${fee} sats exceeds limit ${o.maxFeeSats}`);

      const remaining = o.expectedOutputs.map((e) => {
        try {
          return { s: bytesToHex(btc.OutScript.encode(btc.Address(net).decode(e.address))), a: e.amountSats };
        } catch { throw new WalletError('INVALID_PSBT', 'Invalid destination address'); }
      });
      for (let i = 0; i < tx.outputsLength; i++) {
        const out = tx.getOutput(i);
        if (!out.script || out.amount === undefined) throw new WalletError('INVALID_PSBT', 'Malformed output');
        const s = bytesToHex(out.script);
        const hit = remaining.findIndex((r) => r.s === s && r.a === out.amount);
        if (hit >= 0) remaining.splice(hit, 1);
        else if (!keys.has(s)) throw new WalletError('UNEXPECTED_OUTPUT', `Output ${i} was not approved by the user`);
      }
      if (remaining.length > 0) throw new WalletError('MISSING_OUTPUT', 'An approved output is missing');

      for (let i = 0; i < tx.inputsLength; i++) {
        const script = tx.getInput(i).witnessUtxo?.script;
        const key = script ? keys.get(bytesToHex(script)) : undefined;
        if (!key) throw new WalletError('UNKNOWN_INPUT', `Input ${i} does not belong to this wallet`);
        if (!tx.signIdx(key.privateKey!, i)) throw new WalletError('INVALID_PSBT', `Could not sign input ${i}`);
      }
      tx.finalize();
      return tx.extract();
    } finally {
      for (const k of keys.values()) k.wipePrivateData();
      acct.wipePrivateData();
    }
  }
}

/** Wraps the whole stored vault with a key that never leaves the phone's Secure Enclave / StrongBox Keystore (second encryption layer). */
export interface DeviceWrapper { wrap(data: Uint8Array): Promise<Uint8Array>; unwrap(data: Uint8Array): Promise<Uint8Array> }

export interface WalletVaultOptions {
  deviceWrapper?: DeviceWrapper;
  network?: Network; kdf?: KdfParams; autoLockMs?: number; now?: () => number;
}

export class WalletVault {
  constructor(private store: SecureStorage, private opt: WalletVaultOptions = {}) {}
  #now = () => (this.opt.now ?? Date.now)();

  async exists(): Promise<boolean> { return (await this.store.get(VAULT_KEY)) !== null; }

  /** Creates a wallet and returns the recovery phrase ONCE so the user can back it up. Never log it. */
  async create(password: string, words: WordCount = 24): Promise<string> {
    if (await this.exists()) throw new WalletError('WALLET_EXISTS', 'A wallet already exists');
    return this.#save(newMnemonic(words), password);
  }

  async import(mnemonic: string, password: string): Promise<void> {
    if (await this.exists()) throw new WalletError('WALLET_EXISTS', 'A wallet already exists');
    await this.#save(mnemonic, password);
  }

  async unlock(password: string, bip39Passphrase = ''): Promise<UnlockedSession> {
    const secret = await this.#open(password);
    const seed = mnemonicToSeed(new TextDecoder().decode(secret), bip39Passphrase);
    secret.fill(0);
    try {
      return new UnlockedSession(seed, this.opt.network ?? 'mainnet', this.opt.autoLockMs ?? 60_000);
    } finally { seed.fill(0); }
  }

  /** Re-authenticates, then returns the phrase for backup display. */
  async revealMnemonic(password: string): Promise<string> {
    const secret = await this.#open(password);
    try { return new TextDecoder().decode(secret); } finally { secret.fill(0); }
  }

  async changePassword(oldPassword: string, newPassword: string): Promise<void> {
    const secret = await this.#open(oldPassword);
    try { await this.#write(secret, newPassword); } finally { secret.fill(0); }
  }

  async wipe(): Promise<void> {
    await this.store.delete(VAULT_KEY);
    await this.store.delete(ATTEMPTS_KEY);
  }

  async #save(mnemonic: string, password: string): Promise<string> {
    const m = assertValidMnemonic(mnemonic);
    const bytes = new TextEncoder().encode(m);
    try { await this.#write(bytes, password); } finally { bytes.fill(0); }
    return m;
  }

  async #write(secret: Uint8Array, password: string): Promise<void> {
    const blob = await encryptSecret(secret, password, this.opt.kdf ?? DEFAULT_KDF);
    let out = JSON.stringify(blob);
    const w = this.opt.deviceWrapper;
    if (w) out = 'w1:' + bytesToHex(await w.wrap(new TextEncoder().encode(out)));
    await this.store.set(VAULT_KEY, out);
  }

  // Serialises attempts so parallel unlock() calls cannot all read the same failure counter and bypass the lockout.
  #queue: Promise<unknown> = Promise.resolve();
  #open(password: string): Promise<Uint8Array> {
    const run = this.#queue.then(() => this.#openOnce(password), () => this.#openOnce(password));
    this.#queue = run.catch(() => {});
    return run;
  }

  async #openOnce(password: string): Promise<Uint8Array> {
    const a = await this.#attempts();
    if (a.count >= 5) {
      const wait = Math.min(60_000 * 2 ** (a.count - 5), 3_600_000);
      const left = a.lastAt + wait - this.#now();
      if (left > 0) throw new WalletError('LOCKED_OUT', 'Too many failed attempts', left);
    }
    const raw = await this.store.get(VAULT_KEY);
    if (raw === null) throw new WalletError('NO_WALLET', 'No wallet found');
    let text = raw;
    const w = this.opt.deviceWrapper;
    if (raw.startsWith('w1:')) {
      if (!w) throw new WalletError('BAD_VAULT', 'This vault needs the device key');
      try { text = new TextDecoder().decode(await w.unwrap(hexToBytes(raw.slice(3)))); }
      catch { throw new WalletError('BAD_VAULT', 'Device key could not unlock the vault'); }
    } else if (w) {
      throw new WalletError('BAD_VAULT', 'Vault is not device-wrapped (possible downgrade)'); // refuse silently weaker storage
    }
    let blob: VaultBlob;
    try { blob = JSON.parse(text); } catch { throw new WalletError('BAD_VAULT', 'Vault data is corrupt'); }
    try {
      const secret = await decryptSecret(blob, password);
      await this.store.delete(ATTEMPTS_KEY);
      return secret;
    } catch (e) {
      await this.store.set(ATTEMPTS_KEY, JSON.stringify({ count: a.count + 1, lastAt: this.#now() }));
      throw e;
    }
  }

  async #attempts(): Promise<{ count: number; lastAt: number }> {
    const raw = await this.store.get(ATTEMPTS_KEY);
    try {
      const j = raw ? JSON.parse(raw) : {};
      return { count: Number(j.count) || 0, lastAt: Number(j.lastAt) || 0 };
    } catch { return { count: 0, lastAt: 0 }; }
  }
}
