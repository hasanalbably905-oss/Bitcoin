# btc-wallet-security

Key management and transaction-signing core for a self-custody Bitcoin wallet (TypeScript).
It contains **no UI and no networking**. Your team builds those on top.

## What it does
- **Recovery phrase**: BIP39, 12 or 24 words, validated on import.
- **Keys**: BIP32/BIP84 native SegWit (`bc1q…`), mainnet and testnet. Private keys live only inside an unlocked session.
- **Encrypted vault**: scrypt + XChaCha20-Poly1305. KDF parameters are versioned, authenticated, and bounds-checked.
- **Unlock throttling**: exponential lockout after 5 wrong passwords.
- **Auto-lock** with best-effort wiping of key material.
- **Safe signing**: `signPsbt` signs only inputs that belong to the wallet, only outputs the user approved (plus own change), and never above `maxFeeSats`. This blocks address-swap malware and fee-drain attacks.
- Cryptography comes from the audited `@noble/*` and `@scure/*` libraries. Nothing is hand-rolled.

## Usage
```ts
const vault = new WalletVault(keychainStorage, { network: 'mainnet' });
const phrase = await vault.create(password);            // show once for backup, never log
const session = await vault.unlock(password);
const addr = session.address(0);                        // receive address
const raw = session.signPsbt(psbtBytes, {
  expectedOutputs: [{ address, amountSats }],           // what the user confirmed on screen
  maxFeeSats: 50_000n,
});                                                     // broadcast `raw` via your backend/node
session.lock();
```

## What your team must provide
1. **`SecureStorage`** backed by iOS Keychain (`ThisDeviceOnly`, biometric access control) / Android Keystore (StrongBox if available). Never AsyncStorage or plain files.
2. **Secure randomness**: React Native needs `react-native-get-random-values` loaded first (and `TextEncoder`/`TextDecoder` on older Hermes). Without it the code throws instead of using weak randomness.
3. **UI hygiene**: block screenshots and app-switcher previews on secret screens, clear the clipboard, never log secrets or put them in crash reports or analytics.
4. **Backend**: UTXO lookup, fee estimation, broadcasting. Use `accountXpub()` (watch-only) if the server needs to derive addresses.
5. **Receiving**: a BIP84 address accepts payments from any wallet that supports Bitcoin. Other coins sent to it can be lost, so keep the warning in the UI.

## Known limits
- JavaScript cannot guarantee memory wiping (strings are immutable, the GC copies). Wiping here is best effort. For stronger guarantees, do the signing in native or secure-enclave code.
- Lockout counters are client-side. An attacker who copies the vault file can brute-force offline, so password strength and hardware-backed storage matter. 10+ characters are enforced.
- The BIP39 passphrase (25th word) is supported at unlock but is not stored.
- Only single-sig P2WPKH is supported. Taproot, multisig, and hardware-wallet flows are out of scope.

## Before real funds
1. Run `npm install && npm test`. **This code has not been executed yet**, so fix any API mismatches against the installed library versions.
2. Pin exact dependency versions, commit the lockfile, and enable npm provenance and audit checks in CI.
3. Get an **independent security review** of this module and your storage and UI layers.
4. Test on testnet first, including restore-from-phrase on a different device.
