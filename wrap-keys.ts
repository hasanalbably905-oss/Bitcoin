// Usage: STATE_KEYS='{"k1":"<64 hex>"}' STATE_KEY_CURRENT=k1 WRAP_PASSPHRASE='long passphrase' npm run wrap-keys
// Prints the encrypted blob to store as STATE_KEYS_WRAPPED. Then delete the plain STATE_KEYS from every place it lived.
import { wrapKeys } from '../src/keywrap.ts';
const keys = JSON.parse(process.env.STATE_KEYS ?? '');
console.log(await wrapKeys(keys, process.env.STATE_KEY_CURRENT ?? '', process.env.WRAP_PASSPHRASE ?? ''));
