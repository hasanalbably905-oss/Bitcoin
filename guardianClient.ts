// Owner-app client (React Native / any JS runtime). UNTESTED here: needs `npm i @noble/hashes @noble/ciphers`.
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { gcm } from '@noble/ciphers/aes.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';

export type BreakerName = 'SENDS' | 'RELEASES' | 'SERVICE';
const enc = new TextEncoder();

export class GuardianClient {
  private e2e: Uint8Array;
  constructor(private baseUrl: string, private keyId: string, private secret: Uint8Array) {
    // Must match the server: HKDF-SHA256(secret, salt 'guardian-e2e-salt-v1', info 'guardian/e2e/v1') -> 32-byte AES-GCM key
    this.e2e = hkdf(sha256, secret, enc.encode('guardian-e2e-salt-v1'), enc.encode('guardian/e2e/v1'), 32);
  }
  private b64u(b: Uint8Array) { let s = ''; b.forEach((x) => (s += String.fromCharCode(x))); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  private unb64u(t: string) { const s = atob(t.replace(/-/g, '+').replace(/_/g, '/')); return Uint8Array.from(s, (c) => c.charCodeAt(0)); }
  private seal(plain: string, aad: string) {
    const iv = randomBytes(12); const out = gcm(this.e2e, iv, enc.encode(aad)).encrypt(enc.encode(plain));
    return `v1.e.${this.b64u(iv)}.${this.b64u(out.slice(0, -16))}.${this.b64u(out.slice(-16))}`;
  }
  private unseal(sealed: string, aad: string) {
    const [v, e, iv, ct, tag] = sealed.split('.');
    if (v !== 'v1' || e !== 'e' || !iv || !ct || !tag) throw new Error('bad_envelope');
    const c = this.unb64u(ct), t = this.unb64u(tag); const joined = new Uint8Array(c.length + t.length); joined.set(c); joined.set(t, c.length);
    return new TextDecoder().decode(gcm(this.e2e, this.unb64u(iv), enc.encode(aad)).decrypt(joined));
  }

  private async call<T>(method: 'GET' | 'POST', path: string, payload?: unknown): Promise<T> {
    const ts = Date.now();
    const nonce = bytesToHex(randomBytes(16));
    const route = `${method} ${path}`;
    const body = payload === undefined ? '' : this.seal(JSON.stringify(payload), `req|${route}|${ts}|${nonce}`);
    const sig = bytesToHex(hmac(sha256, this.secret, enc.encode(`${ts}.${nonce}.${route}.${body}`)));
    const res = await fetch(this.baseUrl + path, {
      method, body: method === 'GET' ? undefined : body,
      headers: { 'x-key-id': this.keyId, 'x-ts': String(ts), 'x-nonce': nonce, 'x-sig': sig, 'x-enc': '1' },
    });
    let json = await res.json();
    if (json?.enc) json = JSON.parse(this.unseal(json.enc, `res|${route}|${nonce}`));
    if (!res.ok) throw new Error(json?.error ?? `HTTP ${res.status}`);
    return json as T;
  }

  state() { return this.call<{ breakers: Record<BreakerName, boolean>; incidents: any[] }>('GET', '/state'); }
  registerDevice(token: string) { return this.call('POST', '/devices', { token }); }
  ack(id: string) { return this.call('POST', '/actions', { op: 'ack', id }); }
  close(id: string) { return this.call('POST', '/actions', { op: 'close', id }); }
  propose(name: BreakerName, frozen: boolean) { return this.call<{ id: string; done: boolean; needed: number; approvals: string[] }>('POST', '/actions', { op: 'propose', name, frozen }); }
  approve(id: string) { return this.call('POST', '/actions', { op: 'approve', id }); }
}
// Store `secret` in Keychain/Keystore (biometric-gated). Prefer one key per device so a lost phone can be revoked.
