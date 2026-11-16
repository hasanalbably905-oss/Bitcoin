import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm, stat } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Keyring, wrapKeys, unwrapKeys, FlagStore, createFrozenGuard, FrozenError, deriveE2eKey, e2eSeal, e2eOpen,
  GuardianReporter, Guardian, BreakerPanel, createGuardServer, defaultConfig, signRequest } from '../src/index.ts';

const K1 = 'a1'.repeat(32), K2 = 'b2'.repeat(32);
const tmp = () => mkdtemp(join(tmpdir(), 'hd-'));
class MemoryAnchor { #seq = new Map<string, number>(); async get(n: string) { return this.#seq.get(n) ?? 0; } async advance(n: string, e: number, v: number) { if ((this.#seq.get(n) ?? 0) !== e || v !== e + 1) return false; this.#seq.set(n, v); return true; } }
const OWN = 'o'.repeat(32), SEC = 'c'.repeat(32), SRC = 's'.repeat(32);

test('wrapped master keys: round-trip, wrong passphrase, weak passphrase, tampered parameters', async () => {
  const blob = await wrapKeys({ k1: K1, k2: K2 }, 'k2', 'a long passphrase 123');
  assert.ok(!blob.includes(K1) && !blob.includes(K2)); // master keys never appear in the file
  const ring = await unwrapKeys(blob, 'a long passphrase 123');
  assert.equal(ring.currentId, 'k2');
  assert.equal(ring.get('k1')?.toString('hex'), K1);
  await assert.rejects(unwrapKeys(blob, 'another passphrase 456'), /wrong passphrase/);
  await assert.rejects(wrapKeys({ k1: K1 }, 'k1', 'short'), /at least 16/);
  const j = JSON.parse(blob); j.N = 2 ** 16; // attacker weakens the KDF
  await assert.rejects(unwrapKeys(JSON.stringify(j), 'a long passphrase 123'), /wrong passphrase/);
  j.N = 2 ** 25;
  await assert.rejects(unwrapKeys(JSON.stringify(j), 'a long passphrase 123'), /unsupported/);
});

test('sealed freeze flags: forged, deleted, rolled-back or wrongly-keyed flags all count as FROZEN', async () => {
  const dir = await tmp(); const ring = new Keyring({ f: K1 }, 'f');
  const anchor = new MemoryAnchor();
  const fl = new FlagStore(dir, ring, anchor); await fl.init();
  assert.deepEqual(await fl.status('SENDS'), { frozen: false, reason: 'never set' });
  await fl.write('SENDS', true);
  assert.equal(await fl.isFrozen('SENDS'), true);
  assert.equal((await stat(join(dir, 'SENDS.flag'))).mode & 0o777, 0o640);
  const v1 = await readFile(join(dir, 'SENDS.flag'), 'utf8');
  await fl.write('SENDS', false);
  assert.equal(await fl.isFrozen('SENDS'), false);

  await writeFile(join(dir, 'SENDS.flag'), v1); // replay the old "frozen" flag... then an attacker would try the reverse:
  assert.deepEqual(await fl.status('SENDS'), { frozen: true, reason: 'rollback' });
  await fl.write('SENDS', false);
  const unfrozen = await readFile(join(dir, 'SENDS.flag'), 'utf8');
  await fl.write('SENDS', true);
  await writeFile(join(dir, 'SENDS.flag'), unfrozen); // attacker restores an older "unfrozen" flag
  assert.equal((await fl.status('SENDS')).reason, 'rollback');
  assert.equal(await fl.isFrozen('SENDS'), true);

  await fl.write('RELEASES', false);
  await writeFile(join(dir, 'RELEASES.flag'), '0'); // plain "0" is not a valid seal
  assert.deepEqual(await fl.status('RELEASES'), { frozen: true, reason: 'forged or corrupted' });
  await rm(join(dir, 'RELEASES.flag'));
  assert.deepEqual(await fl.status('RELEASES'), { frozen: true, reason: 'flag missing or deleted' });

  assert.equal(await new FlagStore(dir, new Keyring({ f: K2 }, 'f'), anchor).isFrozen('SENDS'), true); // wrong key
  const swap = await readFile(join(dir, 'SENDS.flag'), 'utf8');
  await writeFile(join(dir, 'SERVICE.flag'), swap); // a SENDS seal copied onto SERVICE
  assert.equal(await new FlagStore(dir, ring, anchor).isFrozen('SERVICE'), true);

  // A fresh process has no local sequence cache; the independent anchor still rejects replay.
  const restarted = new FlagStore(dir, ring, anchor); await restarted.init();
  await writeFile(join(dir, 'SENDS.flag'), unfrozen);
  assert.deepEqual(await restarted.status('SENDS'), { frozen: true, reason: 'rollback' });

  const guard = createFrozenGuard(fl);
  await assert.rejects(guard.assertNotFrozen('SENDS'), FrozenError);
});

async function boot(over: object = {}) {
  const g = new Guardian({ config: defaultConfig(), notifier: { async send() {} } });
  const panel = new BreakerPanel([{ id: 'owner', role: 'owner' }], { async apply() {} });
  const server = createGuardServer({ guardian: g, panel, sourceKeys: { api: SRC }, approverKeys: { owner: OWN, sec: SEC }, requireHttps: false, ...over });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return { g, server, base: `http://127.0.0.1:${(server.address() as any).port}` };
}
async function signedCall(base: string, method: string, path: string, keyId: string, secret: string, plain: string, o: { enc?: boolean; nonce?: string; sealNonce?: string } = {}) {
  const ts = Date.now(), nonce = o.nonce ?? `n-${Math.random().toString(36).slice(2)}-${ts}`;
  const key = deriveE2eKey(secret);
  const route = `${method} ${path}`;
  const body = plain ? (o.enc ? e2eSeal(key, plain, `req|${route}|${ts}|${o.sealNonce ?? nonce}`) : plain) : '';
  const res = await fetch(base + path, { method, body: method === 'GET' ? undefined : body,
    headers: { 'x-key-id': keyId, 'x-ts': String(ts), 'x-nonce': nonce, 'x-sig': signRequest(secret, ts, nonce, route, body), ...(o.enc ? { 'x-enc': '1' } : {}) } });
  const text = await res.text();
  return { status: res.status, text, key, route, nonce };
}

test('end-to-end encryption: bodies are ciphertext both ways; plaintext is refused when required; envelopes are bound to the request', async () => {
  const b = await boot({ encryptBodies: true });
  try {
    await b.g.ingest({ source: 'api', type: 'integrity.mismatch', data: { what: 'SECRET-DETAIL-XYZ' } });
    const r = await signedCall(b.base, 'GET', '/state', 'owner', OWN, '', { enc: true });
    assert.equal(r.status, 200);
    assert.ok(!r.text.includes('breakers') && !r.text.includes('SECRET-DETAIL-XYZ')); // what a TLS-terminating proxy sees
    const inner = JSON.parse(e2eOpen(r.key, JSON.parse(r.text).enc, `res|${r.route}|${r.nonce}`));
    assert.ok(inner.breakers && JSON.stringify(inner).includes('SECRET-DETAIL-XYZ'));
    assert.throws(() => e2eOpen(r.key, JSON.parse(r.text).enc, `res|${r.route}|other-nonce`)); // a response cannot be replayed for another request

    const plain = await signedCall(b.base, 'GET', '/state', 'owner', OWN, '');
    assert.equal(plain.status, 400); assert.match(plain.text, /encryption_required/);

    const act = JSON.stringify({ op: 'propose', name: 'SENDS', frozen: true });
    const swapped = await signedCall(b.base, 'POST', '/actions', 'owner', OWN, act, { enc: true, sealNonce: 'different-nonce-1234' }); // sealed for another request
    assert.equal(swapped.status, 400);
    const ok = await signedCall(b.base, 'POST', '/actions', 'owner', OWN, act, { enc: true });
    assert.equal(ok.status, 200);
    assert.equal(JSON.parse(e2eOpen(ok.key, JSON.parse(ok.text).enc, `res|${ok.route}|${ok.nonce}`)).done, true);
    const junk = await signedCall(b.base, 'POST', '/actions', 'owner', OWN, 'not-an-envelope', { enc: false });
    assert.equal(junk.status, 400);
  } finally { b.server.close(); }
});

test('the reporter sends only ciphertext on the wire', async () => {
  let seen = { body: '', enc: '' };
  const fake = createServer((req, res) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => { seen = { body: b, enc: String(req.headers['x-enc']) }; res.end('{}'); }); });
  await new Promise<void>((r) => fake.listen(0, '127.0.0.1', r));
  try {
    await new GuardianReporter({ url: `http://127.0.0.1:${(fake.address() as any).port}`, keyId: 'api', secret: SRC }).report('api', 'integrity.mismatch', { what: 'PLAINTEXT-MARKER' });
    assert.ok(seen.body.startsWith('v1.e.'));
    assert.ok(!seen.body.includes('PLAINTEXT-MARKER') && !seen.body.includes('integrity'));
    assert.equal(seen.enc, '1');
  } finally { fake.close(); }
});

function haveOpenssl() { try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); return true; } catch { return false; } }
test('mutual TLS: a CA-signed client certificate whose CN equals the key id is required', { skip: !haveOpenssl() }, async () => {
  const dir = await tmp();
  const sh = (...a: string[]) => execFileSync('openssl', a, { stdio: 'ignore', cwd: dir });
  const ca = (n: string) => sh('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${n}.key`, '-out', `${n}.pem`, '-subj', `/CN=${n}`, '-days', '1');
  const client = (cn: string, issuer: string) => {
    sh('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${cn}-${issuer}.key`, '-out', `${cn}-${issuer}.csr`, '-subj', `/CN=${cn}`);
    sh('x509', '-req', '-in', `${cn}-${issuer}.csr`, '-CA', `${issuer}.pem`, '-CAkey', `${issuer}.key`, '-CAcreateserial', '-out', `${cn}-${issuer}.pem`, '-days', '1');
  };
  ca('goodca'); ca('rogueca'); client('owner', 'goodca'); client('sec', 'goodca'); client('owner', 'rogueca');
  sh('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'srv.key', '-out', 'srv.pem', '-subj', '/CN=localhost', '-days', '1', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1');
  const f = (n: string) => readFileSync(join(dir, n));
  const g = new Guardian({ config: defaultConfig(), notifier: { async send() {} } });
  const panel = new BreakerPanel([{ id: 'owner', role: 'owner' }], { async apply() {} });
  const server = createGuardServer({ guardian: g, panel, sourceKeys: { api: SRC }, approverKeys: { owner: OWN, sec: SEC },
    tls: { cert: f('srv.pem'), key: f('srv.key'), clientCa: f('goodca.pem') } });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as any).port;
  const get = (keyId: string, secret: string, cert?: string) => new Promise<number>((resolve, reject) => {
    const ts = Date.now(), nonce = `nonce-${Math.random().toString(36).slice(2)}`;
    const r = https.request({ host: '127.0.0.1', port, path: '/state', method: 'GET', ca: f('srv.pem'), servername: 'localhost',
      ...(cert ? { cert: f(`${cert}.pem`), key: f(`${cert}.key`) } : {}),
      headers: { 'x-key-id': keyId, 'x-ts': String(ts), 'x-nonce': nonce, 'x-sig': signRequest(secret, ts, nonce, 'GET /state', '') } },
      (res) => { res.resume(); resolve(res.statusCode ?? 0); });
    r.on('error', reject); r.end();
  });
  try {
    assert.equal(await get('owner', OWN, 'owner-goodca'), 200);
    assert.equal(await get('owner', OWN, 'sec-goodca'), 401); // valid cert + valid HMAC, but the certificate belongs to someone else
    await assert.rejects(get('owner', OWN)); // no client certificate
    await assert.rejects(get('owner', OWN, 'owner-rogueca')); // certificate from an untrusted CA
  } finally { server.close(); }
});
