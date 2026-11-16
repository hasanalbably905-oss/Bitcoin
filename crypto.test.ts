import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, readdir, rename, stat, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import https from 'node:https';
import { Keyring, seal, open, EncryptedFileStore, EncryptedDeviceStore, AuditLog, readSecret, requireSecret,
  Guardian, BreakerPanel, createGuardServer, defaultConfig, signRequest } from '../src/index.ts';

const K1 = 'a1'.repeat(32), K2 = 'b2'.repeat(32);
const ring1 = () => new Keyring({ k1: K1 }, 'k1');
const tmp = () => mkdtemp(join(tmpdir(), 'gd-'));

test('seal/open round-trips and rejects wrong key, wrong context and tampering', () => {
  const r = ring1(); const s = seal(r, 'سر الحالة', 'ctx');
  assert.equal(open(r, s, 'ctx').toString(), 'سر الحالة');
  assert.ok(!s.includes('سر'));
  assert.throws(() => open(r, s, 'other'), /decryption failed/);
  assert.throws(() => open(new Keyring({ k1: K2 }, 'k1'), s, 'ctx'), /decryption failed/);
  const bad = s.slice(0, -3) + (s.endsWith('AAA') ? 'BBB' : 'AAA');
  assert.throws(() => open(r, bad, 'ctx'), /decryption failed/);
  assert.notEqual(seal(r, 'x', 'c'), seal(r, 'x', 'c')); // fresh IV every time
});

test('keyring rejects weak or malformed keys', () => {
  assert.throws(() => new Keyring({ k1: 'abc' }, 'k1'), /64 hex/);
  assert.throws(() => new Keyring({ k1: K1 }, 'nope'), /not in the keyring/);
});

test('encrypted store: no plaintext on disk, 0600 files, bound to file name, atomic', async () => {
  const dir = await tmp(); const st = new EncryptedFileStore(dir, ring1()); await st.init();
  await st.set('incidents', [{ id: 'inc_1', secretish: 'TOP-SECRET-VALUE' }]);
  assert.deepEqual(await st.get('incidents'), [{ id: 'inc_1', secretish: 'TOP-SECRET-VALUE' }]);
  assert.equal(await st.get('missing'), null);
  assert.ok(!(await readFile(join(dir, 'incidents.enc'), 'utf8')).includes('TOP-SECRET'));
  assert.equal((await stat(join(dir, 'incidents.enc'))).mode & 0o777, 0o600);
  assert.equal((await stat(dir)).mode & 0o777, 0o700);
  assert.ok(!(await readdir(dir)).some((f) => f.endsWith('.tmp')));
  await st.set('other', { a: 1 });
  await rename(join(dir, 'other.enc'), join(dir, 'swapped.enc')); // attacker swaps files
  await assert.rejects(st.get('swapped'), /decryption failed/);
  await assert.rejects(st.get('../etc/passwd'), /invalid store key/);
});

test('key rotation: old data stays readable, then re-encrypts so the old key can be dropped', async () => {
  const dir = await tmp();
  await new EncryptedFileStore(dir, ring1()).set('a', { v: 1 });
  const both = new Keyring({ k1: K1, k2: K2 }, 'k2');
  const st = new EncryptedFileStore(dir, both);
  assert.deepEqual(await st.get('a'), { v: 1 });
  assert.equal(await st.rotate(), 1);
  assert.deepEqual(await new EncryptedFileStore(dir, new Keyring({ k2: K2 }, 'k2')).get('a'), { v: 1 });
});

test('device tokens are encrypted at rest and survive restart', async () => {
  const dir = await tmp(); const st = new EncryptedFileStore(dir, ring1()); await st.init();
  const d = await EncryptedDeviceStore.open(st);
  await d.add('owner', 'fcm-token-abc:123');
  assert.ok(!(await readFile(join(dir, 'devices.enc'), 'utf8')).includes('fcm-token'));
  assert.deepEqual(await (await EncryptedDeviceStore.open(st)).list(), ['fcm-token-abc:123']);
  await d.remove('fcm-token-abc:123');
  assert.deepEqual(await (await EncryptedDeviceStore.open(st)).list(), []);
});

test('audit log: encrypted, chained, and any edit/delete/reorder is detected', async () => {
  const dir = await tmp(); const file = join(dir, 'audit.log'); const r = ring1();
  const log = new AuditLog(file, r); await log.init();
  await Promise.all([log.append({ a: 'CLEARTEXT-MARKER-1' }), log.append({ a: 2 }), log.append({ a: 3 })]);
  const head = log.head();
  assert.ok(!(await readFile(file, 'utf8')).includes('CLEARTEXT-MARKER'));
  assert.deepEqual(await AuditLog.verify(file, r), { ok: true, entries: 3, head });
  const lines = (await readFile(file, 'utf8')).split('\n').filter(Boolean);
  await writeFile(file, [lines[0], lines[2]].join('\n') + '\n'); // delete the middle line
  assert.equal((await AuditLog.verify(file, r)).ok, false);
  await writeFile(file, [lines[1], lines[0], lines[2]].join('\n') + '\n'); // reorder
  assert.equal((await AuditLog.verify(file, r)).ok, false);
  await assert.rejects(new AuditLog(file, r).init(), /tampered/); // refuses to start on a tampered log
  await writeFile(file, lines.join('\n') + '\n');
  const again = new AuditLog(file, r); await again.init(); // restart continues the same chain
  await again.append({ a: 4 });
  assert.equal((await AuditLog.verify(file, r)).entries, 4);
});

test('secrets can come from NAME_FILE', async () => {
  const dir = await tmp(); await writeFile(join(dir, 's'), '  from-file  \n');
  assert.equal(await readSecret({ X_FILE: join(dir, 's') }, 'X'), 'from-file');
  assert.equal(await readSecret({ X: ' plain ' }, 'X'), 'plain');
  await assert.rejects(requireSecret({}, 'X'), /missing secret/);
});

test('guardian snapshot/restore keeps incidents and continues numbering; hook errors never break alerting', async () => {
  const sent: string[] = [];
  const g = new Guardian({ config: defaultConfig(), notifier: { async send(i) { sent.push(i.id); } }, onIncident: () => { throw new Error('hook bug'); } });
  await g.ingest({ source: 'api', type: 'integrity.mismatch' });
  assert.equal(sent.length, 1);
  const g2 = new Guardian({ config: defaultConfig(), notifier: { async send(i) { sent.push(i.id); } } });
  g2.restore(JSON.parse(JSON.stringify(g.snapshot())));
  assert.equal(g2.incidents.size, 1);
  const next = await g2.ingest({ source: 'api', type: 'secret.leaked', data: { name: 'k' } });
  assert.equal(next?.id, 'inc_2');
});

function haveOpenssl() { try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); return true; } catch { return false; } }
test('TLS 1.3 is served directly and TLS 1.2 is refused', { skip: !haveOpenssl() }, async () => {
  const dir = await tmp();
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem'),
    '-subj', '/CN=localhost', '-days', '1', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], { stdio: 'ignore' });
  const cert = readFileSync(join(dir, 'c.pem')), key = readFileSync(join(dir, 'k.pem'));
  const OWN = 'o'.repeat(32);
  const g = new Guardian({ config: defaultConfig(), notifier: { async send() {} } });
  const server = createGuardServer({ guardian: g, panel: new BreakerPanel([{ id: 'owner', role: 'owner' }], { async apply() {} }),
    sourceKeys: { api: 's'.repeat(32) }, approverKeys: { owner: OWN }, tls: { cert, key } });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as any).port;
  const get = (maxVersion: 'TLSv1.2' | 'TLSv1.3') => new Promise<number>((resolve, reject) => {
    const ts = Date.now(), nonce = `nonce-${Math.random().toString(36).slice(2)}`;
    const r = https.request({ host: '127.0.0.1', port, path: '/state', method: 'GET', ca: cert, servername: 'localhost', maxVersion,
      headers: { 'x-key-id': 'owner', 'x-ts': String(ts), 'x-nonce': nonce, 'x-sig': signRequest(OWN, ts, nonce, 'GET /state', '') } },
      (res) => { res.resume(); resolve(res.statusCode ?? 0); });
    r.on('error', reject); r.end();
  });
  try {
    assert.equal(await get('TLSv1.3'), 200);
    await assert.rejects(get('TLSv1.2'));
  } finally { server.close(); }
});
