import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFrozenGuard, FrozenError, FlagStore, Keyring, GuardianReporter, Guardian, BreakerPanel, createGuardServer, defaultConfig } from '../src/index.ts';

const GOOD = 'g'.repeat(32);
test('verified flags are required; sealed flag store blocks and missing/corrupt flags fail closed', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'g-'));
  const seq = new Map<string, number>();
  const anchor = { async get(n: string) { return seq.get(n) ?? 0; }, async advance(n: string, e: number, v: number) { if ((seq.get(n) ?? 0) !== e) return false; seq.set(n, v); return true; } };
  const flags = new FlagStore(dir, new Keyring({ f: 'ff'.repeat(32) }, 'f'), anchor); await flags.init();
  const g = createFrozenGuard(flags);
  assert.equal(await g.isFrozen('SENDS'), false);
  await flags.write('SENDS', true);
  assert.equal(await g.isFrozen('SENDS'), true);
  await assert.rejects(async () => createFrozenGuard(dir as any), /verified FlagStore/);
  await assert.rejects(g.assertNotFrozen('SENDS'), FrozenError);
});

test('middleware answers 503 when verified freeze flag is set', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'g-'));
  const seq = new Map<string, number>();
  const anchor = { async get(n: string) { return seq.get(n) ?? 0; }, async advance(n: string, e: number, v: number) { if ((seq.get(n) ?? 0) !== e) return false; seq.set(n, v); return true; } };
  const flags = new FlagStore(dir, new Keyring({ f: 'ff'.repeat(32) }, 'f'), anchor); await flags.init();
  const mw = createFrozenGuard(flags).middleware('SENDS');
  let called = 0; const out: any = { headers: {}, setHeader() {}, end(b: string) { this.body = b; } };
  await mw({}, out, () => { called++; }); assert.equal(called, 1);
  await flags.write('SENDS', true);
  await mw({}, out, () => { called++; });
  assert.equal(called, 1); assert.equal(out.statusCode, 503);
});

test('reporter sends signed events the server accepts; bad secret is refused', async () => {
  const seen: string[] = [];
  const g = new Guardian({ config: defaultConfig(), notifier: { async send(i) { seen.push(i.id); } } });
  const panel = new BreakerPanel([{ id: 'owner', role: 'owner' }], { async apply() {} });
  const server = createGuardServer({ guardian: g, panel, sourceKeys: { api: GOOD }, approverKeys: { owner: 'x'.repeat(32) }, requireHttps: false });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${(server.address() as any).port}`;
  try {
    await new GuardianReporter({ url, keyId: 'api', secret: GOOD }).report('api', 'integrity.mismatch', { what: 'address differs' });
    assert.equal(seen.length, 1);
    await assert.rejects(new GuardianReporter({ url, keyId: 'api', secret: 'b'.repeat(32) }).report('api', 'integrity.mismatch'), /401/);
    new GuardianReporter({ url: 'http://127.0.0.1:1', keyId: 'api', secret: GOOD }).emit('api', 'x.y'); // must not throw
  } finally { server.close(); }
});
