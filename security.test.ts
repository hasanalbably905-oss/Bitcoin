import { test } from 'node:test';
import assert from 'node:assert/strict';
import { defaultConfig, Guardian, BreakerPanel, createGuardServer, signRequest } from '../src/index.ts';
import type { AuditEntry } from '../src/index.ts';

const SRC = 's'.repeat(32), OWN = 'o'.repeat(32);
const people = [{ id: 'owner', role: 'owner' as const }];

async function boot(over: object = {}, panelAudit?: (e: AuditEntry) => void, registerDevice?: any) {
  const g = new Guardian({ config: defaultConfig(), notifier: { async send() {} } });
  const panel = new BreakerPanel(people, { async apply() {} }, undefined, undefined, panelAudit);
  const logged: unknown[] = [];
  const server = createGuardServer({ guardian: g, panel, sourceKeys: { api: SRC }, approverKeys: { owner: OWN }, registerDevice, log: (e) => logged.push(e), ...over });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as any).port;
  const call = async (method: string, path: string, key: string, secret: string, body: string, extra: Record<string, string> = {}) => {
    const ts = Date.now(), nonce = `n-${Math.random().toString(36).slice(2)}-${ts}`;
    const res = await fetch(`http://127.0.0.1:${port}${path}`, { method, body: method === 'GET' ? undefined : body,
      headers: { 'x-key-id': key, 'x-ts': String(ts), 'x-nonce': nonce, 'x-sig': signRequest(secret, ts, nonce, `${method} ${path}`, body), ...extra } });
    return { status: res.status, headers: res.headers, json: await res.json() as any };
  };
  return { g, server, call, logged };
}

test('plain HTTP is refused by default (426) and accepted behind a trusted TLS proxy', async () => {
  const a = await boot();
  try { assert.equal((await a.call('GET', '/state', 'owner', OWN, '')).status, 426); } finally { a.server.close(); }
  const b = await boot({ trustProxy: true });
  try { assert.equal((await b.call('GET', '/state', 'owner', OWN, '', { 'x-forwarded-proto': 'https' })).status, 200); } finally { b.server.close(); }
});

test('responses carry security headers', async () => {
  const { server, call } = await boot({ requireHttps: false });
  try {
    const r = await call('GET', '/state', 'owner', OWN, '');
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(r.headers.get('cache-control'), 'no-store');
    assert.match(r.headers.get('strict-transport-security') ?? '', /max-age/);
    assert.match(r.headers.get('content-security-policy') ?? '', /default-src 'none'/);
  } finally { server.close(); }
});

test('repeated bad signatures get the caller blocked (429)', async () => {
  const { server, call } = await boot({ requireHttps: false });
  try {
    const codes: number[] = [];
    for (let i = 0; i < 14; i++) codes.push((await call('GET', '/state', 'owner', 'w'.repeat(32), '')).status);
    assert.equal(codes[0], 401);
    assert.ok(codes.includes(429));
    assert.equal((await call('GET', '/state', 'owner', OWN, '')).status, 429); // even a valid request is held back
  } finally { server.close(); }
});

test('errors never leak internals; bad input gets a clean 400', async () => {
  const { server, call, logged } = await boot({ requireHttps: false }, undefined, async () => { throw new Error('db password=hunter2'); });
  try {
    const bad = await call('POST', '/actions', 'owner', OWN, '{not json');
    assert.deepEqual([bad.status, bad.json.error], [400, 'invalid_json']);
    const inj = await call('POST', '/actions', 'owner', OWN, JSON.stringify({ op: 'propose', name: 'DROP TABLE', frozen: true }));
    assert.equal(inj.json.error, 'invalid_action');
    const dev = await call('POST', '/devices', 'owner', OWN, JSON.stringify({ token: 'has spaces <script>' }));
    assert.equal(dev.json.error, 'invalid_token');
    const boom = await call('POST', '/devices', 'owner', OWN, JSON.stringify({ token: 'abc:DEF_123' }));
    assert.deepEqual([boom.status, boom.json.error], [500, 'internal_error']);
    assert.ok(!JSON.stringify(boom.json).includes('hunter2'));
    assert.equal(logged.length, 1); // detail stays server-side
  } finally { server.close(); }
});

test('weak secrets are refused at startup', () => {
  const g = new Guardian({ config: defaultConfig(), notifier: { async send() {} } });
  const panel = new BreakerPanel(people, { async apply() {} });
  assert.throws(() => createGuardServer({ guardian: g, panel, sourceKeys: { api: 'short' }, approverKeys: { owner: OWN } }), /at least 32/);
});

test('memory stays bounded under a flood of distinct attacker-chosen keys', async () => {
  const g = new Guardian({ config: defaultConfig(), notifier: { async send() {} } });
  for (let i = 0; i < 1200; i++) await g.ingest({ source: 'api', type: 'secret.leaked', data: { name: `k${i}` } });
  assert.ok(g.incidents.size <= 1000);
});

test('every breaker attempt is audited, including rejected ones', async () => {
  const log: AuditEntry[] = [];
  const p = new BreakerPanel(people, { async apply() {} }, undefined, undefined, (e) => log.push(e));
  await assert.rejects(p.propose('mallory', 'SENDS', true));
  await p.propose('owner', 'SENDS', true);
  assert.deepEqual(log.map((e) => e.action), ['rejected', 'propose', 'applied']);
  assert.equal(log[0]?.by, 'mallory');
});
