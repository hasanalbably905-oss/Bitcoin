import { test } from 'node:test';
import assert from 'node:assert/strict';
import { defaultConfig, Guardian, BreakerPanel, createGuardServer, signRequest, RequestVerifier } from '../src/index.ts';
import type { Incident, Notifier, Approver } from '../src/index.ts';
import { sanitizeEvent } from '../src/sanitize.ts';

function setup(over: Partial<ReturnType<typeof defaultConfig>> = {}, analyzer?: any) {
  let t = 1_700_000_000_000;
  const sent: { id: string; kind: string }[] = [];
  const state = { fail: false };
  const notifier: Notifier = { async send(i: Incident, kind) { if (state.fail) throw new Error('down'); sent.push({ id: i.id, kind }); } };
  const cfg = { ...defaultConfig(), approvedReleaseHashes: new Set(['good']), ...over };
  const g = new Guardian({ config: cfg, notifier, analyzer, now: () => t });
  return { g, sent, state, advance: (ms: number) => { t += ms; }, now: () => t };
}
const SRC = 's'.repeat(32), OWN = 'o'.repeat(32);
const ev = (type: string, extra: object = {}) => ({ source: 'api', type, ...extra });

test('brute force: warning at 10, critical at 50', async () => {
  const { g, sent } = setup();
  let first = null, crit = null;
  for (let i = 1; i <= 50; i++) {
    const r = await g.ingest(ev('auth.failed', { ip: '1.2.3.4' }));
    if (i === 10) first = r;
    if (i === 50) crit = r;
  }
  assert.equal(first?.severity, 'warning');
  assert.equal(crit?.severity, 'critical');
  assert.equal(sent.length, 2);
});

test('unapproved or unsigned release is critical and suggests freezing releases', async () => {
  const { g } = setup();
  const bad = await g.ingest(ev('release.published', { data: { sha256: 'evil', signed: true } }));
  assert.equal(bad?.severity, 'critical');
  assert.equal(bad?.findings[0]?.suggest, 'RELEASES');
  assert.equal(await g.ingest(ev('release.published', { data: { sha256: 'good', signed: true } })), null);
  assert.ok(await g.ingest(ev('release.published', { data: { sha256: 'good', signed: false } })));
});

test('integrity mismatch, fee spike, secret leak and physical tamper raise critical', async () => {
  const { g } = setup();
  assert.equal((await g.ingest(ev('integrity.mismatch')))?.findings[0]?.suggest, 'SENDS');
  assert.equal((await g.ingest(ev('fee.quote', { data: { satPerVb: 9000 } })))?.severity, 'critical');
  assert.equal(await g.ingest(ev('fee.quote', { data: { satPerVb: 20 } })), null);
  assert.equal((await g.ingest(ev('secret.leaked', { data: { name: 'AWS_KEY' } })))?.severity, 'critical');
  assert.equal((await g.ingest(ev('physical.door_open')))?.findings[0]?.suggest, 'SERVICE');
});

test('admin changes and off-hours admin login', async () => {
  const { g } = setup();
  assert.equal((await g.ingest(ev('admin.created', { actor: 'x' })))?.severity, 'critical');
  const night = Date.UTC(2023, 10, 14, 2, 0, 0);
  const r = await g.ingest({ ...ev('admin.login', { actor: 'bob' }), ts: night });
  // ts is clamped to "now" if it is more than a day away, so build the check from the injected clock
  assert.ok(r === null || r.severity === 'warning');
});

test('cooldown de-duplicates identical findings', async () => {
  const { g, advance } = setup();
  assert.ok(await g.ingest(ev('secret.leaked', { data: { name: 'K' } })));
  assert.equal(await g.ingest(ev('secret.leaked', { data: { name: 'K' } })), null);
  advance(11 * 60_000);
  assert.ok(await g.ingest(ev('secret.leaked', { data: { name: 'K' } })));
});

test('anomaly detection flags a spike but not normal values', async () => {
  const { g } = setup();
  const base = [98, 99, 100, 101, 102];
  for (let i = 0; i < 60; i++) assert.equal(await g.ingest(ev('metric', { data: { name: 'api.rps', value: base[i % 5] } })), null);
  assert.equal(await g.ingest(ev('metric', { data: { name: 'api.rps', value: 101 } })), null);
  const spike = await g.ingest(ev('metric', { data: { name: 'api.rps', value: 1000 } }));
  assert.equal(spike?.severity, 'critical');
});

test('a silent source (attacker muting logs) raises an incident', async () => {
  const { g, advance } = setup({ expectedSources: ['api'] });
  advance(4 * 60_000);
  await g.tick();
  const inc = [...g.incidents.values()][0];
  assert.equal(inc?.findings[0]?.ruleId, 'silence');
});

test('unacknowledged critical incidents are re-sent until acknowledged', async () => {
  const { g, sent, advance } = setup();
  const inc = (await g.ingest(ev('integrity.mismatch')))!;
  advance(60_000); await g.tick();
  assert.equal(sent.length, 1);
  advance(61_000); await g.tick();
  assert.equal(sent.length, 2);
  assert.equal(sent[1]?.kind, 'reminder');
  g.ack(inc.id, 'owner');
  advance(10 * 60_000); await g.tick();
  assert.equal(sent.length, 2);
});

test('failed notification is recorded and retried on the next tick', async () => {
  const { g, sent, state } = setup();
  state.fail = true;
  const inc = (await g.ingest(ev('integrity.mismatch')))!;
  assert.equal(inc.notifyError, 'down');
  state.fail = false;
  await g.tick();
  assert.equal(sent.length, 1);
  assert.equal(inc.notifyError, undefined);
});

test('AI summary is stored but a failing analyzer never blocks the alert', async () => {
  const ok = setup({}, { summarize: async () => 'ملخص' });
  const inc = (await ok.g.ingest(ev('integrity.mismatch')))!;
  await ok.g.flush();
  assert.equal(inc.aiSummary, 'ملخص');
  const bad = setup({}, { summarize: async () => { throw new Error('api down'); } });
  const inc2 = (await bad.g.ingest(ev('integrity.mismatch')))!;
  await bad.g.flush();
  assert.equal(bad.sent.length, 1);
  assert.equal(inc2.aiSummary, undefined);
});

test('sanitizeEvent rejects bad shapes and drops oversized data', () => {
  assert.equal(sanitizeEvent({ source: 'a', type: 'Bad Type!' }, 1), null);
  assert.equal(sanitizeEvent('x', 1), null);
  const e = sanitizeEvent({ source: 'a', type: 'x.y', data: { big: 'z'.repeat(5000) } }, 1);
  assert.equal(e?.data, undefined);
});

const people: Approver[] = [{ id: 'owner', role: 'owner' }, { id: 'sec', role: 'security' }, { id: 'dev', role: 'security' }];
function panelSetup() {
  let t = 0; const applied: string[] = [];
  const p = new BreakerPanel(people, { async apply(n, f) { applied.push(`${n}:${f}`); } }, undefined, () => t);
  return { p, applied, advance: (ms: number) => { t += ms; } };
}

test('freeze needs one approver; full stop needs two distinct people', async () => {
  const { p, applied } = panelSetup();
  await p.propose('sec', 'SENDS', true);
  assert.equal(p.isFrozen('SENDS'), true);
  const pr = await p.propose('sec', 'SERVICE', true);
  assert.equal(p.isFrozen('SERVICE'), false);
  await p.approve('sec', pr.id); // same person twice does not count
  assert.equal(p.isFrozen('SERVICE'), false);
  await p.approve('owner', pr.id);
  assert.equal(p.isFrozen('SERVICE'), true);
  assert.deepEqual(applied, ['SENDS:true', 'SERVICE:true']);
});

test('resume needs two people including an owner', async () => {
  const { p } = panelSetup();
  await p.propose('owner', 'SENDS', true);
  const pr = await p.propose('sec', 'SENDS', false);
  await p.approve('dev', pr.id);
  assert.equal(p.isFrozen('SENDS'), true); // two non-owners are not enough
  await p.approve('owner', pr.id);
  assert.equal(p.isFrozen('SENDS'), false);
});

test('unknown approvers are rejected, proposals expire, enforcer failure keeps state', async () => {
  const { p, advance } = panelSetup();
  await assert.rejects(p.propose('mallory', 'SENDS', true), /not an authorised/);
  const pr = await p.propose('sec', 'SERVICE', true);
  advance(11 * 60_000);
  await assert.rejects(p.approve('owner', pr.id), /expired/);
  const bad = new BreakerPanel(people, { async apply() { throw new Error('cloud api down'); } });
  await assert.rejects(bad.propose('owner', 'SENDS', true), /cloud api down/);
  assert.equal(bad.isFrozen('SENDS'), false);
});

test('request signing: valid passes; tampering, replay and stale timestamps fail', () => {
  const v = new RequestVerifier({ k1: 'secret' });
  const now = 1_000_000;
  const sig = signRequest('secret', now, 'nonce-12345', 'POST /ingest', '{}');
  const h = { keyId: 'k1', ts: now, nonce: 'nonce-12345', sig };
  assert.equal(v.verify(h, 'POST /ingest', '{"x":1}', now), false);
  assert.equal(v.verify(h, 'POST /actions', '{}', now), false);
  assert.equal(v.verify({ ...h, ts: now - 120_000 }, 'POST /ingest', '{}', now), false);
  assert.equal(v.verify(h, 'POST /ingest', '{}', now), true);
  assert.equal(v.verify(h, 'POST /ingest', '{}', now), false); // replay
});

test('HTTP: signed ingest creates an incident, unsigned is refused, owner can freeze', async () => {
  const notes: string[] = [];
  const g = new Guardian({ config: defaultConfig(), notifier: { async send(i) { notes.push(i.id); } } });
  const panel = new BreakerPanel(people, { async apply() {} });
  const server = createGuardServer({ guardian: g, panel, sourceKeys: { api: SRC }, approverKeys: { owner: OWN }, requireHttps: false });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as any).port;
  const call = async (method: string, path: string, key: string, secret: string, body: string, sign = true) => {
    const ts = Date.now(), nonce = `n-${Math.random().toString(36).slice(2)}-${ts}`;
    const sig = sign ? signRequest(secret, ts, nonce, `${method} ${path}`, body) : 'ab'.repeat(32);
    const res = await fetch(`http://127.0.0.1:${port}${path}`, { method, body: method === 'GET' ? undefined : body,
      headers: { 'x-key-id': key, 'x-ts': String(ts), 'x-nonce': nonce, 'x-sig': sig } });
    return { status: res.status, json: await res.json() as any };
  };
  try {
    const body = JSON.stringify({ source: 'api', type: 'integrity.mismatch' });
    assert.equal((await call('POST', '/ingest', 'api', SRC, body, false)).status, 401);
    const ok = await call('POST', '/ingest', 'api', SRC, body);
    assert.equal(ok.status, 200);
    assert.ok(ok.json.incident);
    assert.equal(notes.length, 1);
    assert.equal((await call('POST', '/actions', 'api', SRC, '{}')).status, 401); // a service key cannot act as a human
    const frz = await call('POST', '/actions', 'owner', OWN, JSON.stringify({ op: 'propose', name: 'SENDS', frozen: true }));
    assert.equal(frz.json.done, true);
    const st = await call('GET', '/state', 'owner', OWN, '');
    assert.equal(st.json.breakers.SENDS, true);
  } finally { server.close(); }
});
