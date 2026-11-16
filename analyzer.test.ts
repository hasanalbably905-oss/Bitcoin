import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { redactForExternal, assertSafeBaseUrl, OpenAICompatAnalyzer, createAnalyzerFromEnv } from '../src/index.ts';
import type { Incident, SecurityEvent } from '../src/index.ts';

const inc: Incident = { id: 'inc_1', createdAt: 0, severity: 'critical', status: 'open', lastNotifiedAt: 0, notifyCount: 0, findings: [
  { ruleId: 'bruteforce', severity: 'critical', key: 'k', eventIds: ['e1'], title: 'هجوم من 203.0.113.9', detail: 'token sk_live_' + 'a'.repeat(40) + ' admin@example.com' }] };
const events: SecurityEvent[] = [{ id: 'e1', ts: 0, source: 'api', type: 'auth.failed', ip: '203.0.113.9' }];

async function fakeGateway(handler: (req: any, body: string, res: any) => void) {
  const server = createServer((req, res) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => handler(req, b, res)); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return { server, url: `http://127.0.0.1:${(server.address() as any).port}/v1` };
}

test('redaction masks IPs, emails, bitcoin addresses and long secrets but keeps normal text', () => {
  const out = redactForExternal('from 203.0.113.9 to bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 by a@b.co key ' + 'x'.repeat(40) + ' failed 10 times');
  assert.ok(!/203\.0\.113|bc1q|a@b\.co|xxxxxxxx/.test(out));
  assert.match(out, /failed 10 times/);
});

test('base URL must be https, or http on localhost only, without embedded credentials', () => {
  assert.doesNotThrow(() => assertSafeBaseUrl('https://gateway.example.com/v1'));
  assert.doesNotThrow(() => assertSafeBaseUrl('http://localhost:20128/v1'));
  assert.doesNotThrow(() => assertSafeBaseUrl('http://127.0.0.1:20128/v1'));
  assert.throws(() => assertSafeBaseUrl('http://gateway.example.com/v1'), /https/);
  assert.throws(() => assertSafeBaseUrl('https://user:pw@gateway.example.com'), /credentials/);
  assert.throws(() => assertSafeBaseUrl('not a url'), /invalid/);
});

test('OpenAI-compatible gateway: correct request, key sent, and no raw identifiers leave the system', async () => {
  let seen: { url?: string; auth?: string; body?: string } = {};
  const gw = await fakeGateway((req, body, res) => {
    seen = { url: req.url, auth: req.headers.authorization, body };
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ choices: [{ message: { content: 'ملخص آمن' } }] }));
  });
  try {
    const a = new OpenAICompatAnalyzer({ baseUrl: gw.url, apiKey: 'gw-key', model: 'auto' });
    assert.equal(await a.summarize(inc, events), 'ملخص آمن');
    assert.equal(seen.url, '/v1/chat/completions');
    assert.equal(seen.auth, 'Bearer gw-key');
    assert.ok(!/203\.0\.113\.9|admin@example\.com|sk_live_/.test(seen.body!));
    assert.ok(!seen.body!.includes('"events"')); // raw events are not sent to third parties
    assert.match(seen.body!, /incident_data/);
  } finally { gw.server.close(); }
});

test('redirects are refused so the API key cannot be forwarded elsewhere', async () => {
  const gw = await fakeGateway((_r, _b, res) => { res.writeHead(302, { location: 'http://127.0.0.1:1/steal' }); res.end(); });
  try { await assert.rejects(new OpenAICompatAnalyzer({ baseUrl: gw.url, apiKey: 'k', model: 'm' }).summarize(inc, events)); }
  finally { gw.server.close(); }
});

test('gateway errors and empty answers raise (the Guardian ignores them; alerts are unaffected)', async () => {
  const bad = await fakeGateway((_r, _b, res) => { res.writeHead(500); res.end('boom'); });
  const empty = await fakeGateway((_r, _b, res) => { res.writeHead(200); res.end(JSON.stringify({ choices: [{ message: { content: '  ' } }] })); });
  try {
    await assert.rejects(new OpenAICompatAnalyzer({ baseUrl: bad.url, apiKey: 'k', model: 'm' }).summarize(inc, events), /500/);
    await assert.rejects(new OpenAICompatAnalyzer({ baseUrl: empty.url, apiKey: 'k', model: 'm' }).summarize(inc, events), /empty/);
  } finally { bad.server.close(); empty.server.close(); }
});

test('model output is capped in length', async () => {
  const gw = await fakeGateway((_r, _b, res) => { res.writeHead(200); res.end(JSON.stringify({ choices: [{ message: { content: 'x'.repeat(10_000) } }] })); });
  try { assert.equal((await new OpenAICompatAnalyzer({ baseUrl: gw.url, apiKey: 'k', model: 'm' }).summarize(inc, events)).length, 1500); }
  finally { gw.server.close(); }
});

test('env factory: none without key, strict about required settings', async () => {
  assert.equal(await createAnalyzerFromEnv({}), undefined);
  await assert.rejects(createAnalyzerFromEnv({ ANALYZER_PROVIDER: 'openai-compatible', ANALYZER_API_KEY: 'k' }), /required/);
  await assert.rejects(createAnalyzerFromEnv({ ANALYZER_PROVIDER: 'nope', ANALYZER_API_KEY: 'k' }), /unknown/);
  await assert.rejects(createAnalyzerFromEnv({ ANALYZER_PROVIDER: 'openai-compatible', ANALYZER_API_KEY: 'k', ANALYZER_BASE_URL: 'http://evil.example.com/v1', ANALYZER_MODEL: 'm' }), /https/);
  assert.ok(await createAnalyzerFromEnv({ ANALYZER_PROVIDER: 'openai-compatible', ANALYZER_API_KEY: 'k', ANALYZER_BASE_URL: 'http://localhost:20128/v1', ANALYZER_MODEL: 'auto' }));
});
