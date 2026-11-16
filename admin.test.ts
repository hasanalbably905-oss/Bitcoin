import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { webcrypto } from 'node:crypto';
import { Guardian, BreakerPanel, createGuardServer, defaultConfig, signRequest, Keyring, AuditLog } from '../src/index.ts';

const SRC = 's'.repeat(32), OWN = 'o'.repeat(32), SEC = 'c'.repeat(32);
const XSS = '<img src=x onerror=alert(1)>';
const ASSET = (f: string) => readFileSync(new URL(`../src/admin/${f}`, import.meta.url), 'utf8');

async function boot(over: object = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'ad-'));
  const audit = new AuditLog(join(dir, 'audit.log'), new Keyring({ k1: 'a1'.repeat(32) }, 'k1')); await audit.init();
  const g = new Guardian({ config: defaultConfig(), notifier: { async send() {} } });
  const panel = new BreakerPanel([{ id: 'owner', role: 'owner' }, { id: 'sec', role: 'security' }], { async apply() {} }, undefined, undefined, (e) => void audit.append(e));
  const server = createGuardServer({ guardian: g, panel, sourceKeys: { api: SRC }, approverKeys: { owner: OWN, sec: SEC },
    requireHttps: false, admin: true, auditTail: (n) => audit.tail(n), ...over });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return { g, panel, audit, server, base: `http://127.0.0.1:${(server.address() as any).port}` };
}

test('admin page is off by default and served with a strict CSP when enabled', async () => {
  const off = await boot({ admin: false });
  try {
    const r = await fetch(off.base + '/admin');
    assert.notEqual(r.status, 200); // falls through to the signed API: refused
    assert.ok(!(r.headers.get('content-type') ?? '').includes('html'));
  } finally { off.server.close(); }
  const on = await boot();
  try {
    const r = await fetch(on.base + '/admin');
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-type')!, /text\/html/);
    const csp = r.headers.get('content-security-policy')!;
    assert.match(csp, /script-src 'self'/); assert.match(csp, /default-src 'none'/); assert.match(csp, /frame-ancestors 'none'/);
    assert.ok(!/unsafe-inline|unsafe-eval/.test(csp));
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
    assert.equal((await fetch(on.base + '/admin/app.js')).headers.get('content-type'), 'text/javascript; charset=utf-8');
    assert.notEqual((await fetch(on.base + '/admin/other.js')).status, 200); // only the three known files are served
  } finally { on.server.close(); }
});

test('admin files contain no inline scripts, inline handlers or dangerous DOM sinks', () => {
  const html = ASSET('index.html'), js = ASSET('app.js');
  assert.ok(!/<script(?![^>]*\bsrc=)/i.test(html));
  assert.ok(!/\son\w+\s*=/i.test(html));
  assert.ok(!/<style/i.test(html) && !/style=/i.test(html));
  for (const bad of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'localStorage', 'sessionStorage', 'document.cookie'])
    assert.ok(!js.includes(bad), `app.js must not use ${bad}`);
});

test('IP allow-list protects the admin page and human endpoints but not service ingestion', async () => {
  const b = await boot({ approverIps: ['10.0.0.1'] });
  try {
    assert.equal((await fetch(b.base + '/admin')).status, 403);
    assert.equal((await fetch(b.base + '/state')).status, 403);
    const body = JSON.stringify({ source: 'api', type: 'integrity.mismatch' });
    const ts = Date.now(), nonce = 'nonce-ingest-1';
    const r = await fetch(b.base + '/ingest', { method: 'POST', body, headers: { 'x-key-id': 'api', 'x-ts': String(ts), 'x-nonce': nonce, 'x-sig': signRequest(SRC, ts, nonce, 'POST /ingest', body) } });
    assert.equal(r.status, 200);
  } finally { b.server.close(); }
});

// Runs the real app.js against the real server with a stub DOM.
function runAdmin(base: string) {
  const els: Record<string, any> = {};
  const mk = (): any => ({ children: [], listeners: {} as Record<string, Function[]>, attrs: {} as Record<string, string>, hidden: false, value: '', textContent: '', className: '',
    appendChild(c: any) { this.children.push(c); return c; }, append(...c: any[]) { this.children.push(...c); }, replaceChildren(...c: any[]) { this.children = c; },
    addEventListener(t: string, f: Function) { (this.listeners[t] ||= []).push(f); }, setAttribute(k: string, v: string) { this.attrs[k] = v; } });
  const document = { getElementById: (id: string) => (els[id] ??= mk()), createElement: () => mk(), addEventListener() {} };
  const ctx: any = { document, crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob, Uint8Array, Array, Date, JSON, Promise, Error, String,
    fetch: (p: string, o: any) => fetch(base + p, o), setInterval: () => 1, clearInterval() {}, setTimeout: () => 1, clearTimeout() {},
    confirm: () => true, prompt: () => 'STOP' };
  vm.runInNewContext(ASSET('app.js'), ctx);
  const all = (n: any, out: any[] = []): any[] => { out.push(n); (n.children || []).forEach((c: any) => all(c, out)); return out; };
  const text = () => ['breakers', 'pending', 'incidents', 'audit'].flatMap((id) => all(els[id]).map((n) => n.textContent)).join('\n');
  const button = (action: string) => ['breakers', 'pending', 'incidents'].flatMap((id) => all(els[id])).find((n) => n.attrs['data-action'] === action);
  const login = async (id: string, secret: string) => { document.getElementById('key-id').value = id; document.getElementById('secret').value = secret; await els['login-btn'].listeners.click[0](); };
  const el = (id: string) => document.getElementById(id);
  return { els, el, text, button, login };
}

test('the real admin page logs in, shows data as plain text, freezes, and two people can stop the service', async () => {
  const b = await boot();
  try {
    await b.g.ingest({ source: 'api', type: 'integrity.mismatch', data: { what: XSS } });
    const a = runAdmin(b.base);

    await a.login('owner', 'x'.repeat(32)); // wrong key
    assert.match(a.els['msg'].textContent, /غير صحيح/);
    assert.notEqual(a.el('login').hidden, true); // still on the login screen

    await a.login('owner', OWN);
    assert.equal(a.els['app'].hidden, false);
    assert.equal(a.els['login'].hidden, true);
    assert.equal(a.els['secret'].value, ''); // secret cleared from the field
    assert.equal(a.els['breakers'].children.length, 3);
    assert.ok(a.text().includes(XSS)); // attacker-controlled text is only ever shown as text

    await a.button('freeze:SENDS').listeners.click[0]();
    assert.equal(b.panel.state.SENDS, true);
    assert.ok(a.text().includes('مجمّد'));

    await a.button('freeze:SERVICE').listeners.click[0](); // owner proposes (prompt returns STOP)
    assert.equal(b.panel.state.SERVICE, false);
    assert.ok(a.text().includes('الموافقات 1 من 2'));
    assert.equal(a.button(`approve:${b.panel.pending()[0]!.id}`), undefined); // the proposer cannot approve twice

    const sec = runAdmin(b.base); await sec.login('sec', SEC);
    await sec.button(`approve:${b.panel.pending()[0]!.id}`).listeners.click[0]();
    assert.equal(b.panel.state.SERVICE, true);

    await b.audit.append({ marker: 'last' });
    assert.ok((await b.audit.tail(50)).length >= 3);
    assert.ok(a.text().length > 0);
  } finally { b.server.close(); }
});
