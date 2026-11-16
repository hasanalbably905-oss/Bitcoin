import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import type { Server as HttpsServer } from 'node:https';
import type { TLSSocket } from 'node:tls';
import { e2eOpen, e2eSeal } from './e2e.ts';
import type { Guardian } from './guardian.ts';
import type { BreakerPanel } from './breakers.ts';
import type { BreakerName } from './types.ts';
import { RequestVerifier } from './auth.ts';
import { RateLimiter } from './ratelimit.ts';
import { ADMIN_HEADERS, ADMIN_ROUTES } from './admin-assets.ts';

export interface ServerDeps {
  guardian: Guardian; panel: BreakerPanel;
  sourceKeys: Record<string, string>; // services that report events
  approverKeys: Record<string, string>; // humans (owner, security lead)
  registerDevice?: (approverId: string, token: string) => Promise<void>;
  now?: () => number;
  requireHttps?: boolean; // default true: refuse plain HTTP
  trustProxy?: boolean; // default false: only then trust X-Forwarded-For / X-Forwarded-Proto from your reverse proxy
  log?: (e: unknown) => void; // server-side error log (never sent to clients)
  /** Serve HTTPS directly (TLS 1.3 only). With `clientCa`, mutual TLS: every client needs a certificate signed by that CA whose CN equals its key id. */
  tls?: { cert: string | Buffer; key: string | Buffer; clientCa?: string | Buffer };
  encryptBodies?: boolean; // require end-to-end encrypted envelopes (x-enc: 1) from every client
  admin?: boolean; // serve the admin web page at /admin (default off)
  approverIps?: string[]; // if set, admin page and every human endpoint only answer these IPs
  auditTail?: (n: number) => Promise<unknown[]>;
}

const MIN_SECRET = 32;
const BREAKERS: string[] = ['SENDS', 'RELEASES', 'SERVICE'];
// Only these messages are shown to clients; everything else becomes a generic error.
const SAFE = new Set(['not an authorised approver', 'unknown breaker', 'already in that state', 'no such open proposal', 'proposal expired']);
const HEADERS = {
  'content-type': 'application/json',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
  'strict-transport-security': 'max-age=63072000; includeSubDomains',
};
const isStr = (v: unknown, max: number): v is string => typeof v === 'string' && v.length > 0 && v.length <= max;

class BadRequest extends Error {}

function readBody(req: IncomingMessage, max: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => { size += c.length; if (size > max) { reject(new BadRequest('body_too_large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function clientIp(req: IncomingMessage, trustProxy: boolean): string {
  if (trustProxy) {
    const xff = String(req.headers['x-forwarded-for'] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    if (xff.length) return xff[xff.length - 1]!; // rightmost = appended by YOUR proxy; earlier values are client-controlled
  }
  return req.socket.remoteAddress ?? 'unknown';
}

function isHttps(req: IncomingMessage, trustProxy: boolean): boolean {
  if ((req.socket as { encrypted?: boolean }).encrypted) return true;
  return trustProxy && String(req.headers['x-forwarded-proto'] ?? '') === 'https';
}

export function createGuardServer(d: ServerDeps): Server | HttpsServer {
  for (const [k, s] of [...Object.entries(d.sourceKeys), ...Object.entries(d.approverKeys)])
    if (typeof s !== 'string' || s.length < MIN_SECRET) throw new Error(`secret for "${k}" must be at least ${MIN_SECRET} characters`);
  const sources = new RequestVerifier(d.sourceKeys);
  const approvers = new RequestVerifier(d.approverKeys);
  const perIp = new RateLimiter(120, 2); // burst 120, then 2 req/s per IP
  const perKey = new RateLimiter(300, 5); // a single key cannot flood the system
  const authFails = new RateLimiter(10, 1 / 30); // 10 bad signatures, then blocked ~30s per extra try
  const requireHttps = d.requireHttps ?? true;
  const trust = d.trustProxy === true;

  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    let enc: { key: Buffer; route: string; nonce: string } | undefined;
    const send = (code: number, body: unknown) => {
      res.writeHead(code, HEADERS);
      res.end(JSON.stringify(enc ? { enc: e2eSeal(enc.key, JSON.stringify(body), `res|${enc.route}|${enc.nonce}`) } : body));
    };
    const now = (d.now ?? Date.now)();
    try {
      if (requireHttps && !isHttps(req, trust)) return send(426, { error: 'https_required' });
      const ip = clientIp(req, trust);
      if (authFails.peek(ip, now) < 1 || !perIp.allow(ip, now)) return send(429, { error: 'too_many_requests' });

      const path = (req.url ?? '').split('?')[0]!;
      if (d.admin && req.method === 'GET' && ADMIN_ROUTES[path]) {
        if (d.approverIps && !d.approverIps.includes(ip)) return send(403, { error: 'forbidden' });
        res.writeHead(200, { ...ADMIN_HEADERS, 'content-type': ADMIN_ROUTES[path]!.type });
        return res.end(ADMIN_ROUTES[path]!.body);
      }
      const body = await readBody(req, 65_536);
      const h = (n: string) => String(req.headers[n] ?? '');
      const hdr = { keyId: h('x-key-id').slice(0, 64), ts: Number(h('x-ts')), nonce: h('x-nonce'), sig: h('x-sig') };
      const route = `${req.method} ${(req.url ?? '').split('?')[0]}`;
      const ingest = route === 'POST /ingest';
      if (!ingest && d.approverIps && !d.approverIps.includes(ip)) return send(403, { error: 'forbidden' });
      if (d.tls?.clientCa) { // mutual TLS: the certificate must be CA-signed and its CN must match the key id claimed
        const peer = (req.socket as TLSSocket).getPeerCertificate();
        if (!(req.socket as TLSSocket).authorized || !peer || peer.subject?.CN !== hdr.keyId) { authFails.allow(ip, now); return send(401, { error: 'unauthorized' }); }
      }

      const verifier = ingest ? sources : approvers;
      if (!verifier.verify(hdr, route, body, now)) {
        authFails.allow(ip, now);
        return send(401, { error: 'unauthorized' });
      }
      const wantsEnc = h('x-enc') === '1';
      if (d.encryptBodies && !wantsEnc) return send(400, { error: 'encryption_required' });
      let payload = body;
      if (wantsEnc) { // from here on, responses are encrypted too
        const key = verifier.deriveKey(hdr.keyId)!;
        enc = { key, route, nonce: hdr.nonce };
        if (body) { try { payload = e2eOpen(key, body, `req|${route}|${hdr.ts}|${hdr.nonce}`); } catch { return send(400, { error: 'bad_envelope' }); } }
      }
      if (!perKey.allow(hdr.keyId, now)) return send(429, { error: 'too_many_requests' });

      if (ingest) {
        const inc = await d.guardian.ingest(parse(payload));
        return send(200, { incident: inc?.id ?? null });
      }
      const who = hdr.keyId;
      if (route === 'GET /state')
        return send(200, { breakers: d.panel.state, pending: d.panel.pending(), incidents: [...d.guardian.incidents.values()].filter((i) => i.status !== 'closed') });
      if (route === 'GET /audit') return send(200, { entries: d.auditTail ? await d.auditTail(50) : [] });
      if (route === 'POST /devices' && d.registerDevice) {
        const t = parse(payload).token;
        if (!isStr(t, 4096) || !/^[\w:.\-]+$/.test(t)) throw new BadRequest('invalid_token');
        await d.registerDevice(who, t);
        return send(200, { ok: true });
      }
      if (route === 'POST /actions') {
        const a = parse(payload);
        if (a.op === 'propose') {
          if (!BREAKERS.includes(a.name) || typeof a.frozen !== 'boolean') throw new BadRequest('invalid_action');
          return send(200, await d.panel.propose(who, a.name as BreakerName, a.frozen));
        }
        if (['approve', 'ack', 'close'].includes(a.op)) {
          if (!isStr(a.id, 64)) throw new BadRequest('invalid_id');
          if (a.op === 'approve') return send(200, await d.panel.approve(who, a.id));
          if (a.op === 'ack') return send(200, d.guardian.ack(a.id, who));
          return send(200, d.guardian.close(a.id));
        }
        throw new BadRequest('invalid_action');
      }
      send(404, { error: 'not_found' });
    } catch (e) {
      if (e instanceof BadRequest) return send(400, { error: e.message });
      if (e instanceof Error && SAFE.has(e.message)) return send(400, { error: e.message });
      if (e instanceof SyntaxError) return send(400, { error: 'invalid_json' }); // client mistake, not worth logging
      d.log?.(e); // details stay on the server
      send(500, { error: 'internal_error' });
    }
  };
  const server = d.tls ? createHttpsServer({ cert: d.tls.cert, key: d.tls.key, minVersion: 'TLSv1.3', ...(d.tls.clientCa ? { requestCert: true, rejectUnauthorized: true, ca: d.tls.clientCa } : {}) }, handler) : createServer(handler);
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000; // slow-loris protection
  server.keepAliveTimeout = 5_000;
  return server;
}

function parse(body: string): any {
  const v = JSON.parse(body);
  if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new BadRequest('invalid_json');
  return v;
}
