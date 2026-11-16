// Example wiring. Run this OUTSIDE the infrastructure it watches (separate host/account).
import { readFile } from 'node:fs/promises';
import { defaultConfig, Guardian, BreakerPanel, createGuardServer, FcmNotifier, CompositeNotifier, telegram,
  createAnalyzerFromEnv, Keyring, EncryptedFileStore, EncryptedDeviceStore, AuditLog, FlagStore, HttpSequenceAnchor, unwrapKeys, requireSecret, readSecret, assertPatchedNode } from './index.ts';
import type { Notifier } from './index.ts';

assertPatchedNode(); // refuses to run on a Node.js without the latest security fixes
const env = process.env;
const j = async (name: string) => JSON.parse(await requireSecret(env, name));

// --- encryption at rest: keys come from env/secret files, data lives in ./state (0700, files 0600) ---
// Master keys are stored ENCRYPTED under a passphrase (STATE_KEYS_WRAPPED, made with `npm run wrap-keys`); plain STATE_KEYS is for dev only.
const wrapped = await readSecret(env, 'STATE_KEYS_WRAPPED');
if (!wrapped && env.NODE_ENV === 'production') throw new Error('production requires STATE_KEYS_WRAPPED + STATE_KEYS_PASSPHRASE');
const ring = wrapped ? await unwrapKeys(wrapped, await requireSecret(env, 'STATE_KEYS_PASSPHRASE'))
  : new Keyring(await j('STATE_KEYS'), await requireSecret(env, 'STATE_KEY_CURRENT'));
const store = new EncryptedFileStore(env.STATE_DIR ?? './state', ring);
await store.init();
const audit = new AuditLog(`${env.STATE_DIR ?? './state'}/audit.log`, ring);
await audit.init(); // refuses to start if the log was tampered with
const logAudit = (e: unknown) => void audit.append(e).catch((err) => console.error('audit write failed', err instanceof Error ? err.message : 'unknown'));

const cfg = defaultConfig();
cfg.approvedReleaseHashes = new Set(JSON.parse(env.APPROVED_RELEASES ?? '[]'));
cfg.expectedSources = ['api', 'ci', 'admin'];

const devices = await EncryptedDeviceStore.open(store);
const channels: Notifier[] = [await FcmNotifier.fromServiceAccount(await requireSecret(env, 'FCM_SERVICE_ACCOUNT_FILE_PATH'), devices)];
const tg = await readSecret(env, 'TELEGRAM_BOT_TOKEN');
if (tg) channels.push(telegram(tg, await requireSecret(env, 'TELEGRAM_CHAT_ID'))); // backup channel

let saveTimer: ReturnType<typeof setTimeout> | undefined;
const guardian = new Guardian({
  config: cfg,
  notifier: new CompositeNotifier(channels),
  analyzer: await createAnalyzerFromEnv(env),
  onIncident: (i, kind) => {
    logAudit({ incident: i.id, kind, severity: i.severity, rules: i.findings.map((f) => f.ruleId) });
    clearTimeout(saveTimer); saveTimer = setTimeout(() => void store.set('incidents', guardian.snapshot()), 500);
  },
});
guardian.restore((await store.get('incidents')) ?? []);

// Sealed freeze flags: your API verifies them with FLAG_KEY (a different key from the state keys) and treats anything suspicious as frozen.
if (!env.FLAG_ANCHOR_URL || !env.FLAG_ANCHOR_TOKEN) throw new Error('Production requires an independent HTTPS sequence anchor (FLAG_ANCHOR_URL + FLAG_ANCHOR_TOKEN)');
const sequenceAnchor = new HttpSequenceAnchor(env.FLAG_ANCHOR_URL, await requireSecret(env, 'FLAG_ANCHOR_TOKEN'));
const flags = new FlagStore(env.FLAG_DIR ?? '/var/run/guardian', new Keyring({ f1: await requireSecret(env, 'FLAG_KEY') }, 'f1'), sequenceAnchor);
await flags.init();
const panel = new BreakerPanel(
  await j('APPROVERS'), // [{"id":"owner","role":"owner"},{"id":"sec-lead","role":"security"}]
  { apply: async (name, frozen) => { await flags.write(name, frozen); /* for SERVICE also call your cloud API */ } },
  undefined, undefined, logAudit,
);

const tlsCert = env.TLS_CERT_FILE, tlsKey = env.TLS_KEY_FILE;
createGuardServer({
  guardian, panel,
  sourceKeys: await j('SOURCE_KEYS'), approverKeys: await j('APPROVER_KEYS'),
  registerDevice: (who, token) => devices.add(who, token),
  tls: tlsCert && tlsKey ? { cert: await readFile(tlsCert), key: await readFile(tlsKey), clientCa: env.TLS_CLIENT_CA_FILE ? await readFile(env.TLS_CLIENT_CA_FILE) : undefined } : undefined, // clientCa = mutual TLS
  encryptBodies: env.E2E !== '0', // end-to-end encrypted bodies on top of TLS (default on) // or terminate TLS at a proxy + TRUST_PROXY=1
  admin: env.ADMIN_UI === '1', // serves /admin
  approverIps: env.APPROVER_IPS ? JSON.parse(env.APPROVER_IPS) : undefined, // e.g. ["203.0.113.7"]; strongly recommended
  auditTail: (n) => audit.tail(n),
  trustProxy: env.TRUST_PROXY === '1',
  log: (e) => console.error('guardian error', e instanceof Error ? e.message : 'unknown'),
}).listen(Number(env.PORT ?? 8443), env.HOST ?? '127.0.0.1');

setInterval(() => void guardian.tick(), 30_000);
// Anchor the audit chain outside this host once a day (e.g. send the hash to the owner) so end-truncation is detectable.
setInterval(() => console.log(JSON.stringify({ auditHead: audit.head() })), 24 * 3_600_000);
