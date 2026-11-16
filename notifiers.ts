import type { BreakerName, Incident } from './types.ts';
import type { Notifier } from './guardian.ts';

const ACTION_AR: Record<BreakerName, string> = { SENDS: 'تجميد الإرسال', RELEASES: 'تجميد التحديثات', SERVICE: 'إيقاف الخدمة' };

/**
 * Push services and chat apps are third parties (and lock screens are public). By default the notification carries only
 * severity and a pointer; details are fetched inside the app over the end-to-end encrypted API.
 */
export function formatIncident(i: Incident, kind: 'new' | 'reminder', detailed = false): { title: string; body: string } {
  if (!detailed) return { title: `${kind === 'reminder' ? 'تذكير · ' : ''}إنذار أمني [${i.severity === 'critical' ? 'حرج' : 'تحذير'}]`, body: 'افتح التطبيق لعرض التفاصيل.' };
  const sev = i.severity === 'critical' ? 'حرج' : 'تحذير';
  const f = i.findings[0]!;
  const hint = i.findings.find((x) => x.suggest)?.suggest;
  const more = i.findings.length > 1 ? `\n(+${i.findings.length - 1} نتائج أخرى)` : '';
  return {
    title: `${kind === 'reminder' ? 'تذكير · ' : ''}إنذار أمني [${sev}]: ${f.title}`,
    body: `${f.detail}${more}${hint ? `\nالمقترح: ${ACTION_AR[hint]}` : ''}`,
  };
}

export interface DeviceStore {
  list(): Promise<string[]>; add(owner: string, token: string): Promise<void>; remove(token: string): Promise<void>;
}
export class MemoryDeviceStore implements DeviceStore {
  #t = new Map<string, string>();
  async list() { return [...this.#t.keys()]; }
  async add(owner: string, token: string) { if (token) this.#t.set(token, owner); }
  async remove(token: string) { this.#t.delete(token); }
}

interface Messaging {
  sendEachForMulticast(m: unknown): Promise<{ responses: { success: boolean; error?: { code?: string } }[] }>;
}

/** Push to the owner's phone. The app turns the `security_alarm` data message into an alarm screen. */
export class FcmNotifier implements Notifier {
  #m: Messaging; #store: DeviceStore; #critical: boolean; #details: boolean;
  constructor(messaging: Messaging, store: DeviceStore, opts: { criticalAlerts?: boolean; includeDetails?: boolean } = {}) {
    this.#m = messaging; this.#store = store; this.#critical = opts.criticalAlerts ?? false; this.#details = opts.includeDetails ?? false;
  }
  static async fromServiceAccount(path: string, store: DeviceStore, opts: { criticalAlerts?: boolean; includeDetails?: boolean } = {}) {
    const mod: any = await import('firebase-admin');
    const admin = mod.default ?? mod;
    const { readFile } = await import('node:fs/promises');
    const app = admin.initializeApp({ credential: admin.credential.cert(JSON.parse(await readFile(path, 'utf8'))) });
    return new FcmNotifier(admin.messaging(app), store, opts);
  }
  async send(i: Incident, kind: 'new' | 'reminder'): Promise<void> {
    const tokens = await this.#store.list();
    if (tokens.length === 0) throw new Error('no registered devices');
    const { title, body } = formatIncident(i, kind, this.#details);
    const res = await this.#m.sendEachForMulticast({
      tokens,
      data: { type: 'security_alarm', incidentId: i.id, severity: i.severity },
      notification: { title, body },
      android: { priority: 'high', ttl: 600_000, notification: { channelId: 'security-alarm', priority: 'max', sound: 'alarm', visibility: this.#details ? 'public' : 'private' } },
      apns: {
        headers: { 'apns-priority': '10', 'apns-push-type': 'alert' },
        payload: { aps: {
          sound: this.#critical ? { critical: 1, name: 'alarm.caf', volume: 1 } : 'alarm.caf',
          'interruption-level': this.#critical ? 'critical' : 'time-sensitive',
        } },
      },
    });
    await Promise.all(res.responses.map((r, n) =>
      !r.success && /not-registered|invalid-registration/.test(r.error?.code ?? '') ? this.#store.remove(tokens[n]!) : undefined));
    if (!res.responses.some((r) => r.success)) throw new Error('FCM delivery failed for all devices');
  }
}

/** Generic webhook backup channel (Telegram, Slack, ...). */
export class WebhookNotifier implements Notifier {
  #url: string; #build: (title: string, body: string) => unknown; #details: boolean;
  constructor(url: string, build: (title: string, body: string) => unknown, includeDetails = false) { this.#url = url; this.#build = build; this.#details = includeDetails; }
  async send(i: Incident, kind: 'new' | 'reminder'): Promise<void> {
    const { title, body } = formatIncident(i, kind, this.#details);
    const r = await fetch(this.#url, { method: 'POST', redirect: 'error', headers: { 'content-type': 'application/json', 'accept-encoding': 'identity' },
      body: JSON.stringify(this.#build(title, body)), signal: AbortSignal.timeout(8000) });
    if (!r.ok) throw new Error(`webhook ${r.status}`);
  }
}
export const telegram = (botToken: string, chatId: string, includeDetails = false) =>
  new WebhookNotifier(`https://api.telegram.org/bot${botToken}/sendMessage`, (t, b) => ({ chat_id: chatId, text: `${t}\n${b}` }), includeDetails);

/** Sends on every channel; succeeds if at least one delivered. */
export class CompositeNotifier implements Notifier {
  #list: Notifier[];
  constructor(list: Notifier[]) { this.#list = list; }
  async send(i: Incident, kind: 'new' | 'reminder'): Promise<void> {
    const rs = await Promise.allSettled(this.#list.map((n) => n.send(i, kind)));
    if (!rs.some((r) => r.status === 'fulfilled')) throw new Error('all notification channels failed');
  }
}
