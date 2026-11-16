import type { Finding, Incident, SecurityEvent, Severity } from './types.ts';
import type { GuardConfig } from './config.ts';
import { rules, SlidingCounter } from './rules.ts';
import { AnomalyDetector } from './anomaly.ts';
import { asNumber, asText, cleanText, sanitizeEvent } from './sanitize.ts';

export interface Notifier { send(i: Incident, kind: 'new' | 'reminder'): Promise<void> }
/** Advisory only: output is stored on the incident and never triggers any action. */
export interface Analyzer { summarize(i: Incident, events: SecurityEvent[]): Promise<string> }

const RANK: Record<Severity, number> = { info: 0, warning: 1, critical: 2 };

export class Guardian {
  incidents = new Map<string, Incident>();
  #cfg: GuardConfig; #notifier: Notifier; #analyzer?: Analyzer; #now: () => number;
  #counters = new SlidingCounter(); #anomaly = new AnomalyDetector();
  #recent: SecurityEvent[] = []; #cooldown = new Map<string, number>();
  #lastSeen = new Map<string, number>(); #pending = new Set<Promise<void>>(); #seq = 0;

  #hook?: (i: Incident, kind: 'created' | 'acked' | 'closed') => void;

  constructor(o: { config: GuardConfig; notifier: Notifier; analyzer?: Analyzer; now?: () => number; onIncident?: (i: Incident, kind: 'created' | 'acked' | 'closed') => void }) {
    this.#hook = o.onIncident;
    this.#cfg = o.config; this.#notifier = o.notifier; this.#analyzer = o.analyzer; this.#now = o.now ?? Date.now;
    for (const s of o.config.expectedSources) this.#lastSeen.set(s, this.#now());
  }

  async ingest(raw: unknown): Promise<Incident | null> {
    const e = sanitizeEvent(raw, this.#now());
    if (!e) return null;
    if (this.#cfg.expectedSources.includes(e.source)) this.#lastSeen.set(e.source, this.#now());
    this.#recent.push(e);
    if (this.#recent.length > 500) this.#recent.shift();
    const findings: Finding[] = [];
    const ctx = { config: this.#cfg, counters: this.#counters };
    for (const r of rules) { const f = r(e, ctx); if (f) findings.push(f); }
    if (e.type === 'metric') {
      const name = asText(e.data?.name).slice(0, 100);
      const v = asNumber(e.data?.value);
      if (name && Number.isFinite(v)) {
        const a = this.#anomaly.check(name, v);
        if (a.level !== 'ok')
          findings.push({ ruleId: 'anomaly', severity: a.level, key: `anomaly:${name}`, eventIds: [e.id],
            title: `قيمة غير طبيعية: ${name}`, detail: `القيمة ${v} (انحراف ${a.z.toFixed(1)}σ)` });
      }
    }
    return this.#raise(findings);
  }

  /** Call every ~30s: detects silent sources and re-sends unacknowledged critical incidents. */
  async tick(): Promise<void> {
    const now = this.#now();
    const silent: Finding[] = [];
    for (const src of this.#cfg.expectedSources)
      if (now - (this.#lastSeen.get(src) ?? 0) > this.#cfg.silenceMs)
        silent.push({ ruleId: 'silence', severity: 'critical', key: `silence:${src}`, eventIds: [],
          title: `المصدر "${src}" توقف عن الإرسال`, detail: 'قد يكون عطلًا، أو مهاجمًا أسكت السجلات.' });
    await this.#raise(silent);
    for (const i of this.incidents.values())
      if (i.status === 'open' && i.severity === 'critical' && now - i.lastNotifiedAt >= this.#cfg.reminderMs)
        await this.#notify(i, 'reminder');
  }

  ack(id: string, by: string): Incident | null {
    const i = this.incidents.get(id);
    if (i && i.status === 'open') { i.status = 'acknowledged'; i.ackedBy = by; this.#emit(i, 'acked'); }
    return i ?? null;
  }
  close(id: string): Incident | null {
    const i = this.incidents.get(id);
    if (i) { i.status = 'closed'; this.#emit(i, 'closed'); }
    return i ?? null;
  }
  #emit(i: Incident, kind: 'created' | 'acked' | 'closed') { try { this.#hook?.(i, kind); } catch { /* hooks must never break alerting */ } }
  snapshot(): Incident[] { return [...this.incidents.values()]; }
  restore(list: Incident[]): void {
    for (const i of list) {
      if (typeof i?.id !== 'string' || !Array.isArray(i.findings)) continue;
      this.incidents.set(i.id, i);
      this.#seq = Math.max(this.#seq, Number(i.id.split('_')[1]) || 0);
    }
  }
  async flush(): Promise<void> { await Promise.allSettled([...this.#pending]); }

  async #raise(findings: Finding[]): Promise<Incident | null> {
    const now = this.#now();
    const fresh = findings.filter((f) => {
      const last = this.#cooldown.get(f.key);
      if (last !== undefined && now - last < this.#cfg.cooldownMs) return false;
      this.#cooldown.set(f.key, now);
      return true;
    });
    if (fresh.length === 0) return null;
    const severity = fresh.reduce<Severity>((m, f) => (RANK[f.severity] > RANK[m] ? f.severity : m), 'info');
    const incident: Incident = { id: `inc_${++this.#seq}`, createdAt: now, severity, findings: fresh, status: 'open', lastNotifiedAt: 0, notifyCount: 0 };
    this.incidents.set(incident.id, incident);
    this.#trim();
    await this.#notify(incident, 'new'); // alert first; AI analysis never delays it
    this.#emit(incident, 'created');
    if (this.#analyzer) {
      const p: Promise<void> = this.#analyze(incident).finally(() => this.#pending.delete(p));
      this.#pending.add(p);
    }
    return incident;
  }

  /** Bounded memory: attackers control the keys (IPs, names), so every map has a cap. */
  #trim(): void {
    if (this.incidents.size > 1000) {
      for (const [id, i] of this.incidents) if (i.status === 'closed') { this.incidents.delete(id); if (this.incidents.size <= 1000) break; }
      for (const id of this.incidents.keys()) { if (this.incidents.size <= 1000) break; this.incidents.delete(id); }
    }
    if (this.#cooldown.size > 10_000) {
      const now = this.#now();
      for (const [k, t] of this.#cooldown) if (now - t >= this.#cfg.cooldownMs) this.#cooldown.delete(k);
      if (this.#cooldown.size > 10_000) this.#cooldown.clear();
    }
  }

  async #notify(i: Incident, kind: 'new' | 'reminder'): Promise<void> {
    try {
      await this.#notifier.send(i, kind);
      i.lastNotifiedAt = this.#now(); i.notifyCount++; i.notifyError = undefined;
    } catch (err) {
      i.notifyError = err instanceof Error ? err.message : String(err); // lastNotifiedAt stays 0 -> retried next tick
    }
  }

  async #analyze(i: Incident): Promise<void> {
    try {
      const ids = new Set(i.findings.flatMap((f) => f.eventIds));
      i.aiSummary = cleanText(String(await this.#analyzer!.summarize(i, this.#recent.filter((e) => ids.has(e.id)).slice(-20))), 1500);
    } catch { /* advisory only */ }
  }
}
