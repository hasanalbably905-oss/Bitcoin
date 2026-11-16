import type { Finding, SecurityEvent } from './types.ts';
import type { GuardConfig } from './config.ts';
import { asNumber, asText } from './sanitize.ts';

export class SlidingCounter {
  #hits = new Map<string, number[]>();
  add(key: string, ts: number, windowMs: number): number {
    if (this.#hits.size > 20_000) {
      for (const [k, a] of this.#hits) if ((a[a.length - 1] ?? 0) <= ts - windowMs) this.#hits.delete(k);
      if (this.#hits.size > 20_000) this.#hits.clear();
    }
    const arr = (this.#hits.get(key) ?? []).filter((t) => t > ts - windowMs);
    arr.push(ts);
    this.#hits.set(key, arr);
    return arr.length;
  }
}

export interface RuleContext { config: GuardConfig; counters: SlidingCounter }
export type Rule = (e: SecurityEvent, c: RuleContext) => Finding | null;

const str = asText;

const bruteForce: Rule = (e, c) => {
  if (e.type !== 'auth.failed') return null;
  const who = e.ip ?? e.actor ?? 'unknown';
  const n = c.counters.add(`bf:${who}`, e.ts, c.config.bruteForceWindowMs);
  const all = c.counters.add('bf:all', e.ts, c.config.bruteForceWindowMs);
  if (all === c.config.globalBruteForceCritical)
    return { ruleId: 'bruteforce.distributed', severity: 'critical', key: 'bf:distributed', eventIds: [e.id],
      title: 'هجوم تخمين كلمات مرور موزّع', detail: `${all} محاولة فاشلة خلال الفترة من عناوين متعددة` };
  if (n === c.config.bruteForceCritical)
    return { ruleId: 'bruteforce', severity: 'critical', key: `bf:${who}:c`, eventIds: [e.id],
      title: `هجوم تخمين من ${who}`, detail: `${n} محاولة دخول فاشلة` };
  if (n === c.config.bruteForceWarn)
    return { ruleId: 'bruteforce', severity: 'warning', key: `bf:${who}:w`, eventIds: [e.id],
      title: `محاولات دخول فاشلة متكررة من ${who}`, detail: `${n} محاولة` };
  return null;
};

const adminChange: Rule = (e) =>
  ['admin.created', 'admin.role_changed', 'admin.mfa_disabled'].includes(e.type)
    ? { ruleId: 'admin.change', severity: 'critical', key: `admin:${e.type}:${e.actor ?? ''}`, eventIds: [e.id],
        title: 'تغيير حساس في حسابات الإدارة', detail: `${e.type} بواسطة ${e.actor ?? 'مجهول'}` }
    : null;

const offHoursAdmin: Rule = (e, c) => {
  if (e.type !== 'admin.login') return null;
  const h = new Date(e.ts).getUTCHours();
  const [a, b] = c.config.adminHoursUtc;
  return h >= a && h < b ? null
    : { ruleId: 'admin.offhours', severity: 'warning', key: `offhours:${e.actor ?? ''}`, eventIds: [e.id],
        title: 'دخول إداري خارج أوقات العمل', detail: `${e.actor ?? 'مجهول'} الساعة ${h}:00 UTC` };
};

const releaseTamper: Rule = (e, c) => {
  if (e.type !== 'release.published') return null;
  const ok = e.data?.signed === true && c.config.approvedReleaseHashes.has(str(e.data?.sha256));
  return ok ? null
    : { ruleId: 'release.unapproved', severity: 'critical', key: `release:${str(e.data?.sha256)}`, eventIds: [e.id], suggest: 'RELEASES',
        title: 'إصدار تطبيق غير معتمد أو غير موقّع', detail: `بصمة الإصدار: ${str(e.data?.sha256).slice(0, 16)}` };
};

const integrityMismatch: Rule = (e) =>
  e.type === 'integrity.mismatch'
    ? { ruleId: 'integrity.mismatch', severity: 'critical', key: `integrity:${e.source}`, eventIds: [e.id], suggest: 'SENDS',
        title: 'بيانات مرجعة من الخادم لا تطابق المتوقع', detail: str(e.data?.what).slice(0, 200) || 'عنوان أو رسوم مختلفة عن المتوقع' }
    : null;

const secretLeak: Rule = (e) =>
  e.type === 'secret.leaked' || e.type === 'apikey.new_ip'
    ? { ruleId: 'secret.exposure', severity: 'critical', key: `secret:${e.type}:${str(e.data?.name)}`, eventIds: [e.id],
        title: 'احتمال تسريب مفتاح أو سر', detail: `${e.type} ${str(e.data?.name).slice(0, 60)}` }
    : null;

const physicalTamper: Rule = (e) =>
  e.type.startsWith('physical.')
    ? { ruleId: 'physical', severity: 'critical', key: `physical:${e.type}:${e.source}`, eventIds: [e.id], suggest: 'SERVICE',
        title: 'تنبيه أمن مادي', detail: `${e.type} من ${e.source}` }
    : null;

const feeSpike: Rule = (e, c) => {
  if (e.type !== 'fee.quote') return null;
  const v = asNumber(e.data?.satPerVb);
  return Number.isFinite(v) && v > c.config.maxFeeSatVb
    ? { ruleId: 'fee.spike', severity: 'critical', key: 'fee.spike', eventIds: [e.id], suggest: 'SENDS',
        title: 'رسوم شبكة غير معقولة', detail: `${v} sat/vB (الحد ${c.config.maxFeeSatVb})` }
    : null;
};

export const rules: Rule[] = [bruteForce, adminChange, offHoursAdmin, releaseTamper, integrityMismatch, secretLeak, physicalTamper, feeSpike];
