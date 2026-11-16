import { randomUUID } from 'node:crypto';
import type { SecurityEvent } from './types.ts';

const TYPE = /^[a-z0-9_.]{1,64}$/;
// Removes control characters and invisible/bidi-override characters (used to disguise text in admin screens and notifications).
const INVISIBLE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u200B\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;
export const cleanText = (s: string, max = 500): string => s.normalize('NFC').replace(INVISIBLE, '').slice(0, max);
const clip = (v: unknown, n: number): string | undefined => (typeof v === 'string' ? cleanText(v, n) : undefined);
const DANGEROUS = new Set(['__proto__', 'constructor', 'prototype', 'toString', 'valueOf', 'toJSON', 'hasOwnProperty', 'isPrototypeOf']);
/** Safe coercions: attacker-shaped objects (e.g. {"toString": 1}) make String()/Number() throw. These never do. */
export const asText = (v: unknown): string => (typeof v === 'string' ? v : typeof v === 'number' || typeof v === 'boolean' ? String(v) : '');
export const asNumber = (v: unknown): number => (typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' ? Number(v) : NaN);
function cleanData(v: unknown, depth: number): unknown {
  if (typeof v === 'string') return cleanText(v);
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'boolean' || v === null) return v;
  if (depth >= 4 || typeof v !== 'object') return null;
  if (Array.isArray(v)) return v.slice(0, 50).map((x) => cleanData(x, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, x] of Object.entries(v as Record<string, unknown>).slice(0, 50)) if (!DANGEROUS.has(k)) out[cleanText(k, 64)] = cleanData(x, depth + 1);
  return out;
}

/** Events may come from compromised systems: validate shape and cap sizes. */
export function sanitizeEvent(raw: unknown, now: number): SecurityEvent | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  const type = clip(r.type, 64);
  const source = clip(r.source, 64);
  if (!type || !source || !TYPE.test(type)) return null;
  const ts = typeof r.ts === 'number' && Number.isFinite(r.ts) && Math.abs(r.ts - now) < 86_400_000 ? r.ts : now;
  let data: Record<string, unknown> | undefined;
  if (typeof r.data === 'object' && r.data !== null && !Array.isArray(r.data)) {
    try {
      if (JSON.stringify(r.data).length <= 4096) data = cleanData(r.data, 0) as Record<string, unknown>;
    } catch { /* drop unserialisable data */ }
  }
  return { id: clip(r.id, 100) ?? randomUUID(), ts, source, type, actor: clip(r.actor, 100), ip: clip(r.ip, 64), data };
}
