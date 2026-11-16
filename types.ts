export type Severity = 'info' | 'warning' | 'critical';
export type BreakerName = 'SENDS' | 'RELEASES' | 'SERVICE';

export interface SecurityEvent {
  id: string;
  ts: number; // ms since epoch
  source: string; // emitting system, e.g. "api", "ci", "admin"
  type: string; // e.g. "auth.failed"
  actor?: string;
  ip?: string;
  data?: Record<string, unknown>;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  detail: string;
  key: string; // dedupe key
  eventIds: string[];
  suggest?: BreakerName; // advice for the humans, never auto-executed
}

export interface Incident {
  id: string;
  createdAt: number;
  severity: Severity;
  findings: Finding[];
  status: 'open' | 'acknowledged' | 'closed';
  ackedBy?: string;
  lastNotifiedAt: number;
  notifyCount: number;
  notifyError?: string;
  aiSummary?: string;
}
