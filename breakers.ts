import type { BreakerName } from './types.ts';

export type Role = 'owner' | 'security';
export interface Approver { id: string; role: Role }
export interface Policy { freezeApprovals: number; stopApprovals: number; resumeApprovals: number; proposalTtlMs: number }
export const DEFAULT_POLICY: Policy = { freezeApprovals: 1, stopApprovals: 2, resumeApprovals: 2, proposalTtlMs: 10 * 60_000 };

/** Makes the change real (set a flag your API checks, block traffic, scale a service to 0...). */
export interface Enforcer { apply(name: BreakerName, frozen: boolean): Promise<void> }

export interface Proposal { id: string; name: BreakerName; frozen: boolean; needed: number; approvals: string[]; createdAt: number; done: boolean }
export interface AuditEntry { ts: number; by: string; action: 'propose' | 'approve' | 'applied' | 'rejected'; name?: BreakerName; frozen?: boolean; proposalId?: string; reason?: string }
const NAMES: BreakerName[] = ['SENDS', 'RELEASES', 'SERVICE'];

/**
 * Freezing is fast (1 approver). Full stop needs 2 distinct people.
 * Resuming needs 2 distinct people including an owner, so one hijacked account cannot reopen the system.
 * Every attempt (including rejected ones) is written to the audit callback.
 */
export class BreakerPanel {
  state: Record<BreakerName, boolean> = { SENDS: false, RELEASES: false, SERVICE: false };
  #approvers = new Map<string, Approver>();
  #enforcer: Enforcer; #policy: Policy; #now: () => number; #audit: (e: AuditEntry) => void;
  #proposals = new Map<string, Proposal>(); #seq = 0;

  constructor(approvers: Approver[], enforcer: Enforcer, policy: Policy = DEFAULT_POLICY, now: () => number = Date.now, audit: (e: AuditEntry) => void = () => {}) {
    for (const a of approvers) this.#approvers.set(a.id, a);
    this.#enforcer = enforcer; this.#policy = policy; this.#now = now; this.#audit = audit;
  }

  isFrozen(name: BreakerName): boolean { return this.state[name]; }

  /** Open, unexpired proposals (for the admin page). */
  pending(): Proposal[] {
    const now = this.#now();
    for (const [id, p] of this.#proposals) if (p.done || now - p.createdAt > this.#policy.proposalTtlMs) this.#proposals.delete(id);
    return [...this.#proposals.values()].map((p) => ({ ...p, approvals: [...p.approvals] }));
  }

  async propose(by: string, name: BreakerName, frozen: boolean): Promise<Proposal> {
    try {
      this.#who(by);
      if (!NAMES.includes(name)) throw new Error('unknown breaker');
      if (this.state[name] === frozen) throw new Error('already in that state');
      const p = this.#policy;
      const needed = !frozen ? p.resumeApprovals : name === 'SERVICE' ? p.stopApprovals : p.freezeApprovals;
      const pr: Proposal = { id: `prop_${++this.#seq}`, name, frozen, needed, approvals: [by], createdAt: this.#now(), done: false };
      this.#proposals.set(pr.id, pr);
      this.#audit({ ts: this.#now(), by, action: 'propose', name, frozen, proposalId: pr.id });
      return await this.#maybeApply(pr);
    } catch (e) { this.#reject(by, e, { name, frozen }); throw e; }
  }

  async approve(by: string, id: string): Promise<Proposal> {
    try {
      this.#who(by);
      const pr = this.#proposals.get(id);
      if (!pr || pr.done) throw new Error('no such open proposal');
      if (this.#now() - pr.createdAt > this.#policy.proposalTtlMs) { this.#proposals.delete(id); throw new Error('proposal expired'); }
      if (!pr.approvals.includes(by)) pr.approvals.push(by);
      this.#audit({ ts: this.#now(), by, action: 'approve', name: pr.name, frozen: pr.frozen, proposalId: id });
      return await this.#maybeApply(pr);
    } catch (e) { this.#reject(by, e, { proposalId: id }); throw e; }
  }

  #reject(by: string, e: unknown, extra: Partial<AuditEntry>) {
    this.#audit({ ts: this.#now(), by, action: 'rejected', reason: e instanceof Error ? e.message : String(e), ...extra });
  }

  #who(id: string): Approver {
    const a = this.#approvers.get(id);
    if (!a) throw new Error('not an authorised approver');
    return a;
  }

  async #maybeApply(pr: Proposal): Promise<Proposal> {
    if (pr.approvals.length < pr.needed) return pr;
    if (!pr.frozen && !pr.approvals.some((id) => this.#approvers.get(id)?.role === 'owner')) return pr;
    await this.#enforcer.apply(pr.name, pr.frozen); // if this throws, state is unchanged
    this.state[pr.name] = pr.frozen;
    pr.done = true;
    this.#audit({ ts: this.#now(), by: pr.approvals.join('+'), action: 'applied', name: pr.name, frozen: pr.frozen, proposalId: pr.id });
    return pr;
  }
}
