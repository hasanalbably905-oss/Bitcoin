export interface GuardConfig {
  bruteForceWindowMs: number;
  bruteForceWarn: number;
  bruteForceCritical: number;
  globalBruteForceCritical: number;
  adminHoursUtc: [number, number]; // allowed admin login window [start, end)
  maxFeeSatVb: number;
  approvedReleaseHashes: Set<string>;
  cooldownMs: number; // same finding is not re-raised inside this window
  reminderMs: number; // unacknowledged critical incidents are re-sent this often
  expectedSources: string[]; // each must keep sending events (heartbeat)
  silenceMs: number;
}

export const defaultConfig = (): GuardConfig => ({
  bruteForceWindowMs: 5 * 60_000,
  bruteForceWarn: 10,
  bruteForceCritical: 50,
  globalBruteForceCritical: 200,
  adminHoursUtc: [5, 20],
  maxFeeSatVb: 500,
  approvedReleaseHashes: new Set(),
  cooldownMs: 10 * 60_000,
  reminderMs: 2 * 60_000,
  expectedSources: [],
  silenceMs: 3 * 60_000,
});
