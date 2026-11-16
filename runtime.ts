// Minimum Node.js versions that contain the 11 Nov 2026 security release (TLS/HTTP/HTTP2 memory-safety and mTLS fixes)
// plus the 21 Oct 2026 one (TLS hostname checks, Brotli decoder). UPDATE THIS TABLE after every Node security release.
export const MIN_PATCHED_NODE: Record<number, [number, number, number]> = { 22: [22, 23, 5], 24: [24, 22, 3], 26: [26, 13, 1] };

export function checkNodeVersion(version: string, min: Record<number, [number, number, number]> = MIN_PATCHED_NODE): { ok: boolean; reason: string } {
  const m = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(version.trim());
  if (!m) return { ok: false, reason: `unrecognised Node version "${version}"` };
  const v = [Number(m[1]), Number(m[2]), Number(m[3])] as const;
  const need = min[v[0]];
  if (!need) return { ok: false, reason: `Node ${v[0]}.x is not a supported release line (use ${Object.keys(min).join(', ')})` };
  for (let i = 0; i < 3; i++) {
    if (v[i]! > need[i]!) return { ok: true, reason: 'ok' };
    if (v[i]! < need[i]!) return { ok: false, reason: `Node ${version} lacks security fixes; need >= ${need.join('.')}` };
  }
  return { ok: true, reason: 'ok' };
}

/** Refuses to start on an unpatched runtime (override only for development). */
export function assertPatchedNode(version: string = process.versions.node, env: Record<string, string | undefined> = process.env): void {
  const r = checkNodeVersion(version);
  if (!r.ok && env.ALLOW_UNPATCHED_NODE !== '1') throw new Error(`${r.reason} (set ALLOW_UNPATCHED_NODE=1 only for development)`);
}
