/** Checks a package-lock.json for the traits seen in 2026 npm supply-chain attacks. Returns a list of problems (empty = clean). */
export function verifyLockfile(lock: any): string[] {
  const problems: string[] = [];
  if (!lock || typeof lock !== 'object' || !lock.packages) return ['lockfile missing or unsupported (need lockfileVersion 2 or 3)'];
  for (const [path, p] of Object.entries<any>(lock.packages)) {
    if (path === '') continue;
    const name = path.replace(/^.*node_modules\//, '');
    if (p.link) { problems.push(`${name}: symlinked/local dependency`); continue; }
    if (typeof p.resolved !== 'string' || !p.resolved.startsWith('https://registry.npmjs.org/')) problems.push(`${name}: not resolved from the npm registry over https (${String(p.resolved).slice(0, 60)})`);
    if (typeof p.integrity !== 'string' || !p.integrity.startsWith('sha512-')) problems.push(`${name}: missing sha512 integrity hash`);
    if (p.hasInstallScript) problems.push(`${name}: runs an install script (review it, or allow it explicitly)`);
  }
  return problems;
}

/** Flags manifest entries that bypass the lockfile (git/http/file URLs, "latest", "*"). */
export function verifyManifest(pkg: any): string[] {
  const out: string[] = [];
  for (const sect of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    for (const [n, v] of Object.entries<string>(pkg?.[sect] ?? {})) {
      if (/^(git|github|http|https|file|link):|\/|^latest$|^\*$|^$/.test(v)) out.push(`${sect}.${n}: unsafe version spec "${v}"`);
    }
  }
  for (const s of ['preinstall', 'install', 'postinstall', 'prepare']) if (pkg?.scripts?.[s]) out.push(`scripts.${s}: lifecycle hook present`);
  return out;
}
