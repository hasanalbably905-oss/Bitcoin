import { readFile } from 'node:fs/promises';

/** Reads NAME, or the file named by NAME_FILE (Docker/Kubernetes secrets). Files keep secrets out of `ps`, `docker inspect` and crash dumps. */
export async function readSecret(env: Record<string, string | undefined>, name: string): Promise<string | undefined> {
  const file = env[`${name}_FILE`];
  if (file) return (await readFile(file, 'utf8')).trim();
  return env[name]?.trim() || undefined;
}
export async function requireSecret(env: Record<string, string | undefined>, name: string): Promise<string> {
  const v = await readSecret(env, name);
  if (!v) throw new Error(`missing secret ${name} (or ${name}_FILE)`);
  return v;
}
