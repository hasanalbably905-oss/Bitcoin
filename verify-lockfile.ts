// CI gate: node scripts/verify-lockfile.ts   (run after `npm ci`; fails the build on any problem)
import { readFileSync, existsSync } from 'node:fs';
import { verifyLockfile, verifyManifest } from '../src/supply-chain.ts';
if (!existsSync('package-lock.json')) { console.error('package-lock.json is missing: run `npm install` once and commit it'); process.exit(1); }
const problems = [...verifyManifest(JSON.parse(readFileSync('package.json', 'utf8'))), ...verifyLockfile(JSON.parse(readFileSync('package-lock.json', 'utf8')))];
if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
console.log('lockfile ok');
