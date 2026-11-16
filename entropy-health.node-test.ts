import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { assessEntropy } from '../../src/entropy-health.ts';
import { verifyLockfile, verifyManifest } from '../../src/supply-chain.ts';

test('known-bad generators are rejected', () => {
  assert.equal(assessEntropy(new Uint8Array(32)).ok, false); // all zero (unseeded PRNG)
  assert.equal(assessEntropy(new Uint8Array(32).fill(0xff)).ok, false);
  assert.equal(assessEntropy(Uint8Array.from({ length: 32 }, (_, i) => i)).ok, false); // counter
  assert.equal(assessEntropy(Uint8Array.from({ length: 32 }, (_, i) => (i * 7) % 256)).ok, false); // arithmetic sequence
  assert.equal(assessEntropy(Uint8Array.from({ length: 32 }, (_, i) => [1, 2, 3, 4][i % 4]!)).ok, false); // repeating block
  assert.equal(assessEntropy(Uint8Array.from({ length: 32 }, () => 0x01)).ok, false);
  assert.equal(assessEntropy(Uint8Array.from({ length: 32 }, (_, i) => (i % 2 ? 0x00 : 0x11))).ok, false);
  assert.equal(assessEntropy(randomBytes(8)).ok, false); // too short
});

test('real CSPRNG output passes, with a negligible false-alarm rate', () => {
  let bad = 0;
  for (let i = 0; i < 20_000; i++) if (!assessEntropy(randomBytes(32)).ok) bad++;
  for (let i = 0; i < 20_000; i++) if (!assessEntropy(randomBytes(16)).ok) bad++;
  assert.ok(bad <= 4, `false alarms: ${bad} of 40000`);
});

test('lockfile verifier flags registry bypass, missing hashes and install scripts', () => {
  const good = { lockfileVersion: 3, packages: { '': {}, 'node_modules/a': { resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz', integrity: 'sha512-abc' } } };
  assert.deepEqual(verifyLockfile(good), []);
  const bad = { lockfileVersion: 3, packages: { '': {}, 'node_modules/x': { resolved: 'git+ssh://git@github.com/x/x.git', integrity: 'sha1-abc' },
    'node_modules/y': { resolved: 'https://evil.example/y.tgz', integrity: 'sha512-1', hasInstallScript: true }, 'node_modules/z': { link: true } } };
  const p = verifyLockfile(bad).join('|');
  assert.match(p, /x: not resolved/); assert.match(p, /x: missing sha512/); assert.match(p, /y: not resolved/); assert.match(p, /y: runs an install script/); assert.match(p, /z: symlinked/);
  assert.equal(verifyLockfile(null).length, 1);
  assert.equal(verifyManifest({ dependencies: { a: 'github:x/y', b: '^1.0.0', c: 'latest', d: '*' }, scripts: { postinstall: 'x' } }).length, 4);
});
