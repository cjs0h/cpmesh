// Tests for the dependency check: node --test scripts/check-deps.test.mjs
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { checkDependencies, compareLockfiles, formatReport } from './check-deps.mjs';

const SCRIPT = fileURLToPath(new URL('./check-deps.mjs', import.meta.url));
const REPO_ROOT = path.resolve(path.dirname(SCRIPT), '..');

const LOCK = {
  name: 'app',
  version: '1.0.0',
  lockfileVersion: 3,
  requires: true,
  packages: {
    '': { name: 'app', version: '1.0.0', devDependencies: { '@tailwindcss/vite': '^4.3.3', vite: '^8.3.4' } },
    'node_modules/@rollup/rollup-darwin-arm64': {
      version: '4.50.0',
      dev: true,
      optional: true,
      os: ['darwin'],
      cpu: ['arm64'],
    },
    'node_modules/@tailwindcss/vite': { version: '4.3.3', dev: true },
    'node_modules/fsevents': { version: '2.3.3', devOptional: true },
    'node_modules/postcss': { version: '8.5.29', dev: true },
    'node_modules/vite': { version: '8.3.4', dev: true },
    'node_modules/vite/node_modules/esbuild': { version: '0.28.2', dev: true },
  },
};

/** What npm records in node_modules/.package-lock.json after `npm ci` on Linux. */
function installedFrom(lock) {
  const packages = { ...lock.packages };
  delete packages[''];
  delete packages['node_modules/@rollup/rollup-darwin-arm64'];
  delete packages['node_modules/fsevents'];
  return { name: lock.name, version: lock.version, lockfileVersion: 3, requires: true, packages };
}

function withPackages(base, edit) {
  const packages = { ...base.packages };
  edit(packages);
  return { ...base, packages };
}

describe('compareLockfiles', () => {
  it('accepts a complete install without other platforms\' optional packages', () => {
    assert.deepEqual(compareLockfiles(LOCK, installedFrom(LOCK)), { missing: [], changed: [], extra: [] });
  });

  it('ignores the project version, which set-version.mjs bumps', () => {
    const bumped = withPackages({ ...LOCK, version: '2.0.0' }, (p) => {
      p[''] = { ...p[''], version: '2.0.0' };
    });
    assert.deepEqual(compareLockfiles(bumped, installedFrom(LOCK)), { missing: [], changed: [], extra: [] });
  });

  it('lists missing, mismatched and unlisted packages, direct dependencies first', () => {
    const stale = withPackages(installedFrom(LOCK), (p) => {
      delete p['node_modules/@tailwindcss/vite'];
      delete p['node_modules/postcss'];
      delete p['node_modules/vite/node_modules/esbuild'];
      p['node_modules/vite'] = { version: '8.2.0', dev: true };
      p['node_modules/left-pad'] = { version: '1.3.0' };
    });
    assert.deepEqual(compareLockfiles(LOCK, stale), {
      missing: ['@tailwindcss/vite@4.3.3', 'postcss@8.5.29', 'vite > esbuild@0.28.2'],
      changed: ['vite (installed 8.2.0, locked 8.3.4)'],
      extra: ['left-pad@1.3.0'],
    });
  });

  it('leaves packages swapped in with npm link alone', () => {
    const linked = withPackages(installedFrom(LOCK), (p) => {
      p['node_modules/vite'] = { resolved: '../../vite', link: true };
      p['node_modules/local-tool'] = { resolved: '../local-tool', link: true };
    });
    assert.deepEqual(compareLockfiles(LOCK, linked), { missing: [], changed: [], extra: [] });
  });
});

describe('formatReport', () => {
  it('names the problem, the packages and the fix', () => {
    const missing = ['a@1.0.0', 'b@1.0.0', 'c@1.0.0', 'd@1.0.0', 'e@1.0.0', 'f@1.0.0', 'g@1.0.0'];
    assert.deepEqual(formatReport({ problem: 'do not match package-lock.json', missing, changed: [], extra: [] }, 'web'), [
      'The dependencies in web do not match package-lock.json:',
      '  missing: a@1.0.0, b@1.0.0, c@1.0.0, d@1.0.0, e@1.0.0 and 2 more',
      'Run `npm ci` in web to install the locked versions, then try again.',
    ]);
    assert.deepEqual(formatReport({ problem: 'are not installed' }, 'web'), [
      'The dependencies in web are not installed.',
      'Run `npm ci` in web to install the locked versions, then try again.',
    ]);
  });
});

describe('checkDependencies and the CLI', () => {
  const dirs = [];

  /** Creates a package directory holding the given JSON files. */
  async function fixture(files) {
    const dir = await realpath(await mkdtemp(path.join(tmpdir(), 'cpmesh-check-deps-')));
    dirs.push(dir);
    for (const [relative, data] of Object.entries(files)) {
      await mkdir(path.dirname(path.join(dir, relative)), { recursive: true });
      await writeFile(path.join(dir, relative), typeof data === 'string' ? data : JSON.stringify(data, null, 2));
    }
    return dir;
  }

  function run(dir, args = [], env = {}) {
    return spawnSync(process.execPath, [SCRIPT, ...args], {
      cwd: dir,
      encoding: 'utf8',
      env: { ...process.env, CPMESH_SKIP_DEPS_CHECK: '', ...env },
    });
  }

  after(async () => {
    await Promise.all(dirs.map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it('has nothing to check without a lockfile', async () => {
    const dir = await fixture({ 'package.json': {} });
    assert.equal(checkDependencies(dir), undefined);
    assert.equal(run(dir).status, 0);
  });

  it('reports dependencies that were not installed by npm', async () => {
    assert.deepEqual(checkDependencies(await fixture({ 'package-lock.json': LOCK })), { problem: 'are not installed' });
    assert.deepEqual(checkDependencies(await fixture({ 'package-lock.json': LOCK, 'node_modules/vite/package.json': {} })), {
      problem: 'were not installed by npm from package-lock.json',
    });
  });

  it('is silent when node_modules matches the lockfile', async () => {
    const dir = await fixture({ 'package-lock.json': LOCK, 'node_modules/.package-lock.json': installedFrom(LOCK) });
    assert.equal(checkDependencies(dir), undefined);
    const result = run(dir);
    assert.equal(result.status, 0);
    assert.equal(result.stdout + result.stderr, '');
  });

  it('fails with the fix when the lockfile changed after the install', async () => {
    const changed = withPackages(LOCK, (p) => {
      p['node_modules/tailwindcss'] = { version: '4.3.3', dev: true };
    });
    const dir = await fixture({ 'package-lock.json': changed, 'node_modules/.package-lock.json': installedFrom(LOCK) });
    const result = run(dir);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.equal(
      result.stderr,
      [
        `The dependencies in ${dir} do not match package-lock.json:`,
        '  missing: tailwindcss@4.3.3',
        `Run \`npm ci\` in ${dir} to install the locked versions, then try again.`,
        '',
      ].join('\n'),
    );
    assert.equal(run(REPO_ROOT, [dir]).status, 1, 'takes the package directory as an argument');
    assert.equal(run(dir, [], { CPMESH_SKIP_DEPS_CHECK: '1' }).status, 0, 'can be skipped');
  });

  it('fails clearly on an unreadable lockfile', async () => {
    const result = run(await fixture({ 'package-lock.json': '<<<<<<< HEAD\n' }));
    assert.equal(result.status, 1);
    assert.match(result.stderr, /^Cannot check the dependencies in .+: /);
  });
});

describe('npm hooks', () => {
  for (const pkg of ['desktop-tauri', 'web', 'mcp/cpmesh-mcp']) {
    it(`${pkg} checks its dependencies before dev, build, check, typecheck and test`, async () => {
      const { scripts } = JSON.parse(await readFile(path.join(REPO_ROOT, pkg, 'package.json'), 'utf8'));
      const guarded = ['dev', 'build', 'check', 'typecheck', 'test'].filter((name) => scripts[name]);
      assert.ok(guarded.includes('build') && guarded.includes('test'), pkg);
      for (const name of guarded) {
        const hook = scripts[`pre${name}`] ?? '';
        const target = hook.match(/^node (\S+check-deps\.mjs)$/)?.[1];
        assert.ok(target, `${pkg}: "pre${name}" should run check-deps.mjs, got "${hook}"`);
        assert.equal(path.resolve(REPO_ROOT, pkg, target), SCRIPT, `${pkg}: pre${name}`);
      }
    });
  }
});
