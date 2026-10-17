#!/usr/bin/env node
/**
 * Stops early when a package's node_modules no longer matches its package-lock.json, typically
 * after pulling dependency changes without reinstalling, so the failure says to run `npm ci`
 * instead of surfacing as a "Cannot find module" error halfway through a build.
 *
 *   node scripts/check-deps.mjs [package-dir]    (defaults to the current directory)
 *
 * desktop-tauri, web and mcp/cpmesh-mcp run it from npm pre-hooks of their dev, build, check,
 * typecheck and test scripts, which `tauri dev` and `tauri build` trigger as well. It compares the
 * lockfile with node_modules/.package-lock.json, npm's record of what it installed, and prints
 * nothing when they match. Set CPMESH_SKIP_DEPS_CHECK=1 to skip it.
 *
 * Keep it dependency-free and compatible with Node 18.19, the oldest version the MCP server supports.
 */
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NODE_MODULES = 'node_modules/';
const LIST_LIMIT = 5;

/** Turns a lockfile key such as `node_modules/a/node_modules/b` into `a > b`. */
function packageName(key) {
  return key.slice(NODE_MODULES.length).split(`/${NODE_MODULES}`).join(' > ');
}

/**
 * Compares the `packages` of package-lock.json with those of node_modules/.package-lock.json and
 * lists the packages that are missing, installed at another version, or not in the lockfile, the
 * project's direct dependencies first. Optional packages may be missing because npm skips the ones
 * built for other platforms, packages swapped in with `npm link` are left alone, and the project's
 * own entry is ignored, so bumping its version does not require a reinstall.
 */
export function compareLockfiles(lock, installed) {
  const locked = lock.packages ?? {};
  const present = installed.packages ?? {};
  const root = locked[''] ?? {};
  const direct = new Set(
    [root.dependencies, root.devDependencies, root.optionalDependencies, root.peerDependencies]
      .flatMap((deps) => Object.keys(deps ?? {}))
      .map((name) => NODE_MODULES + name),
  );
  const missing = [];
  const changed = [];
  const extra = [];
  const entries = Object.entries(locked).sort(([a], [b]) => Number(direct.has(b)) - Number(direct.has(a)));
  for (const [key, want] of entries) {
    if (!key.startsWith(NODE_MODULES) || want.link) continue;
    const have = Object.hasOwn(present, key) ? present[key] : undefined;
    if (!have) {
      if (!want.optional && !want.devOptional) missing.push(`${packageName(key)}@${want.version}`);
    } else if (!have.link && have.version !== want.version) {
      changed.push(`${packageName(key)} (installed ${have.version}, locked ${want.version})`);
    }
  }
  for (const [key, have] of Object.entries(present)) {
    if (key.startsWith(NODE_MODULES) && !have.link && !Object.hasOwn(locked, key)) {
      extra.push(`${packageName(key)}@${have.version}`);
    }
  }
  return { missing, changed, extra };
}

/**
 * Checks the npm package in `dir`. Returns undefined when its node_modules matches its
 * package-lock.json, or when it has no lockfile to check, and otherwise why it does not.
 */
export function checkDependencies(dir) {
  const lockFile = path.join(dir, 'package-lock.json');
  if (!existsSync(lockFile)) return undefined;
  const lock = JSON.parse(readFileSync(lockFile, 'utf8'));
  if (!existsSync(path.join(dir, 'node_modules'))) return { problem: 'are not installed' };
  let installed;
  try {
    installed = JSON.parse(readFileSync(path.join(dir, 'node_modules', '.package-lock.json'), 'utf8'));
  } catch {
    return { problem: 'were not installed by npm from package-lock.json' };
  }
  const diff = compareLockfiles(lock, installed);
  if (!diff.missing.length && !diff.changed.length && !diff.extra.length) return undefined;
  return { problem: 'do not match package-lock.json', ...diff };
}

/** Formats a failed check, naming the package directory as `where`. */
export function formatReport(result, where) {
  const list = (items) =>
    items.length > LIST_LIMIT
      ? `${items.slice(0, LIST_LIMIT).join(', ')} and ${items.length - LIST_LIMIT} more`
      : items.join(', ');
  const details = [];
  if (result.missing?.length) details.push(`  missing: ${list(result.missing)}`);
  if (result.changed?.length) details.push(`  wrong version: ${list(result.changed)}`);
  if (result.extra?.length) details.push(`  not in the lockfile: ${list(result.extra)}`);
  return [
    `The dependencies in ${where} ${result.problem}${details.length ? ':' : '.'}`,
    ...details,
    `Run \`npm ci\` in ${where} to install the locked versions, then try again.`,
  ];
}

/** Names `dir` relative to the repository root when it is inside it. */
function describeDir(dir) {
  const relative = path.relative(REPO_ROOT, dir);
  return relative && !relative.startsWith('..') && !path.isAbsolute(relative) ? relative : dir;
}

function main() {
  const skip = process.env.CPMESH_SKIP_DEPS_CHECK;
  if (skip === '1' || skip === 'true') return 0;
  const dir = path.resolve(process.argv[2] ?? '.');
  const where = describeDir(dir);
  let result;
  try {
    result = checkDependencies(dir);
  } catch (err) {
    console.error(`Cannot check the dependencies in ${where}: ${err.message}`);
    return 1;
  }
  if (!result) return 0;
  console.error(formatReport(result, where).join('\n'));
  return 1;
}

function isMain() {
  try {
    return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (isMain()) process.exitCode = main();
