#!/usr/bin/env node
/**
 * Sets the app version in every desktop/mobile manifest that declares it.
 *
 *   node scripts/release/set-version.mjs 0.2.0
 *
 * The Release workflow runs this with the version from the git tag so the installers,
 * the Android versionCode (which Tauri derives from tauri.conf.json) and the version the
 * apps report to the update check (CARGO_PKG_VERSION) always match the published release.
 */
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const VERSION_RE = /^\d+\.\d+\.\d+$/;

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

/**
 * Replaces the first `count` `"version": "..."` values in a JSON document. The caller
 * verifies the parsed result, so a file where those are not the intended keys fails loudly.
 */
export function setJsonVersions(text, version, count) {
  let seen = 0;
  const out = text.replace(/("version"\s*:\s*")[^"]*(")/g, (match, open, close) =>
    seen++ < count ? `${open}${version}${close}` : match,
  );
  if (seen < count) throw new Error(`expected ${count} "version" keys, found ${seen}`);
  return out;
}

/** Sets `version` in the `[package]` table of a Cargo.toml, preserving everything else. */
export function setCargoPackageVersion(text, version) {
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const lines = text.split(/\r?\n/);
  let inPackage = false;
  for (let i = 0; i < lines.length; i++) {
    if (/^\s*\[/.test(lines[i])) {
      inPackage = /^\s*\[package\]\s*(#.*)?$/.test(lines[i]);
      continue;
    }
    if (inPackage && /^\s*version\s*=/.test(lines[i])) {
      const updated = lines[i].replace(/^(\s*version\s*=\s*")[^"]*(")/, `$1${version}$2`);
      if (!updated.includes(`"${version}"`)) {
        throw new Error(`unsupported [package] version line: ${lines[i].trim()}`);
      }
      lines[i] = updated;
      return lines.join(eol);
    }
  }
  throw new Error('no version found in the [package] table');
}

/** Sets the version of one package entry in a Cargo.lock. */
export function setCargoLockVersion(text, packageName, version) {
  const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`(\\[\\[package\\]\\]\\r?\\nname = "${escaped}"\\r?\\nversion = ")[^"]*(")`, 'g');
  let found = 0;
  const out = text.replace(re, (_match, open, close) => {
    found++;
    return `${open}${version}${close}`;
  });
  if (found !== 1) throw new Error(`expected one "${packageName}" entry in Cargo.lock, found ${found}`);
  return out;
}

function checkedJson(text, check, description) {
  const doc = JSON.parse(text);
  if (!check(doc)) throw new Error(`version was not applied to ${description}`);
  return text;
}

/** The manifests to update, relative to the repository root. */
export function versionEdits(version) {
  return [
    [
      'desktop-tauri/src-tauri/tauri.conf.json',
      (t) => checkedJson(setJsonVersions(t, version, 1), (j) => j.version === version, 'the top-level "version"'),
    ],
    ['desktop-tauri/src-tauri/Cargo.toml', (t) => setCargoPackageVersion(t, version)],
    ['desktop-tauri/src-tauri/Cargo.lock', (t) => setCargoLockVersion(t, 'cpmesh-desktop', version)],
    [
      'desktop-tauri/package.json',
      (t) => checkedJson(setJsonVersions(t, version, 1), (j) => j.version === version, 'the top-level "version"'),
    ],
    [
      'desktop-tauri/package-lock.json',
      (t) =>
        checkedJson(
          setJsonVersions(t, version, 2),
          (j) => j.version === version && j.packages?.['']?.version === version,
          'the root package entries',
        ),
    ],
  ];
}

/** Applies the version to every manifest under `root`. Returns the files that changed. */
export async function setVersion(root, version) {
  if (!VERSION_RE.test(version)) throw new Error(`version must look like 1.2.3, got "${version}"`);
  const changed = [];
  for (const [relative, edit] of versionEdits(version)) {
    const file = path.join(root, relative);
    const before = await readFile(file, 'utf8');
    let after;
    try {
      after = edit(before);
    } catch (err) {
      throw new Error(`${relative}: ${err.message}`);
    }
    if (after !== before) {
      await writeFile(file, after);
      changed.push(relative);
    }
  }
  return changed;
}

async function main() {
  const version = (process.argv[2] ?? '').replace(/^v/, '');
  if (!VERSION_RE.test(version)) {
    console.error('Usage: node scripts/release/set-version.mjs <major.minor.patch>');
    process.exit(2);
  }
  const changed = await setVersion(REPO_ROOT, version);
  console.log(changed.length ? `Set version ${version} in:\n  ${changed.join('\n  ')}` : `Version is already ${version}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((err) => {
    console.error(`error: ${err.message}`);
    process.exit(1);
  });
}
