#!/usr/bin/env node
/**
 * Registers a published GitHub release with a cpmesh server, so the website's Downloads
 * section (/api/downloads/current) and the apps' update check (/api/updates/check) offer it.
 *
 *   gh release view v1.2.3 --json tagName,url,isDraft,assets > release.json
 *   node scripts/release/publish-website.mjs --release release.json [--notes "One-line summary"]
 *
 * Options:
 *   --notes <text>      One-line note shown in the apps' update banner (defaults to a link to the release)
 *   --dry-run           Print what would be published without contacting the server
 *   --force             Allow publishing a version older than the one currently offered
 *   --skip-url-check    Do not check that the installer URLs are downloadable first
 *
 * Environment:
 *   CPMESH_URL              Server base URL (default https://cpmesh.com)
 *   CPMESH_ADMIN_USERNAME   Admin account used for the admin API (publishing is skipped when unset)
 *   CPMESH_ADMIN_PASSWORD
 *
 * Installers must be named cpmesh-<version>-<os>[-<arch>][-setup].<ext>. For every update target
 * (the platform/arch pair an app reports) the best installer becomes a current app release, and
 * each installer becomes a download link attached to a release. Re-running is idempotent.
 */
import { appendFile, readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

const ASSET_RE =
  /^cpmesh-(\d+\.\d+\.\d+)-(windows|macos|linux|android)(?:-(amd64|arm64|universal))?(?:-setup)?\.(exe|msi|dmg|deb|rpm|appimage|apk)$/i;

// Lower ranks are preferred: the best installer for a target is what the in-app updater downloads,
// and the website lists a platform's links in this order.
const FORMAT_RANK = { exe: 0, msi: 1, dmg: 0, deb: 0, appimage: 1, rpm: 2, apk: 0 };

// The apps report macOS as "darwin" to the update check; the website groups links under "macos".
const UPDATE_PLATFORM = { windows: 'windows', macos: 'darwin', linux: 'linux', android: 'android' };

const IN_ACTIONS = process.env.GITHUB_ACTIONS === 'true';

/** Compares dotted numeric versions; returns <0, 0 or >0. */
export function compareVersions(a, b) {
  const pa = String(a).replace(/^v/, '').split('.').map((n) => Number.parseInt(n, 10) || 0);
  const pb = String(b).replace(/^v/, '').split('.').map((n) => Number.parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function updateArches(os, arch, name) {
  if (arch === 'universal') return ['arm64', 'amd64'];
  if (arch) return [arch];
  // The universal APK bundles arm64, armv7 and x86_64. Devices report arm64 or amd64; other ABIs send
  // an empty arch, which the update check matches against any current Android release.
  if (os === 'android') return ['arm64', 'amd64'];
  throw new Error(`${name}: desktop installers must include an architecture (amd64, arm64 or universal)`);
}

/**
 * Turns `gh release view --json tagName,url,isDraft,assets` output into the releases and
 * download links to register.
 */
export function buildPlan(release, { notes = '' } = {}) {
  const version = String(release.tagName ?? '').replace(/^v/, '');
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error(`release tag "${release.tagName}" is not vX.Y.Z`);
  if (release.isDraft) throw new Error(`release ${release.tagName} is still a draft; its download URLs are not public yet`);

  const installers = [];
  const ignored = [];
  for (const asset of release.assets ?? []) {
    const match = ASSET_RE.exec(asset.name);
    if (!match) {
      ignored.push(asset.name);
      continue;
    }
    const [, assetVersion, os, arch = '', ext] = match;
    if (assetVersion !== version) throw new Error(`${asset.name} does not belong to release ${version}`);
    if (asset.state && asset.state !== 'uploaded') throw new Error(`${asset.name} is not fully uploaded (${asset.state})`);
    if (!/^https:\/\//.test(asset.url ?? '')) throw new Error(`${asset.name} has no https download URL`);
    const platform = os.toLowerCase();
    const format = ext.toLowerCase();
    installers.push({
      name: asset.name,
      url: asset.url,
      platform,
      arch: arch.toLowerCase(),
      format,
      rank: FORMAT_RANK[format],
      targets: updateArches(platform, arch.toLowerCase(), asset.name).map((a) => ({
        platform: UPDATE_PLATFORM[platform],
        arch: a,
      })),
    });
  }
  if (installers.length === 0) throw new Error(`release ${release.tagName} has no installer assets`);

  const releases = new Map();
  for (const inst of installers) {
    for (const target of inst.targets) {
      const key = `${target.platform}/${target.arch}`;
      const best = releases.get(key);
      if (!best || inst.rank < best.rank) {
        releases.set(key, { key, ...target, download_url: inst.url, installer: inst.name, rank: inst.rank });
      }
    }
  }

  // A link is listed on the website while the release it is attached to is current. Multi-target
  // installers (e.g. the universal DMG) hang off their first target so they are listed once.
  const downloads = installers
    .map((inst) => ({
      name: inst.name,
      url: inst.url,
      platform: inst.platform,
      arch: inst.arch,
      format: inst.format,
      sort_order: inst.rank,
      release_key: `${inst.targets[0].platform}/${inst.targets[0].arch}`,
    }))
    .sort((a, b) => a.platform.localeCompare(b.platform) || a.sort_order - b.sort_order || a.name.localeCompare(b.name));

  return {
    version,
    tag: release.tagName,
    notes: oneLine(notes) || `See what's new in cpmesh ${version}: ${release.url}`,
    releases: [...releases.values()].map(({ rank: _rank, ...r }) => r),
    downloads,
    ignored,
  };
}

function oneLine(text) {
  return String(text ?? '').replace(/\s+/g, ' ').trim().slice(0, 300);
}

/** Minimal client for the cpmesh REST API. */
export function createApi(baseUrl, { fetch: fetchImpl = globalThis.fetch } = {}) {
  let token = null;

  async function call(method, pathname, { body, auth = true } = {}) {
    const headers = { Accept: 'application/json', 'User-Agent': 'cpmesh-release-publisher' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (auth) {
      if (!token) throw new Error('not logged in');
      headers.Authorization = `Bearer ${token}`;
    }
    const url = new URL(pathname, baseUrl);
    let res;
    try {
      res = await fetchImpl(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: 'error',
      });
    } catch (err) {
      throw new Error(`${method} ${url.pathname} failed: ${err.cause?.message ?? err.message}`);
    }
    const text = await res.text();
    let data;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = undefined;
    }
    if (!res.ok) {
      const detail =
        data?.message ?? data?.error ?? `${res.headers.get('content-type') ?? 'no content type'}: ${text.slice(0, 120)}`;
      throw new Error(`${method} ${url.pathname} returned HTTP ${res.status} (${detail})`);
    }
    if (data === undefined) {
      throw new Error(
        `${method} ${url.pathname} returned ${res.headers.get('content-type') ?? 'non-JSON content'} instead of JSON; ` +
          'check that the URL points at a cpmesh server and that no proxy or bot challenge intercepts the request',
      );
    }
    return data;
  }

  return {
    async login(username, password) {
      const data = await call('POST', '/api/auth/login', { body: { username, password }, auth: false });
      if (typeof data?.access_token !== 'string' || !data.access_token) {
        throw new Error('login succeeded but returned no access token');
      }
      token = data.access_token;
      return token;
    },
    get: (pathname, options) => call('GET', pathname, options),
    post: (pathname, body) => call('POST', pathname, { body }),
    put: (pathname, body) => call('PUT', pathname, { body }),
  };
}

/** Creates or updates the releases and download links. Safe to run repeatedly for one version. */
export async function publishPlan(plan, api, { force = false, log = () => {} } = {}) {
  const existingReleases = await api.get('/api/admin/releases');

  for (const target of plan.releases) {
    const current = existingReleases.find(
      (r) => r.is_current && r.platform === target.platform && r.arch === target.arch,
    );
    if (current && compareVersions(current.version, plan.version) > 0 && !force) {
      throw new Error(
        `${target.platform}/${target.arch} already offers ${current.version}, newer than ${plan.version}; ` +
          'pass --force to roll back',
      );
    }
  }

  const releaseIds = new Map();
  for (const target of plan.releases) {
    const body = {
      version: plan.version,
      platform: target.platform,
      arch: target.arch,
      download_url: target.download_url,
      release_notes: plan.notes,
      is_current: true,
    };
    const existing = existingReleases.find(
      (r) => r.version === plan.version && r.platform === target.platform && r.arch === target.arch,
    );
    const saved = existing
      ? await api.put(`/api/admin/releases/${existing.id}`, body)
      : await api.post('/api/admin/releases', body);
    releaseIds.set(target.key, saved.id);
    log(`${existing ? 'Updated' : 'Created'} release ${plan.version} for ${target.key}`);
  }

  const existingLinks = await api.get('/api/admin/downloads');
  for (const download of plan.downloads) {
    const body = {
      name: download.name,
      url: download.url,
      platform: download.platform,
      arch: download.arch,
      format: download.format,
      sort_order: download.sort_order,
      is_active: true,
      release_id: releaseIds.get(download.release_key),
    };
    const existing = existingLinks.find((l) => l.url === download.url);
    if (existing) await api.put(`/api/admin/downloads/${existing.id}`, body);
    else await api.post('/api/admin/downloads', body);
    log(`${existing ? 'Updated' : 'Created'} download link ${download.name}`);
  }
}

/** Reads the public endpoints back to confirm the website and update check serve the release. */
export async function verifyPublished(plan, api) {
  const listed = new Set((await api.get('/api/downloads/current', { auth: false })).map((l) => l.url));
  const missing = plan.downloads.filter((d) => !listed.has(d.url)).map((d) => d.name);
  if (missing.length) throw new Error(`not listed by /api/downloads/current: ${missing.join(', ')}`);

  for (const target of plan.releases) {
    const query = new URLSearchParams({ platform: target.platform, arch: target.arch, version: '0.0.0' });
    const check = await api.get(`/api/updates/check?${query}`, { auth: false });
    if (!check.update_available || check.version !== plan.version || check.download_url !== target.download_url) {
      throw new Error(`/api/updates/check for ${target.key} returned ${JSON.stringify(check)}`);
    }
  }
}

/** Confirms every installer URL resolves (GitHub answers with a redirect to the file). */
export async function checkDownloadUrls(plan, fetchImpl = globalThis.fetch, { attempts = 4, delayMs = 5000 } = {}) {
  for (const d of plan.downloads) {
    // Retry briefly: a just-published release's download URLs can take a moment to resolve
    for (let attempt = 1; ; attempt++) {
      let status;
      try {
        status = (await fetchImpl(d.url, { method: 'HEAD', redirect: 'manual' })).status;
      } catch (err) {
        if (attempt >= attempts) throw new Error(`${d.name}: ${err.cause?.message ?? err.message}`);
      }
      if (status === 200 || (status >= 300 && status < 400)) break;
      if (status !== undefined && attempt >= attempts) {
        throw new Error(`${d.name} is not downloadable yet (HTTP ${status} for ${d.url})`);
      }
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
}

export function checkBaseUrl(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`CPMESH_URL "${raw}" is not a valid URL`);
  }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) {
    throw new Error('CPMESH_URL must use https (http is only allowed for localhost)');
  }
  return `${url.origin}/`;
}

export function formatPlan(plan) {
  const lines = [`cpmesh ${plan.version}: ${plan.downloads.length} installers`, '', 'Website download links:'];
  for (const d of plan.downloads) {
    lines.push(`  ${d.platform.padEnd(8)} ${(d.arch || '-').padEnd(10)} ${d.format.padEnd(9)} ${d.name}`);
  }
  lines.push('', 'Update check targets:');
  for (const r of plan.releases) lines.push(`  ${r.key.padEnd(16)} -> ${r.installer}`);
  if (plan.ignored.length) lines.push('', `Ignored assets: ${plan.ignored.join(', ')}`);
  lines.push('', `Release notes: ${plan.notes}`);
  return lines.join('\n');
}

function summaryMarkdown(plan, baseUrl) {
  const rows = plan.downloads.map((d) => `| [${d.name}](${d.url}) | ${d.platform} | ${d.arch || '—'} | ${d.format} |`);
  const targets = plan.releases.map((r) => `\`${r.key}\``).join(', ');
  return [
    `### Website updated`,
    '',
    `cpmesh ${plan.version} is now offered on ${baseUrl} and by the in-app update check (${targets}).`,
    '',
    '| Installer | Platform | Arch | Format |',
    '| --- | --- | --- | --- |',
    ...rows,
    '',
  ].join('\n');
}

function escapeAnnotation(text) {
  return String(text).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function warn(title, message) {
  console.log(IN_ACTIONS ? `::warning title=${title}::${escapeAnnotation(message)}` : `warning: ${message}`);
}

async function main() {
  const { values } = parseArgs({
    options: {
      release: { type: 'string' },
      notes: { type: 'string', default: '' },
      'dry-run': { type: 'boolean', default: false },
      force: { type: 'boolean', default: false },
      'skip-url-check': { type: 'boolean', default: false },
    },
  });
  if (!values.release) {
    console.error('Usage: node scripts/release/publish-website.mjs --release <gh-release.json> [--notes <text>] [--dry-run]');
    process.exitCode = 2;
    return;
  }

  const plan = buildPlan(JSON.parse(await readFile(values.release, 'utf8')), { notes: values.notes });
  console.log(formatPlan(plan));
  if (values['dry-run']) return;

  const { CPMESH_ADMIN_USERNAME: username, CPMESH_ADMIN_PASSWORD: password } = process.env;
  if (!username || !password) {
    warn(
      'Website not updated',
      'CPMESH_ADMIN_USERNAME and CPMESH_ADMIN_PASSWORD are not set, so the release was not registered on the website.',
    );
    return;
  }
  const baseUrl = checkBaseUrl(process.env.CPMESH_URL || 'https://cpmesh.com');

  if (!values['skip-url-check']) await checkDownloadUrls(plan);

  const api = createApi(baseUrl);
  const token = await api.login(username, password);
  if (IN_ACTIONS) console.log(`::add-mask::${token}`);

  console.log(`\nPublishing to ${baseUrl}`);
  await publishPlan(plan, api, { force: values.force, log: (line) => console.log(`  ${line}`) });
  await verifyPublished(plan, api);
  console.log(`Verified: ${baseUrl} lists the installers and offers ${plan.version} to the apps.`);

  if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, summaryMarkdown(plan, baseUrl));
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((err) => {
    console.error(IN_ACTIONS ? `::error title=Website update failed::${escapeAnnotation(err.message)}` : `error: ${err.message}`);
    // Not process.exit(): exiting while fetch sockets are still closing can abort Node on Windows
    process.exitCode = 1;
  });
}
