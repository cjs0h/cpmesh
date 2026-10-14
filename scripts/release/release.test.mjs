// Tests for the release scripts: node --test "scripts/release/*.test.mjs"
import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  buildPlan,
  checkBaseUrl,
  checkDownloadUrls,
  compareVersions,
  createApi,
  formatPlan,
  publishPlan,
  verifyPublished,
} from './publish-website.mjs';
import {
  setCargoLockVersion,
  setCargoPackageVersion,
  setJsonVersions,
  setVersion,
  versionEdits,
} from './set-version.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

function asset(name, version = '0.2.0') {
  return { name, state: 'uploaded', url: `https://github.com/cjs0h/cpmesh/releases/download/v${version}/${name}` };
}

function release(version, names, extra = {}) {
  return {
    tagName: `v${version}`,
    url: `https://github.com/cjs0h/cpmesh/releases/tag/v${version}`,
    isDraft: false,
    assets: names.map((n) => asset(n, version)),
    ...extra,
  };
}

const ALL_INSTALLERS = (v) => [
  `cpmesh-${v}-windows-amd64-setup.exe`,
  `cpmesh-${v}-macos-universal.dmg`,
  `cpmesh-${v}-linux-amd64.deb`,
  `cpmesh-${v}-linux-amd64.AppImage`,
  `cpmesh-${v}-android.apk`,
];

/** In-memory stand-in for the cpmesh admin and public release APIs. */
class FakeCpmesh {
  constructor({ password = 'secret' } = {}) {
    this.password = password;
    this.releases = [];
    this.links = [];
    this.calls = [];
    this.nextId = 1;
    this.fetch = this.fetch.bind(this);
  }

  json(status, data) {
    return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });
  }

  // Mirrors the server: marking a release current unsets the others for the same platform/arch.
  makeCurrent(rel) {
    if (!rel.is_current) return;
    for (const other of this.releases) {
      if (other !== rel && other.platform === rel.platform && other.arch === rel.arch) other.is_current = false;
    }
  }

  async fetch(input, init = {}) {
    const url = new URL(input);
    const method = init.method ?? 'GET';
    const body = init.body ? JSON.parse(init.body) : undefined;
    this.calls.push(`${method} ${url.pathname}`);

    if (method === 'POST' && url.pathname === '/api/auth/login') {
      return body.username === 'admin' && body.password === this.password
        ? this.json(200, { access_token: 'access-token', refresh_token: 'refresh', user_id: 'u1' })
        : this.json(401, { error: 'invalid credentials' });
    }
    if (url.pathname.startsWith('/api/admin/') && init.headers?.Authorization !== 'Bearer access-token') {
      return this.json(401, { error: 'missing authorization token' });
    }

    const releaseId = url.pathname.match(/^\/api\/admin\/releases\/(.+)$/)?.[1];
    const linkId = url.pathname.match(/^\/api\/admin\/downloads\/(.+)$/)?.[1];
    if (method === 'GET' && url.pathname === '/api/admin/releases') return this.json(200, this.releases);
    if (method === 'POST' && url.pathname === '/api/admin/releases') {
      const rel = { id: `r${this.nextId++}`, ...body };
      this.releases.push(rel);
      this.makeCurrent(rel);
      return this.json(201, rel);
    }
    if (method === 'PUT' && releaseId) {
      const rel = this.releases.find((r) => r.id === releaseId);
      if (!rel) return this.json(500, { error: 'failed to update release' });
      Object.assign(rel, body);
      this.makeCurrent(rel);
      return this.json(200, rel);
    }
    if (method === 'GET' && url.pathname === '/api/admin/downloads') return this.json(200, this.links);
    if (method === 'POST' && url.pathname === '/api/admin/downloads') {
      const link = { id: `d${this.nextId++}`, ...body };
      this.links.push(link);
      return this.json(201, link);
    }
    if (method === 'PUT' && linkId) {
      const link = this.links.find((l) => l.id === linkId);
      if (!link) return this.json(500, { error: 'failed to update download link' });
      Object.assign(link, body);
      return this.json(200, link);
    }
    if (method === 'GET' && url.pathname === '/api/downloads/current') {
      const current = new Set(this.releases.filter((r) => r.is_current).map((r) => r.id));
      return this.json(
        200,
        this.links.filter((l) => l.is_active && current.has(l.release_id)),
      );
    }
    if (method === 'GET' && url.pathname === '/api/updates/check') {
      const platform = url.searchParams.get('platform');
      const arch = url.searchParams.get('arch');
      const version = url.searchParams.get('version');
      const rel = this.releases.find((r) => r.platform === platform && r.is_current && (!arch || r.arch === arch));
      if (!rel) return this.json(200, { update_available: false });
      return this.json(200, {
        update_available: rel.version !== version && compareVersions(rel.version, version) > 0,
        version: rel.version,
        download_url: rel.download_url,
        release_notes: rel.release_notes,
      });
    }
    return this.json(404, { error: 'not found' });
  }
}

async function publishWith(server, plan, options) {
  const api = createApi('https://cpmesh.test/', { fetch: server.fetch });
  await api.login('admin', server.password);
  await publishPlan(plan, api, options);
  await verifyPublished(plan, api);
  return api;
}

describe('buildPlan', () => {
  it('maps installers to website links and update targets', () => {
    const plan = buildPlan(release('0.2.0', [...ALL_INSTALLERS('0.2.0'), 'SHA256SUMS.txt']));
    assert.equal(plan.version, '0.2.0');
    assert.deepEqual(plan.ignored, ['SHA256SUMS.txt']);
    assert.deepEqual(
      plan.releases.map((r) => [r.key, r.installer]),
      [
        ['windows/amd64', 'cpmesh-0.2.0-windows-amd64-setup.exe'],
        ['darwin/arm64', 'cpmesh-0.2.0-macos-universal.dmg'],
        ['darwin/amd64', 'cpmesh-0.2.0-macos-universal.dmg'],
        ['linux/amd64', 'cpmesh-0.2.0-linux-amd64.deb'],
        ['android/arm64', 'cpmesh-0.2.0-android.apk'],
        ['android/amd64', 'cpmesh-0.2.0-android.apk'],
      ],
    );
    assert.deepEqual(
      plan.downloads.map((d) => [d.name, d.platform, d.arch, d.format, d.sort_order, d.release_key]),
      [
        ['cpmesh-0.2.0-android.apk', 'android', '', 'apk', 0, 'android/arm64'],
        ['cpmesh-0.2.0-linux-amd64.deb', 'linux', 'amd64', 'deb', 0, 'linux/amd64'],
        ['cpmesh-0.2.0-linux-amd64.AppImage', 'linux', 'amd64', 'appimage', 1, 'linux/amd64'],
        ['cpmesh-0.2.0-macos-universal.dmg', 'macos', 'universal', 'dmg', 0, 'darwin/arm64'],
        ['cpmesh-0.2.0-windows-amd64-setup.exe', 'windows', 'amd64', 'exe', 0, 'windows/amd64'],
      ],
    );
    assert.match(formatPlan(plan), /darwin\/amd64\s+-> cpmesh-0\.2\.0-macos-universal\.dmg/);
  });

  it('picks the preferred format as the update download regardless of asset order', () => {
    const plan = buildPlan(
      release('1.0.0', ['cpmesh-1.0.0-windows-amd64.msi', 'cpmesh-1.0.0-windows-amd64-setup.exe', 'cpmesh-1.0.0-linux-arm64.AppImage']),
    );
    assert.equal(plan.releases.find((r) => r.key === 'windows/amd64').installer, 'cpmesh-1.0.0-windows-amd64-setup.exe');
    // Without a .deb, the AppImage is the best Linux installer
    assert.equal(plan.releases.find((r) => r.key === 'linux/arm64').installer, 'cpmesh-1.0.0-linux-arm64.AppImage');
    assert.deepEqual(
      plan.downloads.filter((d) => d.platform === 'windows').map((d) => d.format),
      ['exe', 'msi'],
    );
  });

  it('uses a one-line note, defaulting to a link to the release', () => {
    assert.equal(
      buildPlan(release('0.2.0', ALL_INSTALLERS('0.2.0'))).notes,
      "See what's new in cpmesh 0.2.0: https://github.com/cjs0h/cpmesh/releases/tag/v0.2.0",
    );
    assert.equal(
      buildPlan(release('0.2.0', ALL_INSTALLERS('0.2.0')), { notes: '  Faster sync\nand file previews  ' }).notes,
      'Faster sync and file previews',
    );
  });

  it('rejects releases that cannot be published', () => {
    assert.throws(() => buildPlan(release('0.2.0', ALL_INSTALLERS('0.2.0'), { isDraft: true })), /still a draft/);
    assert.throws(() => buildPlan(release('0.2.0', [], { tagName: 'nightly' })), /not vX\.Y\.Z/);
    assert.throws(() => buildPlan(release('0.2.0', ['notes.txt'])), /no installer assets/);
    assert.throws(
      () => buildPlan(release('0.2.0', ['cpmesh-0.1.9-linux-amd64.deb'])),
      /does not belong to release 0\.2\.0/,
    );
    assert.throws(() => buildPlan(release('0.2.0', ['cpmesh-0.2.0-windows-setup.exe'])), /must include an architecture/);
    const partial = release('0.2.0', ['cpmesh-0.2.0-android.apk']);
    partial.assets[0].state = 'starter';
    assert.throws(() => buildPlan(partial), /not fully uploaded/);
  });
});

describe('publishPlan', () => {
  it('registers releases and links, then serves them publicly', async () => {
    const server = new FakeCpmesh();
    const plan = buildPlan(release('0.2.0', ALL_INSTALLERS('0.2.0')), { notes: 'First release' });
    await publishWith(server, plan);

    assert.equal(server.releases.length, 6);
    assert.ok(server.releases.every((r) => r.is_current && r.version === '0.2.0' && r.release_notes === 'First release'));
    assert.equal(server.links.length, 5);
    const dmg = server.links.find((l) => l.format === 'dmg');
    assert.equal(dmg.platform, 'macos');
    assert.equal(server.releases.find((r) => r.id === dmg.release_id).platform, 'darwin');
  });

  it('is idempotent when re-run for the same version', async () => {
    const server = new FakeCpmesh();
    const plan = buildPlan(release('0.2.0', ALL_INSTALLERS('0.2.0')));
    await publishWith(server, plan);
    server.calls.length = 0;
    await publishWith(server, plan);

    assert.equal(server.releases.length, 6);
    assert.equal(server.links.length, 5);
    assert.ok(!server.calls.some((c) => c.startsWith('POST /api/admin/')), server.calls.join('\n'));
  });

  it('replaces the previous version on the website and in the update check', async () => {
    const server = new FakeCpmesh();
    await publishWith(server, buildPlan(release('0.2.0', ALL_INSTALLERS('0.2.0'))));
    await publishWith(server, buildPlan(release('0.3.0', ALL_INSTALLERS('0.3.0'))));

    assert.equal(server.releases.filter((r) => r.is_current).length, 6);
    assert.ok(server.releases.filter((r) => r.version === '0.2.0').every((r) => !r.is_current));
    const listed = (await (await server.fetch('https://cpmesh.test/api/downloads/current')).json()).map((l) => l.name);
    assert.deepEqual(listed.sort(), [...ALL_INSTALLERS('0.3.0')].sort());
  });

  it('refuses to roll back to an older version unless forced', async () => {
    const server = new FakeCpmesh();
    await publishWith(server, buildPlan(release('0.3.0', ALL_INSTALLERS('0.3.0'))));
    const older = buildPlan(release('0.2.0', ALL_INSTALLERS('0.2.0')));
    await assert.rejects(publishWith(server, older), /already offers 0\.3\.0, newer than 0\.2\.0/);
    assert.equal(server.releases.length, 6, 'nothing was written');

    await publishWith(server, older, { force: true });
    assert.ok(server.releases.filter((r) => r.is_current).every((r) => r.version === '0.2.0'));
  });

  it('verifyPublished reports links the website does not list', async () => {
    const server = new FakeCpmesh();
    const plan = buildPlan(release('0.2.0', ALL_INSTALLERS('0.2.0')));
    const api = await publishWith(server, plan);
    server.links.find((l) => l.format === 'apk').is_active = false;
    await assert.rejects(verifyPublished(plan, api), /cpmesh-0\.2\.0-android\.apk/);
  });
});

describe('createApi', () => {
  const respond = (status, body, type = 'application/json') => async () =>
    new Response(body, { status, headers: { 'content-type': type } });

  it('reports the server error message', async () => {
    const api = createApi('https://cpmesh.test/', { fetch: respond(401, '{"error":"invalid credentials"}') });
    await assert.rejects(api.login('admin', 'wrong'), /POST \/api\/auth\/login returned HTTP 401 \(invalid credentials\)/);
  });

  it('explains non-JSON responses such as proxy challenges', async () => {
    const challenge = createApi('https://cpmesh.test/', { fetch: respond(403, '<html>Just a moment...</html>', 'text/html') });
    await assert.rejects(challenge.login('admin', 'pw'), /HTTP 403 \(text\/html: <html>Just a moment/);
    const notCpmesh = createApi('https://cpmesh.test/', { fetch: respond(200, '<html></html>', 'text/html') });
    await assert.rejects(notCpmesh.login('admin', 'pw'), /instead of JSON/);
  });

  it('wraps network failures and requires a login for admin calls', async () => {
    const api = createApi('https://cpmesh.test/', {
      fetch: async () => {
        throw new TypeError('fetch failed', { cause: new Error('getaddrinfo ENOTFOUND cpmesh.test') });
      },
    });
    await assert.rejects(api.get('/api/downloads/current', { auth: false }), /ENOTFOUND/);
    await assert.rejects(api.get('/api/admin/releases'), /not logged in/);
  });

  it('sends the bearer token after logging in, and never follows redirects', async () => {
    const seen = [];
    const api = createApi('https://cpmesh.test/', {
      fetch: async (url, init) => {
        seen.push(init);
        return new Response('{"access_token":"t0k"}', { status: 200, headers: { 'content-type': 'application/json' } });
      },
    });
    await api.login('admin', 'pw');
    await api.get('/api/admin/releases');
    assert.equal(seen[0].headers.Authorization, undefined);
    assert.equal(seen[1].headers.Authorization, 'Bearer t0k');
    assert.ok(seen.every((init) => init.redirect === 'error'));
  });
});

describe('helpers', () => {
  it('compareVersions orders numerically', () => {
    assert.ok(compareVersions('0.10.0', '0.9.9') > 0);
    assert.ok(compareVersions('v1.0.0', '1.0.1') < 0);
    assert.equal(compareVersions('1.2.3', '1.2.3'), 0);
  });

  it('checkBaseUrl requires https except on localhost', () => {
    assert.equal(checkBaseUrl('https://cpmesh.com'), 'https://cpmesh.com/');
    assert.equal(checkBaseUrl('http://localhost:39271/some/path'), 'http://localhost:39271/');
    assert.throws(() => checkBaseUrl('http://cpmesh.com'), /must use https/);
    assert.throws(() => checkBaseUrl('cpmesh.com'), /not a valid URL/);
  });

  it('checkDownloadUrls accepts redirects, retries briefly and rejects missing files', async () => {
    const plan = buildPlan(release('0.2.0', ['cpmesh-0.2.0-android.apk']));
    const fast = { attempts: 3, delayMs: 0 };
    await checkDownloadUrls(plan, async () => new Response(null, { status: 302 }), fast);

    const statuses = [404, 302];
    let calls = 0;
    await checkDownloadUrls(plan, async () => new Response(null, { status: statuses[calls++] }), fast);
    assert.equal(calls, 2, 'a 404 right after publishing is retried');

    calls = 0;
    await assert.rejects(
      checkDownloadUrls(plan, async () => (calls++, new Response(null, { status: 404 })), fast),
      /cpmesh-0\.2\.0-android\.apk is not downloadable yet \(HTTP 404/,
    );
    assert.equal(calls, 3);
    await assert.rejects(
      checkDownloadUrls(plan, async () => { throw new TypeError('fetch failed', { cause: new Error('ECONNRESET') }); }, fast),
      /cpmesh-0\.2\.0-android\.apk: ECONNRESET/,
    );
  });
});

describe('set-version', () => {
  it('setJsonVersions replaces the requested number of keys', () => {
    const text = '{\n  "version": "0.1.0",\n  "packages": { "": { "version": "0.1.0" }, "dep": { "version": "9.9.9" } }\n}\n';
    const out = setJsonVersions(text, '1.2.3', 2);
    assert.deepEqual(JSON.parse(out), {
      version: '1.2.3',
      packages: { '': { version: '1.2.3' }, dep: { version: '9.9.9' } },
    });
    assert.throws(() => setJsonVersions('{"name":"x"}', '1.2.3', 1), /expected 1 "version" keys, found 0/);
  });

  it('setCargoPackageVersion only touches [package] and keeps line endings', () => {
    const toml = '[lib]\r\nversion = "lib"\r\n\r\n[package]\r\nname = "x"\r\nversion = "0.1.0"\r\n\r\n[dependencies]\r\nserde = { version = "1" }\r\n';
    assert.equal(
      setCargoPackageVersion(toml, '2.0.0'),
      toml.replace('version = "0.1.0"', 'version = "2.0.0"'),
    );
    assert.throws(() => setCargoPackageVersion('[package]\nversion.workspace = true\n', '1.0.0'), /no version/);
  });

  it('setCargoLockVersion updates exactly one package entry', () => {
    const lock = '[[package]]\nname = "cpmesh-desktop"\nversion = "0.1.0"\n\n[[package]]\nname = "cpmesh-desktop-helper"\nversion = "0.1.0"\n';
    assert.equal(
      setCargoLockVersion(lock, 'cpmesh-desktop', '0.2.0'),
      lock.replace('"cpmesh-desktop"\nversion = "0.1.0"', '"cpmesh-desktop"\nversion = "0.2.0"'),
    );
    assert.throws(() => setCargoLockVersion(lock, 'missing', '0.2.0'), /found 0/);
  });

  it('updates the real manifests and nothing else', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'cpmesh-set-version-'));
    try {
      const files = versionEdits('0.0.0').map(([relative]) => relative);
      for (const relative of files) await cp(path.join(REPO_ROOT, relative), path.join(dir, relative));

      const changed = await setVersion(dir, '9.8.7');
      assert.deepEqual(changed, files);
      assert.deepEqual(await setVersion(dir, '9.8.7'), [], 'second run is a no-op');

      const expectedLineChanges = { 'desktop-tauri/package-lock.json': 2 };
      for (const relative of files) {
        const before = (await readFile(path.join(REPO_ROOT, relative), 'utf8')).split(/\r?\n/);
        const after = (await readFile(path.join(dir, relative), 'utf8')).split(/\r?\n/);
        assert.equal(after.length, before.length, relative);
        const diffs = after.filter((line, i) => line !== before[i]);
        assert.equal(diffs.length, expectedLineChanges[relative] ?? 1, `${relative}: ${diffs.join(' | ')}`);
        assert.ok(diffs.every((line) => line.includes('9.8.7')), relative);
      }
      const conf = JSON.parse(await readFile(path.join(dir, 'desktop-tauri/src-tauri/tauri.conf.json'), 'utf8'));
      assert.equal(conf.version, '9.8.7');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('rejects versions that are not x.y.z', async () => {
    await assert.rejects(setVersion(REPO_ROOT, '1.2.3-beta.1'), /must look like 1\.2\.3/);
  });
});
