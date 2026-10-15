// Tests for the updater signature check: node --test "scripts/release/*.test.mjs"
//
// The fixtures were made with `tauri signer generate` and `tauri signer sign --app-version 9.9.9`
// (test keys only); the desktop app's updater tests use the same ones.
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';

import { verifyInstaller, verifySignature } from './verify-signature.mjs';

const PUBLIC_KEY =
  'dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDE4OUE3NzlDRDkzQzdCN0YKUldSL2V6elpuSGVhR09QU0JUQ1NPb2ViQjczQ28xRFNMcU5yaG9BdVQyT3oya1JPOW8vYkZxR3IK';
const OTHER_PUBLIC_KEY =
  'dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDE5OEYzNkUzNDBEREI5ODcKUldTSHVkMUE0emFQR2VnWWpJWkl4TTFEUmpJanBtODF4Q0tRNVZEVUV6ZXdURjNvbTlWVVdMNGsK';
const INSTALLER = Buffer.from('cpmesh test installer\n');
const INSTALLER_NAME = 'cpmesh-9.9.9-windows-amd64-setup.exe';
const SIGNATURE =
  'dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVSL2V6elpuSGVhR09sYXRLUFAvajZnNGpYYzA1elVrdnkydENvelVzTjZHb092aW50bGVrUk1LL0NibXJMYU9xbkRmWjNNLzRYNEV2L2VnNjRESlJFV2tNaUNvN243bEE0PQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzkyMDQzMjYxCWZpbGU6Y3BtZXNoLTkuOS45LXdpbmRvd3MtYW1kNjQtc2V0dXAuZXhlCXZlcnNpb246OS45LjkKK2hYYUcySkV4aTNkRU53dVZoMndxZFRoNThLME9uMFZHYnNrU0IrQnBoRll0T0JhTVozb0M4clNJTi90K1daSzhrWUdHM25WR01XSDhZTVJ5eHVUQ3c9PQo=';

describe('verifySignature', () => {
  it('accepts a valid signature and returns its signed fields', () => {
    const fields = verifySignature(INSTALLER, SIGNATURE, PUBLIC_KEY);
    assert.equal(fields.file, INSTALLER_NAME);
    assert.equal(fields.version, '9.9.9');
    assert.match(fields.timestamp, /^\d+$/);
  });

  it('rejects a modified file', () => {
    assert.throws(
      () => verifySignature(Buffer.from('cpmesh test installer!\n'), SIGNATURE, PUBLIC_KEY),
      /does not match the file/,
    );
  });

  it('rejects a signature made with another key', () => {
    assert.throws(() => verifySignature(INSTALLER, SIGNATURE, OTHER_PUBLIC_KEY), /different key/);
  });

  it('rejects an altered trusted comment', () => {
    const text = Buffer.from(SIGNATURE, 'base64').toString('utf8').replace('version:9.9.9', 'version:9.9.10');
    const forged = Buffer.from(text, 'utf8').toString('base64');
    assert.throws(() => verifySignature(INSTALLER, forged, PUBLIC_KEY), /trusted comment was altered/);
  });

  it('rejects malformed keys and signatures', () => {
    assert.throws(() => verifySignature(INSTALLER, 'Z2FyYmFnZQ==', PUBLIC_KEY), /not a minisign signature/);
    assert.throws(() => verifySignature(INSTALLER, SIGNATURE, ''), /not a minisign public key/);
  });
});

describe('verifyInstaller', () => {
  async function withInstaller(name, fn) {
    const dir = await mkdtemp(path.join(tmpdir(), 'cpmesh-sig-'));
    try {
      const file = path.join(dir, name);
      const publicKeyPath = path.join(dir, 'updater-key.pub');
      await writeFile(file, INSTALLER);
      await writeFile(`${file}.sig`, SIGNATURE);
      await writeFile(publicKeyPath, `${PUBLIC_KEY}\n`);
      await fn(file, publicKeyPath);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }

  it('accepts an installer signed for this release under its own name', async () => {
    await withInstaller(INSTALLER_NAME, async (file, publicKeyPath) => {
      const fields = await verifyInstaller(file, { publicKeyPath, version: '9.9.9' });
      assert.equal(fields.version, '9.9.9');
    });
  });

  it('rejects a signature made for another version', async () => {
    await withInstaller(INSTALLER_NAME, async (file, publicKeyPath) => {
      await assert.rejects(verifyInstaller(file, { publicKeyPath, version: '9.9.10' }), /signed for version 9\.9\.9/);
    });
  });

  it('rejects a signature made for another file', async () => {
    await withInstaller('cpmesh-9.9.9-linux-amd64.deb', async (file, publicKeyPath) => {
      await assert.rejects(verifyInstaller(file, { publicKeyPath, version: '9.9.9' }), /is signed as/);
    });
  });
});
