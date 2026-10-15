#!/usr/bin/env node
/**
 * Checks installers' updater signatures against the public key the apps are built with, so
 * a release is never published with signatures the apps would reject.
 *
 *   node scripts/release/verify-signature.mjs --public-key desktop-tauri/src-tauri/updater-key.pub \
 *     --version 1.2.3 dist/cpmesh-1.2.3-linux-amd64.deb [...]
 *
 * Each installer's signature is read from <installer>.sig. Keys and signatures use the format
 * `tauri signer` writes: base64 of minisign's text format. Like the apps, this accepts only
 * prehashed (BLAKE2b-512) Ed25519 signatures whose trusted comment names the file and version.
 */
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

// DER prefix of an Ed25519 SubjectPublicKeyInfo; the raw 32-byte key follows it.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const TRUSTED_PREFIX = 'trusted comment: ';

function decodeLines(encoded) {
  return Buffer.from(String(encoded).trim(), 'base64').toString('utf8').split('\n');
}

/** Parses a `tauri signer` public key. */
export function parsePublicKey(encoded) {
  const bin = Buffer.from((decodeLines(encoded)[1] ?? '').trim(), 'base64');
  if (bin.length !== 42 || bin.subarray(0, 2).toString('latin1') !== 'Ed') {
    throw new Error('not a minisign public key');
  }
  return {
    keyId: bin.subarray(2, 10),
    key: createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, bin.subarray(10, 42)]),
      format: 'der',
      type: 'spki',
    }),
  };
}

/** Parses a `tauri signer` signature. */
export function parseSignature(encoded) {
  const lines = decodeLines(encoded);
  const bin = Buffer.from((lines[1] ?? '').trim(), 'base64');
  const trusted = lines[2] ?? '';
  const globalSignature = Buffer.from((lines[3] ?? '').trim(), 'base64');
  if (bin.length !== 74 || globalSignature.length !== 64 || !trusted.startsWith(TRUSTED_PREFIX)) {
    throw new Error('not a minisign signature');
  }
  if (bin.subarray(0, 2).toString('latin1') !== 'ED') {
    throw new Error('only prehashed signatures are supported');
  }
  return {
    keyId: bin.subarray(2, 10),
    signature: bin.subarray(10, 74),
    trustedComment: trusted.slice(TRUSTED_PREFIX.length),
    globalSignature,
  };
}

/** Verifies `data` against a signature and returns the signed trusted-comment fields. */
export function verifySignature(data, signatureText, publicKeyText) {
  const publicKey = parsePublicKey(publicKeyText);
  const sig = parseSignature(signatureText);
  if (!publicKey.keyId.equals(sig.keyId)) {
    throw new Error('signed with a different key than the one the apps trust');
  }
  const digest = createHash('blake2b512').update(data).digest();
  if (!verify(null, digest, publicKey.key, sig.signature)) {
    throw new Error('the signature does not match the file');
  }
  const signedComment = Buffer.concat([sig.signature, Buffer.from(sig.trustedComment, 'utf8')]);
  if (!verify(null, signedComment, publicKey.key, sig.globalSignature)) {
    throw new Error('the trusted comment was altered');
  }
  return Object.fromEntries(
    sig.trustedComment.split('\t').map((field) => {
      const colon = field.indexOf(':');
      return colon < 0 ? [field, ''] : [field.slice(0, colon), field.slice(colon + 1)];
    }),
  );
}

/** Verifies `<file>.sig` for `file` and that it was signed for `version` under the file's name. */
export async function verifyInstaller(file, { publicKeyPath, version }) {
  const [data, signature, publicKey] = await Promise.all([
    readFile(file),
    readFile(`${file}.sig`, 'utf8'),
    readFile(publicKeyPath, 'utf8'),
  ]);
  const name = path.basename(file);
  const fields = verifySignature(data, signature, publicKey);
  if (fields.version !== version) {
    throw new Error(`${name} is signed for version ${fields.version || '(none)'}, not ${version}`);
  }
  if (fields.file !== name) {
    throw new Error(`${name} is signed as ${fields.file || '(no file name)'}`);
  }
  return fields;
}

async function main() {
  const { values, positionals } = parseArgs({
    options: { 'public-key': { type: 'string' }, version: { type: 'string' } },
    allowPositionals: true,
  });
  if (!values['public-key'] || !values.version || positionals.length === 0) {
    console.error('usage: verify-signature.mjs --public-key <file> --version <x.y.z> <installer>...');
    process.exit(2);
  }
  for (const file of positionals) {
    await verifyInstaller(file, { publicKeyPath: values['public-key'], version: values.version });
    console.log(`${path.basename(file)}: signature OK`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(`error: ${err.message}`);
    process.exit(1);
  });
}
