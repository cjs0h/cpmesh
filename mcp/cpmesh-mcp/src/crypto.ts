/**
 * Byte-compatible TypeScript port of the cpmesh end-to-end encryption stack.
 *
 * Mirrors desktop-tauri/src-tauri/src/crypto/{keys,encrypt,exchange}.rs.
 * Compatibility with the Rust implementation is pinned by the golden
 * vectors in test/vectors.json (see vector-gen/ for the generator).
 *
 * Formats:
 * - HKDF-SHA256 with the exact info strings used by the Rust client
 * - ECDH shared secret = x-coordinate (32 bytes) of the P-256 shared point
 * - AES-256-GCM: nonce(12) || ciphertext || tag(16)
 * - Clipboard payload: salt(16) || nonce(12) || ciphertext || tag(16)
 * - Group key wrap: ECDH-derived key, salt "group-key-wrap"
 * - Keyring file: salt(16) || AES-GCM blob of the keyring JSON (KEK derived
 *   from the device private key, info "cpnet-keyring-v1")
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { p256 } from "@noble/curves/p256";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { readFileSync, writeFileSync, mkdirSync, existsSync, openSync, closeSync, fsyncSync, renameSync, rmSync } from "node:fs";
import { dirname } from "node:path";
import type { DeviceIdentity, StoreGroupKeyEntry } from "./protocol.js";
import { z } from "zod";

const INFO_SHARED = new TextEncoder().encode("cpmesh-clipboard-v1");
const INFO_GROUP = new TextEncoder().encode("cpmesh-group-v1");
const INFO_KEYRING = new TextEncoder().encode("cpnet-keyring-v1");
const INFO_APPROVAL = new TextEncoder().encode("cpmesh-pairing-fingerprint-v2");
const SALT_GROUP_KEY_WRAP = new TextEncoder().encode("group-key-wrap");

export class CryptoError extends Error {}

// === HKDF ===

function deriveKey(
  secret: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
): Uint8Array {
  return new Uint8Array(hkdf(sha256, secret, salt, info, 32));
}

/** Derives a shared AES-256 key from ECDH + HKDF (Rust: derive_shared_key). */
export function deriveSharedKey(
  privateKey: Uint8Array,
  peerPublicKey: Uint8Array,
  salt: Uint8Array,
): Uint8Array {
  const shared = p256.getSharedSecret(privateKey, peerPublicKey);
  // noble returns the 65-byte uncompressed point; the raw ECDH secret is the
  // x-coordinate, matching Rust's raw_secret_bytes().
  const x = shared.slice(1, 33);
  return deriveKey(x, salt, INFO_SHARED);
}

/** Derives an AES-256 key from a group key + salt (Rust: derive_key_from_group_key). */
export function deriveKeyFromGroupKey(
  groupKey: Uint8Array,
  salt: Uint8Array,
): Uint8Array {
  return deriveKey(groupKey, salt, INFO_GROUP);
}

/** Derives an AES-256 key from arbitrary secret material (Rust: derive_key_from_secret). */
export function deriveKeyFromSecret(
  secret: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
): Uint8Array {
  return deriveKey(secret, salt, info);
}

// === AES-256-GCM ===

/** AES-256-GCM encrypt with explicit nonce → ciphertext || tag. */
export function aesGcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return new Uint8Array(Buffer.concat([ct, tag]));
}

/** AES-256-GCM decrypt of ciphertext || tag with explicit nonce. */
export function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  if (data.length < 16) {
    throw new CryptoError("ciphertext too short");
  }
  const ct = data.subarray(0, data.length - 16);
  const tag = data.subarray(data.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return new Uint8Array(pt);
}

/** Encrypt with a random nonce → nonce(12) || ciphertext || tag. */
export function encrypt(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const nonce = new Uint8Array(randomBytes(12));
  const ct = aesGcmEncrypt(key, nonce, plaintext);
  const out = new Uint8Array(12 + ct.length);
  out.set(nonce, 0);
  out.set(ct, 12);
  return out;
}

/** Decrypt nonce(12) || ciphertext || tag. */
export function decrypt(key: Uint8Array, data: Uint8Array): Uint8Array {
  if (data.length < 12 + 16) {
    throw new CryptoError("ciphertext too short");
  }
  const nonce = data.subarray(0, 12);
  const ct = data.subarray(12);
  return aesGcmDecrypt(key, nonce, ct);
}

export function generateGroupKey(): Uint8Array {
  return new Uint8Array(randomBytes(32));
}

// === Group key wrapping (device-to-device) ===

export function encryptGroupKey(
  groupKey: Uint8Array,
  privateKey: Uint8Array,
  peerPublicKey: Uint8Array,
): Uint8Array {
  const shared = deriveSharedKey(privateKey, peerPublicKey, SALT_GROUP_KEY_WRAP);
  return encrypt(shared, groupKey);
}

export function decryptGroupKey(
  encryptedGroupKey: Uint8Array,
  privateKey: Uint8Array,
  peerPublicKey: Uint8Array,
): Uint8Array {
  const shared = deriveSharedKey(privateKey, peerPublicKey, SALT_GROUP_KEY_WRAP);
  return decrypt(shared, encryptedGroupKey);
}

// === Approval code ===

/**
 * Full 256-bit fingerprint: compare all characters on BOTH devices through an
 * independent trusted channel. This is not a short authentication-string protocol.
 */
export function deriveApprovalCode(
  ourPrivateKey: Uint8Array,
  peerPublicKey: Uint8Array,
  ourPublicKey: Uint8Array,
): string {
  const shared = p256.getSharedSecret(ourPrivateKey, peerPublicKey).slice(1, 33);
  // Salt = SHA-256 of the sorted concatenation of both public keys, so both
  // sides derive the same salt regardless of who is approver and who is pending.
  const a = ourPublicKey;
  const b = peerPublicKey;
  const combined =
    lexicographicCompare(a, b) <= 0 ? concat(a, b) : concat(b, a);
  const salt = sha256(combined);
  return Buffer.from(deriveKey(shared, salt, INFO_APPROVAL)).toString("hex").toUpperCase();
}

// === ECDSA public-key self-signature ===

function compactToDer(compact: Uint8Array): Uint8Array {
  const r = compact.subarray(0, 32);
  const s = compact.subarray(32, 64);
  const rDer = trimLeadingZeros(r);
  const sDer = trimLeadingZeros(s);
  const bodyLen = 2 + rDer.length + 2 + sDer.length;
  const out = new Uint8Array(2 + bodyLen);
  let i = 0;
  out[i++] = 0x30; // SEQUENCE
  out[i++] = bodyLen;
  out[i++] = 0x02; // INTEGER r
  out[i++] = rDer.length;
  out.set(rDer, i);
  i += rDer.length;
  out[i++] = 0x02; // INTEGER s
  out[i++] = sDer.length;
  out.set(sDer, i);
  return out;
}

function derToCompact(der: Uint8Array): Uint8Array {
  if (der.length === 64) return der;
  if (der[0] !== 0x30) throw new CryptoError("invalid DER signature");
  let i = 2; // skip SEQUENCE header (length < 128 is guaranteed here)
  if (der[i] !== 0x02) throw new CryptoError("invalid DER signature");
  const rLen = der[i + 1]!;
  let r = der.subarray(i + 2, i + 2 + rLen);
  i += 2 + rLen;
  if (der[i] !== 0x02) throw new CryptoError("invalid DER signature");
  const sLen = der[i + 1]!;
  let s = der.subarray(i + 2, i + 2 + sLen);
  // Strip sign-padding byte, then left-pad to 32 bytes.
  if (r[0] === 0) r = r.subarray(1);
  if (s[0] === 0) s = s.subarray(1);
  const compact = new Uint8Array(64);
  compact.set(r, 32 - r.length);
  compact.set(s, 64 - s.length);
  return compact;
}

function trimLeadingZeros(n: Uint8Array): Uint8Array {
  let i = 0;
  while (i < n.length - 1 && n[i] === 0) i++;
  // Preserve the sign bit: if the high bit is set, prepend a zero byte.
  const v = n.subarray(i);
  if (v[0]! & 0x80) {
    const padded = new Uint8Array(v.length + 1);
    padded.set(v, 1);
    return padded;
  }
  return v;
}

function normalizeSignature(raw: unknown): Uint8Array {
  if (raw instanceof Uint8Array) return raw;
  const sig = raw as { toCompactRawBytes?: () => Uint8Array };
  if (typeof sig.toCompactRawBytes === "function") {
    return sig.toCompactRawBytes();
  }
  throw new CryptoError("unsupported signature type");
}

// === Device key pair ===

const PEM_TAG = "ECDH PRIVATE KEY";

export class KeyPair {
  private constructor(
    readonly privateKey: Uint8Array,
    readonly publicKey: Uint8Array,
  ) {}

  static generate(): KeyPair {
    // Loop until randomBytes yields a valid P-256 scalar (virtually never loops).
    for (;;) {
      try {
        const priv = new Uint8Array(randomBytes(32));
        const pub = p256.getPublicKey(priv, false);
        return new KeyPair(priv, pub);
      } catch {
        // invalid scalar — retry
      }
    }
  }

  static fromPrivateKey(priv: Uint8Array): KeyPair {
    return new KeyPair(priv, p256.getPublicKey(priv, false));
  }

  /** Uncompressed SEC1 bytes (65 bytes, 0x04-prefixed). */
  publicKeyBytes(): Uint8Array {
    return this.publicKey;
  }

  static parsePublicKey(data: Uint8Array): Uint8Array {
    // Throws if invalid; returns the normalized uncompressed form.
    p256.getSharedSecret(
      new Uint8Array(32).fill(1),
      data,
    );
    return data;
  }

  /** ECDSA-P256-SHA256 signature over the public key bytes, DER-encoded. */
  signPublicKey(): Uint8Array {
    // Matches the Rust client: ECDSA over SHA256(pub_bytes), via noble's
    // prehash mode (which signs the provided digest as-is).
    const compact = normalizeSignature(
      p256.sign(sha256(this.publicKey), this.privateKey, { prehash: true }),
    );
    return compactToDer(compact);
  }

  signMessage(message: Uint8Array): Uint8Array {
    return compactToDer(normalizeSignature(p256.sign(message, this.privateKey, { prehash: true })));
  }

  signDeviceChallenge(challenge: string): string {
    return Buffer.from(this.signMessage(new TextEncoder().encode(`cpmesh-device-proof-v1\n${challenge}`))).toString("base64");
  }

  static verifyMessage(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
    try {
      return p256.verify(derToCompact(signature), message, publicKey, { prehash: true, lowS: false });
    } catch { return false; }
  }

  static verifyPublicKeySignature(
    publicKey: Uint8Array,
    signature: Uint8Array,
  ): boolean {
    try {
      const compact = derToCompact(signature);
      return p256.verify(compact, sha256(publicKey), publicKey, {
        prehash: true,
      });
    } catch {
      return false;
    }
  }

  save(path: string): void {
    const b64 = Buffer.from(this.privateKey).toString("base64");
    const lines = b64.match(/.{1,64}/g) ?? [];
    const pem = `-----BEGIN ${PEM_TAG}-----\n${lines.join("\n")}\n-----END ${PEM_TAG}-----\n`;
    writeSecretFile(path, Buffer.from(pem, "utf8"));
  }

  static load(path: string): KeyPair {
    const pem = readFileSync(path, "utf8");
    const m = /-----BEGIN ([^-]+)-----([\s\S]*?)-----END \1-----/.exec(pem);
    if (!m || m[1] !== PEM_TAG) {
      throw new CryptoError(`invalid PEM block type: ${m?.[1] ?? "none"}`);
    }
    const priv = Buffer.from(m[2]!.replace(/\s+/g, ""), "base64");
    return KeyPair.fromPrivateKey(new Uint8Array(priv));
  }

  static loadOrGenerate(path: string): KeyPair {
    if (existsSync(path)) return KeyPair.load(path);
    const kp = KeyPair.generate();
    kp.save(path);
    return kp;
  }
}

// === Group-key keyring (port of Rust KeyExchange) ===

export class Keyring {
  private keysByVersion = new Map<number, Uint8Array>();
  currentVersion = 0;

  hasGroupKey(): boolean {
    return this.keysByVersion.size > 0;
  }

  initGroupKey(): void {
    if (this.hasGroupKey()) throw new CryptoError("refusing to reinitialize an existing keyring");
    this.addKeyVersion(1, generateGroupKey());
  }

  addKeyVersion(version: number, key: Uint8Array): void {
    if (!Number.isSafeInteger(version) || version < 1 || key.length !== 32) {
      throw new CryptoError("invalid group key version or length");
    }
    const previous = this.keysByVersion.get(version);
    if (previous && !Buffer.from(previous).equals(Buffer.from(key))) {
      throw new CryptoError("refusing to replace existing key material");
    }
    if (version > this.currentVersion) this.currentVersion = version;
    this.keysByVersion.set(version, key);
  }

  hasVersion(version: number): boolean { return this.keysByVersion.has(version); }

  clone(): Keyring {
    const copy = new Keyring();
    for (const [version, key] of this.keysByVersion) copy.addKeyVersion(version, key.slice());
    return copy;
  }

  replaceWith(candidate: Keyring): void {
    this.keysByVersion = candidate.keysByVersion;
    this.currentVersion = candidate.currentVersion;
  }

  private currentKey(): Uint8Array {
    const key = this.keysByVersion.get(this.currentVersion);
    if (!key) throw new CryptoError("no current group key");
    return key;
  }

  keyForVersion(version: number): Uint8Array {
    const key = this.keysByVersion.get(version);
    if (!key) throw new CryptoError(`no group key for version ${version}`);
    return key;
  }

  /** Wraps the current group key for a peer device's public key. */
  encryptForDevice(
    privateKey: Uint8Array,
    peerPublicKey: Uint8Array,
  ): Uint8Array {
    return encryptGroupKey(this.currentKey(), privateKey, peerPublicKey);
  }

  /** Unwraps a group key from a peer and records it at the given version. */
  decryptFromDevice(
    encryptedKey: Uint8Array,
    privateKey: Uint8Array,
    peerPublicKey: Uint8Array,
    version: number,
  ): void {
    const gk = decryptGroupKey(encryptedKey, privateKey, peerPublicKey);
    this.addKeyVersion(version, gk);
  }

  /** Encrypts clipboard data → salt(16) || nonce(12) || ciphertext || tag. */
  encryptPayload(plaintext: Uint8Array): { data: Uint8Array; keyVersion: number } {
    const gk = this.currentKey();
    const salt = new Uint8Array(randomBytes(16));
    const key = deriveKeyFromGroupKey(gk, salt);
    const encrypted = encrypt(key, plaintext);
    const out = new Uint8Array(16 + encrypted.length);
    out.set(salt, 0);
    out.set(encrypted, 16);
    return { data: out, keyVersion: this.currentVersion };
  }

  decryptPayload(data: Uint8Array, version: number): Uint8Array {
    if (data.length < 16) throw new CryptoError("ciphertext too short");
    const salt = data.subarray(0, 16);
    const encrypted = data.subarray(16);
    const key = deriveKeyFromGroupKey(this.keyForVersion(version), salt);
    return decrypt(key, encrypted);
  }

  /** Tries the given version, then all known versions (legacy entries). */
  decryptPayloadLegacy(data: Uint8Array, version: number): Uint8Array {
    try {
      return this.decryptPayload(data, version);
    } catch {
      for (const v of [...this.keysByVersion.keys()].sort((a, b) => b - a)) {
        if (v === version) continue;
        try {
          return this.decryptPayload(data, v);
        } catch {
          // try next
        }
      }
      throw new CryptoError("no key version could decrypt this payload");
    }
  }

  // === Persistence (same file format as the Rust desktop client) ===

  save(path: string, devicePrivateKey: Uint8Array): void {
    const keys: Record<string, string> = {};
    for (const [v, k] of this.keysByVersion) {
      keys[v] = Buffer.from(k).toString("base64");
    }
    const json = JSON.stringify({ current_version: this.currentVersion, keys });
    const salt = new Uint8Array(randomBytes(16));
    const kek = deriveKeyFromSecret(devicePrivateKey, salt, INFO_KEYRING);
    const encrypted = encrypt(kek, new TextEncoder().encode(json));
    const out = new Uint8Array(16 + encrypted.length);
    out.set(salt, 0);
    out.set(encrypted, 16);
    writeSecretFile(path, Buffer.from(out));
  }

  static load(path: string, devicePrivateKey: Uint8Array): Keyring {
    const data = new Uint8Array(readFileSync(path));
    if (data.length < 16) throw new CryptoError("keyring too short");
    const salt = data.subarray(0, 16);
    const encrypted = data.subarray(16);
    const kek = deriveKeyFromSecret(devicePrivateKey, salt, INFO_KEYRING);
    const json = new TextDecoder().decode(decrypt(kek, encrypted));
    const parsed = z.object({
      current_version: z.number().int().positive(), keys: z.record(z.string()),
    }).parse(JSON.parse(json));
    const ring = new Keyring();
    for (const [v, b64] of Object.entries(parsed.keys)) {
      ring.addKeyVersion(Number(v), new Uint8Array(Buffer.from(b64, "base64")));
    }
    if (!ring.hasVersion(parsed.current_version) || ring.currentVersion !== parsed.current_version) {
      throw new CryptoError("saved keyring has no valid active key");
    }
    return ring;
  }
}

// === Helpers ===

export function fingerprintOfPublicKey(publicKey: Uint8Array): string {
  const hash = sha256(publicKey);
  return [...hash].map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join(":");
}

export function shortFingerprint(publicKey: Uint8Array): string {
  return fingerprintOfPublicKey(publicKey).split(":").slice(0, 8).join(":");
}

function lexicographicCompare(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]! < b[i]!) return -1;
    if (a[i]! > b[i]!) return 1;
  }
  return a.length - b.length;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** Atomic replacement, never a partially written private key or keyring. */
export function writeSecretFile(path: string, data: Buffer): void {
  const dir = dirname(path);
  if (dir) mkdirSync(dir, { recursive: true });
  const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    const fd = openSync(temporary, "wx", 0o600);
    try { writeFileSync(fd, data); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(temporary, path);
  } finally {
    if (existsSync(temporary)) rmSync(temporary);
  }
}

export function membershipTranscript(
  version: number, sender: string, members: DeviceIdentity[], hashes: Record<string, string>,
): Uint8Array {
  const id = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  if (!Number.isInteger(version) || version < 1 || !id.test(sender)
      || Object.keys(hashes).length !== members.length
      || members.some((member) => !id.test(member.id) || !hashes[member.id])
      || Object.values(hashes).some((hash) => !/^[0-9a-f]{64}$/.test(hash))) {
    throw new CryptoError("invalid wrapped-key commitments");
  }
  const ordered = [...members].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  return new TextEncoder().encode(
    `cpmesh-membership-v2\n${version}\n${sender}\n` +
    ordered.map((m) => `${m.id}:${m.public_key}:${hashes[m.id]}\n`).join(""),
  );
}

export function wrappedKeyHash(encrypted: Uint8Array): string {
  return Buffer.from(sha256(encrypted)).toString("hex");
}

export function signedWraps(
  pair: KeyPair, sender: string, version: number, groupKey: Uint8Array, members: DeviceIdentity[],
): StoreGroupKeyEntry[] {
  if (members.length === 0) throw new CryptoError("empty membership");
  const wraps: StoreGroupKeyEntry[] = members.map((member) => {
    const encrypted_key = Buffer.from(encryptGroupKey(
      groupKey, pair.privateKey, Buffer.from(member.public_key, "base64"),
    )).toString("base64");
    return { device_id: member.id, encrypted_key };
  });
  const hashes = Object.fromEntries(wraps.map((wrap) => [
    wrap.device_id, wrappedKeyHash(Buffer.from(wrap.encrypted_key, "base64")),
  ]));
  wraps[0]!.membership = {
    members, wrapped_key_hashes: hashes,
    signature: Buffer.from(pair.signMessage(membershipTranscript(version, sender, members, hashes))).toString("base64"),
  };
  return wraps;
}
