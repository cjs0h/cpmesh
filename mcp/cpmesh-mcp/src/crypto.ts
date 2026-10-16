/**
 * Byte-compatible TypeScript port of the cpmesh end-to-end encryption stack
 * (protocol v3).
 *
 * Mirrors desktop-tauri/src-tauri/src/crypto/{keys,encrypt,exchange,membership}.rs
 * and the transcript builders in crates/cpmesh-proto/src/models.rs.
 * Compatibility with the Rust implementation is pinned by the golden
 * vectors in test/vectors.json (see vector-gen/ for the generator).
 *
 * Formats:
 * - HKDF-SHA256 with the exact info strings used by the Rust client
 * - ECDH shared secret = x-coordinate (32 bytes) of the P-256 shared point
 * - AES-256-GCM (optionally with associated data): nonce(12) || ciphertext || tag(16)
 * - Clipboard payload: salt(16) || nonce(12) || ciphertext || tag(16), bound to
 *   its entry context through the AAD
 * - Group key wrap v3 (ephemeral-static): eph_pub(65) || nonce(12) || ct(32) || tag(16)
 * - Legacy group key wrap (static-static against the identity key, import only):
 *   nonce(12) || ct(32) || tag(16)
 * - Keyring file: salt(16) || AES-GCM blob of the keyring JSON (KEK derived
 *   from the identity private key, info "cpnet-keyring-v1")
 *
 * A device holds two P-256 key pairs: the identity key only signs (ECDSA) and
 * the encryption key only receives ECDH wraps; the identity key certifies the
 * encryption key.
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
import type { ContentType, DeviceIdentity, StoreGroupKeyEntry } from "./protocol.js";
import { WRAP_LEGACY_LEN, WRAP_V3_LEN } from "./protocol.js";
import { z } from "zod";

const utf8 = (text: string) => new TextEncoder().encode(text);
const INFO_SHARED = utf8("cpmesh-clipboard-v1");
const INFO_GROUP = utf8("cpmesh-group-v1");
const INFO_KEYRING = utf8("cpnet-keyring-v1");
const INFO_WRAP_V3 = utf8("cpmesh-group-key-wrap-v3");
const SALT_GROUP_KEY_WRAP = utf8("group-key-wrap");
const SALT_PREFIX_WRAP_V3 = utf8("cpmesh-wrap-v3");
const EMPTY = new Uint8Array(0);
const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export class CryptoError extends Error {}

// === HKDF ===

function deriveKey(
  secret: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
): Uint8Array {
  return new Uint8Array(hkdf(sha256, secret, salt, info, 32));
}

/** Raw ECDH secret: the x-coordinate of the shared point (Rust: raw_secret_bytes). */
function ecdhX(privateKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
  return p256.getSharedSecret(privateKey, peerPublicKey).slice(1, 33);
}

/** Derives a shared AES-256 key from ECDH + HKDF (Rust: derive_shared_key). */
export function deriveSharedKey(
  privateKey: Uint8Array,
  peerPublicKey: Uint8Array,
  salt: Uint8Array,
): Uint8Array {
  return deriveKey(ecdhX(privateKey, peerPublicKey), salt, INFO_SHARED);
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

/** AES-256-GCM encrypt with explicit nonce → ciphertext || tag (Rust: encrypt_with_nonce minus the nonce prefix). */
export function aesGcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = EMPTY,
): Uint8Array {
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  if (aad.length > 0) cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return new Uint8Array(Buffer.concat([ct, tag]));
}

/** AES-256-GCM decrypt of ciphertext || tag with explicit nonce and the same AAD it was sealed with. */
export function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  aad: Uint8Array = EMPTY,
): Uint8Array {
  if (data.length < 16) {
    throw new CryptoError("ciphertext too short");
  }
  const ct = data.subarray(0, data.length - 16);
  const tag = data.subarray(data.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  if (aad.length > 0) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  let pt: Buffer;
  try {
    pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new CryptoError("decryption failed: authentication tag or context mismatch");
  }
  return new Uint8Array(pt);
}

/** Encrypt with a random nonce → nonce(12) || ciphertext || tag (Rust: encrypt_with_aad). */
export function encrypt(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array = EMPTY): Uint8Array {
  return encryptWithNonce(key, new Uint8Array(randomBytes(12)), plaintext, aad);
}

/** Deterministic variant for golden vectors; callers must never reuse a nonce under one key. */
export function encryptWithNonce(
  key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array = EMPTY,
): Uint8Array {
  if (nonce.length !== 12) throw new CryptoError("nonce must be 12 bytes");
  return concat(nonce, aesGcmEncrypt(key, nonce, plaintext, aad));
}

/** Decrypt nonce(12) || ciphertext || tag (Rust: decrypt_with_aad). */
export function decrypt(key: Uint8Array, data: Uint8Array, aad: Uint8Array = EMPTY): Uint8Array {
  if (data.length < 12 + 16) {
    throw new CryptoError("ciphertext too short");
  }
  return aesGcmDecrypt(key, data.subarray(0, 12), data.subarray(12), aad);
}

export function generateGroupKey(): Uint8Array {
  return new Uint8Array(randomBytes(32));
}

// === Legacy group key wrapping (protocol ≤ 2, static-static against identity keys) ===

/** Legacy wrap; only tests create these. Production wraps are {@link wrapGroupKeyV3}. */
export function encryptGroupKey(
  groupKey: Uint8Array,
  privateKey: Uint8Array,
  peerPublicKey: Uint8Array,
): Uint8Array {
  const shared = deriveSharedKey(privateKey, peerPublicKey, SALT_GROUP_KEY_WRAP);
  return encrypt(shared, groupKey);
}

/** Opens a legacy 60-byte wrap with this device's identity key (Rust: decrypt_group_key). */
export function decryptGroupKey(
  encryptedGroupKey: Uint8Array,
  privateKey: Uint8Array,
  peerPublicKey: Uint8Array,
): Uint8Array {
  const shared = deriveSharedKey(privateKey, peerPublicKey, SALT_GROUP_KEY_WRAP);
  return decrypt(shared, encryptedGroupKey);
}

// === Group key wrapping v3 (ephemeral-static against the recipient's encryption key) ===

/** Associated data binding a v3 wrap to the key version and both parties (Rust: wrap_aad). */
export function wrapAad(version: number, senderDeviceId: string, recipientDeviceId: string): Uint8Array {
  if (!Number.isSafeInteger(version)) throw new CryptoError("invalid key version");
  return utf8(`cpmesh-wrap-v3\n${version}\n${senderDeviceId}\n${recipientDeviceId}\n`);
}

/**
 * Key for a v3 wrap (Rust: derive_wrap_key_v3). `privateKey`/`dhPeer` are
 * (ephemeral, recipient) when wrapping and (recipient, ephemeral) when
 * unwrapping; both public keys are bound into the HKDF salt either way.
 */
function deriveWrapKeyV3(
  privateKey: Uint8Array, dhPeer: Uint8Array, ephemeralPublic: Uint8Array, recipientEncryptionKey: Uint8Array,
): Uint8Array {
  const salt = sha256(concat(SALT_PREFIX_WRAP_V3, ephemeralPublic, recipientEncryptionKey));
  return deriveKey(ecdhX(privateKey, dhPeer), salt, INFO_WRAP_V3);
}

/** {@link wrapGroupKeyV3} with caller-supplied ephemeral key and nonce (golden vectors only). */
export function wrapGroupKeyV3Deterministic(
  groupKey: Uint8Array,
  ephemeralPrivate: Uint8Array,
  nonce: Uint8Array,
  recipientEncryptionKey: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (groupKey.length !== 32) throw new CryptoError("group key must be 32 bytes");
  const recipient = KeyPair.parsePublicKey(recipientEncryptionKey);
  const ephemeralPublic = p256.getPublicKey(ephemeralPrivate, false);
  const key = deriveWrapKeyV3(ephemeralPrivate, recipient, ephemeralPublic, recipient);
  return concat(ephemeralPublic, encryptWithNonce(key, nonce, groupKey, aad));
}

/**
 * Wraps a group key for one recipient with a fresh ephemeral key, so a later
 * compromise of the sender's long-term keys does not open past wraps.
 * Layout: ephemeral public key(65) || nonce(12) || ciphertext(32) || tag(16).
 */
export function wrapGroupKeyV3(groupKey: Uint8Array, recipientEncryptionKey: Uint8Array, aad: Uint8Array): Uint8Array {
  const ephemeral = KeyPair.generate();
  return wrapGroupKeyV3Deterministic(groupKey, ephemeral.privateKey, new Uint8Array(randomBytes(12)), recipientEncryptionKey, aad);
}

/** Opens a v3 wrap with this device's static encryption key (Rust: unwrap_group_key_v3). */
export function unwrapGroupKeyV3(blob: Uint8Array, encryptionPrivate: Uint8Array, aad: Uint8Array): Uint8Array {
  if (blob.length !== WRAP_V3_LEN) throw new CryptoError(`unexpected wrap length ${blob.length}`);
  const ephemeralPublic = KeyPair.parsePublicKey(blob.subarray(0, 65));
  const ownPublic = p256.getPublicKey(encryptionPrivate, false);
  const key = deriveWrapKeyV3(encryptionPrivate, ephemeralPublic, ephemeralPublic, ownPublic);
  const groupKey = decrypt(key, blob.subarray(65), aad);
  if (groupKey.length !== 32) throw new CryptoError("unwrapped key has the wrong length");
  return groupKey;
}

// === Encryption key certification ===

/** Rust: encryption_key_transcript. */
export function encryptionKeyTranscript(identityPublicKey: Uint8Array, encryptionKey: Uint8Array): Uint8Array {
  return utf8(`cpmesh-encryption-key-v1\n${toBase64(identityPublicKey)}\n${toBase64(encryptionKey)}\n`);
}

/**
 * Checks that `encryptionKey` was certified by the holder of `identity` and
 * returns it in normalized SEC1 form (Rust: verify_encryption_key).
 */
export function verifyEncryptionKey(identity: Uint8Array, encryptionKey: Uint8Array, signature: Uint8Array): Uint8Array {
  const key = KeyPair.parsePublicKey(encryptionKey);
  if (!KeyPair.verifyMessage(identity, encryptionKeyTranscript(identity, encryptionKey), signature)) {
    throw new CryptoError("encryption key certification is invalid");
  }
  return key;
}

// === Clipboard entry context (Rust: clipboard_*_aad, clipboard_signature_transcript) ===

/** Identifies the entry every v3 ciphertext and signature is bound to. */
export interface EntryContext {
  keyVersion: number;
  contentType: ContentType;
  senderId: string;
  requestId: string;
  /** Sender clock, Unix milliseconds. */
  sentAt: number;
}

function clipboardContext(context: EntryContext): string {
  const { keyVersion, contentType, senderId, requestId, sentAt } = context;
  if (!Number.isSafeInteger(keyVersion) || keyVersion < 1 || !Number.isSafeInteger(sentAt) || sentAt <= 0
      || !["text", "image", "file"].includes(contentType)
      || !CANONICAL_UUID.test(senderId) || !CANONICAL_UUID.test(requestId)) {
    throw new CryptoError("invalid clipboard entry context");
  }
  return `cpmesh-clipboard-v3\n${keyVersion}\n${contentType}\n${senderId}\n${requestId}\n${sentAt}\n`;
}

/** AAD for the clipboard data ciphertext. */
export function clipboardDataAad(context: EntryContext): Uint8Array {
  return utf8(clipboardContext(context) + "data\n");
}

/** AAD for the encrypted metadata; distinct so metadata cannot be spliced between entries. */
export function clipboardMetadataAad(context: EntryContext): Uint8Array {
  return utf8(clipboardContext(context) + "metadata\n");
}

/**
 * Message signed by the sender identity key: the context plus commitments to
 * both ciphertexts. `metadata` is the raw (pre-base64) encrypted metadata, empty if absent.
 */
export function clipboardSignatureTranscript(context: EntryContext, encryptedData: Uint8Array, metadata: Uint8Array): Uint8Array {
  return utf8(clipboardContext(context) + toHex(sha256(encryptedData)) + "\n" + toHex(sha256(metadata)) + "\n");
}

// === Pairing: committed short authentication string (Rust: sas_*, pairing_fingerprint) ===

function nonce32(value: Uint8Array, what: string): Uint8Array {
  if (value.length !== 32) throw new CryptoError(`${what} must be 32 bytes`);
  return value;
}

/** The approver's commitment to its nonce, published before the pending device contributes its own. */
export function sasCommitment(approverNonce: Uint8Array): Uint8Array {
  return sha256(concat(utf8("cpmesh-sas-commit-v1\n"), nonce32(approverNonce, "approver nonce")));
}

/**
 * Eight-digit short authentication string, shown as "1234 5678" on both devices.
 * Each side hashes the identity keys as IT sees them.
 */
export function sasCode(
  approverNonce: Uint8Array, pendingNonce: Uint8Array, ownPublicKey: Uint8Array, peerPublicKey: Uint8Array,
): string {
  const digest = sha256(concat(
    utf8("cpmesh-sas-v1\n"), nonce32(approverNonce, "approver nonce"), nonce32(pendingNonce, "pending nonce"),
    sortedPair(ownPublicKey, peerPublicKey),
  ));
  const prefix = new DataView(digest.buffer, digest.byteOffset, 8).getBigUint64(0);
  const digits = (prefix % 100_000_000n).toString().padStart(8, "0");
  return `${digits.slice(0, 4)} ${digits.slice(4)}`;
}

/**
 * Full 256-bit pairing code over both identity keys (no ECDH: the identity key
 * only signs in v3). Compare every character when the short code is not enough.
 */
export function pairingFingerprint(ownPublicKey: Uint8Array, peerPublicKey: Uint8Array): string {
  return toHex(sha256(concat(utf8("cpmesh-pairing-fingerprint-v3\n"), sortedPair(ownPublicKey, peerPublicKey)))).toUpperCase();
}

// === ECDSA signatures (DER <-> compact) ===

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
  if (r.length > 32 || s.length > 32) throw new CryptoError("invalid DER signature");
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

// === Device key pairs ===

/** PEM tag of the identity key file (historical name; the key only signs in v3). */
export const IDENTITY_PEM_TAG = "ECDH PRIVATE KEY";
/** PEM tag of the static encryption key file; distinct so the two keys can never be confused. */
export const ENCRYPTION_PEM_TAG = "CPMESH ENCRYPTION KEY";

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

  /** Validates a SEC1 point and returns it in uncompressed form (Rust: parse_public_key + public_key_to_bytes). */
  static parsePublicKey(data: Uint8Array): Uint8Array {
    try {
      return p256.ProjectivePoint.fromHex(data).toRawBytes(false);
    } catch (error) {
      throw new CryptoError(`invalid public key point: ${error instanceof Error ? error.message : String(error)}`);
    }
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
    return Buffer.from(this.signMessage(utf8(`cpmesh-device-proof-v1\n${challenge}`))).toString("base64");
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

  save(path: string, tag: string = IDENTITY_PEM_TAG): void {
    const b64 = Buffer.from(this.privateKey).toString("base64");
    const lines = b64.match(/.{1,64}/g) ?? [];
    const pem = `-----BEGIN ${tag}-----\n${lines.join("\n")}\n-----END ${tag}-----\n`;
    writeSecretFile(path, Buffer.from(pem, "utf8"));
  }

  static load(path: string, tag: string = IDENTITY_PEM_TAG): KeyPair {
    const pem = readFileSync(path, "utf8");
    const m = /-----BEGIN ([^-]+)-----([\s\S]*?)-----END \1-----/.exec(pem);
    if (!m || m[1] !== tag) {
      throw new CryptoError(`invalid PEM block type: ${m?.[1] ?? "none"}`);
    }
    const priv = Buffer.from(m[2]!.replace(/\s+/g, ""), "base64");
    if (priv.length !== 32) throw new CryptoError("private scalar must be 32 bytes");
    return KeyPair.fromPrivateKey(new Uint8Array(priv));
  }

  static loadOrGenerate(path: string, tag: string = IDENTITY_PEM_TAG): KeyPair {
    if (existsSync(path)) return KeyPair.load(path, tag);
    const kp = KeyPair.generate();
    kp.save(path, tag);
    return kp;
  }
}

/**
 * The two long-term keys of a device: the identity key signs, the encryption
 * key receives ECDH wraps. No key is ever used by two algorithms.
 */
export class DeviceKeys {
  constructor(
    readonly identity: KeyPair,
    readonly encryption: KeyPair,
  ) {
    if (Buffer.from(identity.publicKey).equals(Buffer.from(encryption.publicKey))) {
      throw new CryptoError("identity and encryption keys must be distinct");
    }
  }

  static generate(): DeviceKeys {
    return new DeviceKeys(KeyPair.generate(), KeyPair.generate());
  }

  /** Loads both keys; the encryption key is created on first use for installs that predate it. */
  static load(identityPath: string, encryptionPath: string): DeviceKeys {
    return new DeviceKeys(
      KeyPair.load(identityPath, IDENTITY_PEM_TAG),
      KeyPair.loadOrGenerate(encryptionPath, ENCRYPTION_PEM_TAG),
    );
  }

  static loadOrGenerate(identityPath: string, encryptionPath: string): DeviceKeys {
    return new DeviceKeys(
      KeyPair.loadOrGenerate(identityPath, IDENTITY_PEM_TAG),
      KeyPair.loadOrGenerate(encryptionPath, ENCRYPTION_PEM_TAG),
    );
  }

  /** Certifies the encryption key with the identity key (Rust: certify_encryption_key). */
  certifyEncryptionKey(): Uint8Array {
    return this.identity.signMessage(encryptionKeyTranscript(this.identity.publicKey, this.encryption.publicKey));
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

  /**
   * Imports a wrap addressed to this device and records it at `version`
   * (Rust: import_wrapped). v3 wraps open with the encryption key; legacy
   * 60-byte wraps (created before the upgrade) open with the identity key.
   */
  importWrapped(
    encryptedKey: Uint8Array,
    keys: DeviceKeys,
    senderIdentityKey: Uint8Array,
    senderId: string,
    ownId: string,
    version: number,
  ): void {
    let groupKey: Uint8Array;
    switch (encryptedKey.length) {
      case WRAP_V3_LEN:
        groupKey = unwrapGroupKeyV3(encryptedKey, keys.encryption.privateKey, wrapAad(version, senderId, ownId));
        break;
      case WRAP_LEGACY_LEN:
        groupKey = decryptGroupKey(encryptedKey, keys.identity.privateKey, senderIdentityKey);
        break;
      default:
        throw new CryptoError(`unexpected wrapped key length ${encryptedKey.length}`);
    }
    this.addKeyVersion(version, groupKey);
  }

  /** Encrypts clipboard data bound to `aad` → salt(16) || nonce(12) || ciphertext || tag. */
  encryptPayload(plaintext: Uint8Array, aad: Uint8Array): { data: Uint8Array; keyVersion: number } {
    const gk = this.currentKey();
    const salt = new Uint8Array(randomBytes(16));
    const key = deriveKeyFromGroupKey(gk, salt);
    return { data: concat(salt, encrypt(key, plaintext, aad)), keyVersion: this.currentVersion };
  }

  /** Decrypts clipboard data at `version` with the same `aad` it was sealed with. */
  decryptPayload(data: Uint8Array, version: number, aad: Uint8Array): Uint8Array {
    if (data.length < 16) throw new CryptoError("ciphertext too short");
    const salt = data.subarray(0, 16);
    const encrypted = data.subarray(16);
    const key = deriveKeyFromGroupKey(this.keyForVersion(version), salt);
    return decrypt(key, encrypted, aad);
  }

  /**
   * Legacy (pre-v3) entries carry no AAD and may be labelled with the wrong
   * version: tries the hint, then every version. Only for unsigned history entries.
   */
  decryptPayloadLegacy(data: Uint8Array, versionHint: number): Uint8Array {
    if (this.keysByVersion.has(versionHint)) {
      try {
        return this.decryptPayload(data, versionHint, EMPTY);
      } catch {
        // fall through to the other versions
      }
    }
    for (const v of [...this.keysByVersion.keys()].sort((a, b) => b - a)) {
      if (v === versionHint) continue;
      try {
        return this.decryptPayload(data, v, EMPTY);
      } catch {
        // try next
      }
    }
    throw new CryptoError("no key version could decrypt this payload");
  }

  // === Persistence (same file format as the Rust desktop client) ===

  /** `devicePrivateKey` is the identity private scalar (KEK input, as on the desktop). */
  save(path: string, devicePrivateKey: Uint8Array): void {
    const keys: Record<string, string> = {};
    for (const [v, k] of this.keysByVersion) {
      keys[v] = Buffer.from(k).toString("base64");
    }
    const json = JSON.stringify({ current_version: this.currentVersion, keys });
    const salt = new Uint8Array(randomBytes(16));
    const kek = deriveKeyFromSecret(devicePrivateKey, salt, INFO_KEYRING);
    writeSecretFile(path, Buffer.from(concat(salt, encrypt(kek, utf8(json)))));
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

export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export function fromBase64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64"));
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && Buffer.from(a).equals(Buffer.from(b));
}

function lexicographicCompare(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]! < b[i]!) return -1;
    if (a[i]! > b[i]!) return 1;
  }
  return a.length - b.length;
}

/** Rust: sorted_pair — the lexicographically smaller key first. */
function sortedPair(a: Uint8Array, b: Uint8Array): Uint8Array {
  return lexicographicCompare(a, b) <= 0 ? concat(a, b) : concat(b, a);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
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

// === Authenticated membership (Rust: membership_transcript, signed_wraps, certified_target) ===

export function membershipTranscript(
  version: number, sender: string, members: DeviceIdentity[], hashes: Record<string, string>,
): Uint8Array {
  if (!Number.isInteger(version) || version < 1 || !CANONICAL_UUID.test(sender)
      || Object.keys(hashes).length !== members.length
      || members.some((member) => !CANONICAL_UUID.test(member.id) || !hashes[member.id])
      || Object.values(hashes).some((hash) => !/^[0-9a-f]{64}$/.test(hash))) {
    throw new CryptoError("invalid wrapped-key commitments");
  }
  const ordered = [...members].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  return utf8(
    `cpmesh-membership-v2\n${version}\n${sender}\n` +
    ordered.map((m) => `${m.id}:${m.public_key}:${hashes[m.id]}\n`).join(""),
  );
}

export function wrappedKeyHash(encrypted: Uint8Array): string {
  return toHex(sha256(encrypted));
}

/** A mesh member together with the encryption key its identity key certified. */
export interface WrapTarget {
  identity: DeviceIdentity;
  /** Uncompressed SEC1 bytes of the certified encryption key. */
  encryptionKey: Uint8Array;
}

/**
 * Checks a member's published encryption key against its (already pinned)
 * identity key. A missing or forged certification means the device has not
 * been updated to protocol v3, or the relay is lying; neither gets a wrap.
 */
export function certifiedTarget(
  identity: DeviceIdentity,
  encryptionKey: string | null | undefined,
  encryptionKeySig: string | null | undefined,
  deviceName: string = identity.id,
): WrapTarget {
  const identityKey = KeyPair.parsePublicKey(fromBase64(identity.public_key));
  if (!encryptionKey || !encryptionKeySig) {
    throw new CryptoError(
      `Device "${deviceName}" has not published a certified encryption key; update it to protocol 3 or remove it`,
    );
  }
  try {
    return { identity, encryptionKey: verifyEncryptionKey(identityKey, fromBase64(encryptionKey), fromBase64(encryptionKeySig)) };
  } catch (error) {
    throw new CryptoError(`Device "${deviceName}": ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Wraps `groupKey` for every target with a fresh ephemeral key (v3) and signs
 * the membership transcript with the identity key. The sender must be one of
 * the targets, under its own identity key.
 */
export function signedWraps(
  pair: KeyPair, sender: string, version: number, groupKey: Uint8Array, targets: WrapTarget[],
): StoreGroupKeyEntry[] {
  if (targets.length === 0) throw new CryptoError("empty membership");
  const members = targets.map((target) => target.identity);
  const ids = new Set(members.map((member) => member.id));
  if (ids.size !== members.length) throw new CryptoError("invalid or duplicate member ID");
  if (!members.some((member) => member.id === sender && member.public_key === toBase64(pair.publicKey))) {
    throw new CryptoError("authenticated membership does not include the sender's own key");
  }
  const wraps: StoreGroupKeyEntry[] = targets.map((target) => ({
    device_id: target.identity.id,
    encrypted_key: toBase64(wrapGroupKeyV3(groupKey, target.encryptionKey, wrapAad(version, sender, target.identity.id))),
  }));
  const hashes = Object.fromEntries(wraps.map((wrap) => [
    wrap.device_id, wrappedKeyHash(fromBase64(wrap.encrypted_key)),
  ]));
  wraps[0]!.membership = {
    members, wrapped_key_hashes: hashes,
    signature: toBase64(pair.signMessage(membershipTranscript(version, sender, members, hashes))),
  };
  return wraps;
}
