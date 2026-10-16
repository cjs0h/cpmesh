/**
 * Golden-vector compatibility tests between the TypeScript crypto port and
 * the Rust desktop client implementation (protocol v3).
 *
 * vectors.json is produced by vector-gen/ (cargo run > test/vectors.json),
 * which includes the desktop crypto modules byte-for-byte. If these tests
 * fail after regenerating vectors, the two implementations have diverged.
 */

import { describe, expect, it } from "vitest";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { p256 } from "@noble/curves/p256";
import {
  DeviceKeys,
  ENCRYPTION_PEM_TAG,
  KeyPair,
  Keyring,
  aesGcmDecrypt,
  aesGcmEncrypt,
  clipboardDataAad,
  clipboardMetadataAad,
  clipboardSignatureTranscript,
  decrypt,
  decryptGroupKey,
  deriveKeyFromGroupKey,
  deriveKeyFromSecret,
  deriveSharedKey,
  encrypt,
  encryptGroupKey,
  encryptWithNonce,
  encryptionKeyTranscript,
  fingerprintOfPublicKey,
  pairingFingerprint,
  sasCode,
  sasCommitment,
  unwrapGroupKeyV3,
  verifyEncryptionKey,
  wrapAad,
  wrapGroupKeyV3,
  wrapGroupKeyV3Deterministic,
  type EntryContext,
} from "../src/crypto.js";
import { WRAP_LEGACY_LEN, WRAP_V3_LEN } from "../src/protocol.js";

const vectors = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "vectors.json"), "utf8"),
) as Record<string, string> & { sent_at: number };

const hex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const utf8 = (s: string) => new TextEncoder().encode(s);
const here = dirname(fileURLToPath(import.meta.url));

/** The v3 clipboard entry pinned by the vectors (sent by A at key version 1). */
const entryContext: EntryContext = {
  keyVersion: 1, contentType: "text", senderId: vectors.sender_id!, requestId: vectors.request_id!, sentAt: vectors.sent_at,
};

describe("golden vectors (Rust ↔ TS byte compatibility)", () => {
  it("derives the same ECDH x-coordinate", () => {
    const shared = p256.getSharedSecret(hex(vectors.priv_a!), hex(vectors.pub_b!));
    expect(toHex(shared.slice(1, 33))).toBe(vectors.ecdh_x_ab!);
  });

  it("derives the same ECDH shared key (legacy group-key-wrap salt)", () => {
    const key = deriveSharedKey(hex(vectors.priv_a!), hex(vectors.pub_b!), utf8("group-key-wrap"));
    expect(toHex(key)).toBe(vectors.shared_key_wrap_ab!);
  });

  it("derives the same payload key from a group key", () => {
    const key = deriveKeyFromGroupKey(hex(vectors.group_key!), hex(vectors.payload_salt!));
    expect(toHex(key)).toBe(vectors.payload_key!);
  });

  it("produces identical AES-256-GCM ciphertext+tag with a fixed nonce", () => {
    const ct = aesGcmDecrypt(hex(vectors.payload_key!), hex(vectors.nonce12!), hex(vectors.aes_ct_tag!));
    expect(Buffer.from(ct).toString("utf8")).toBe("Hello from cpmesh MCP golden vectors");
    const reenc = aesGcmEncrypt(hex(vectors.payload_key!), hex(vectors.nonce12!), ct);
    expect(toHex(reenc)).toBe(vectors.aes_ct_tag!);
  });

  it("decrypts a legacy (AAD-less) Rust clipboard payload only through the legacy path", () => {
    const ring = new Keyring();
    ring.addKeyVersion(1, hex(vectors.group_key!));
    expect(ring.currentVersion).toBe(1);
    const plain = ring.decryptPayloadLegacy(hex(vectors.payload_full!), 1);
    expect(Buffer.from(plain).toString("utf8")).toBe("Hello from cpmesh MCP golden vectors");
    // A v3 context never opens an unbound legacy ciphertext.
    expect(() => ring.decryptPayload(hex(vectors.payload_full!), 1, clipboardDataAad(entryContext))).toThrow();
  });

  it("round-trips its own payloads and matches the Rust entry layout", () => {
    const ring = new Keyring();
    ring.initGroupKey();
    const aad = clipboardDataAad(entryContext);
    const { data, keyVersion } = ring.encryptPayload(utf8("round trip"), aad);
    // salt(16) + nonce(12) + tag(16) overhead
    expect(data.length).toBe(16 + 12 + 16 + "round trip".length);
    expect(ring.decryptPayload(data, keyVersion, aad)).toEqual(utf8("round trip"));
    expect(() => ring.decryptPayload(data, keyVersion, clipboardMetadataAad(entryContext))).toThrow();
  });

  it("decrypts a Rust-produced legacy group-key wrap with a fixed nonce", () => {
    const wrapped = hex(vectors.gk_wrapped_fixed_nonce!);
    expect(wrapped.length).toBe(WRAP_LEGACY_LEN);
    const gk = decryptGroupKey(wrapped, hex(vectors.priv_b!), hex(vectors.pub_a!));
    expect(toHex(gk)).toBe(vectors.group_key!);
  });

  it("verifies the Rust-generated public-key self-signature", () => {
    expect(KeyPair.verifyPublicKeySignature(hex(vectors.pub_a!), hex(vectors.sig_a_der!))).toBe(true);
    // Tampered signature must fail.
    const bad = hex(vectors.sig_a_der!).slice();
    bad[bad.length - 1] ^= 0xff;
    expect(KeyPair.verifyPublicKeySignature(hex(vectors.pub_a!), bad)).toBe(false);
  });

  it("signs public keys that verify against itself", () => {
    const kp = KeyPair.generate();
    const sig = kp.signPublicKey();
    expect(KeyPair.verifyPublicKeySignature(kp.publicKeyBytes(), sig)).toBe(true);
  });

  it("loads a Rust-written keyring file", () => {
    const tmp = join(here, "tmp-keyring.enc");
    rmSync(tmp, { force: true });
    writeFileSync(tmp, Buffer.from(vectors.keyring_file!, "hex"));
    try {
      const ring = Keyring.load(tmp, hex(vectors.priv_a!));
      expect(ring.currentVersion).toBe(2);
      expect(ring.keyForVersion(1)).toEqual(hex(vectors.group_key!));
      expect(ring.keyForVersion(2)).toEqual(hex(vectors.group_key_2!));
    } finally {
      rmSync(tmp);
    }
  });

  it("saves and reloads its own keyring with the same KEK derivation", () => {
    const tmp = join(here, "tmp-keyring2.enc");
    const priv = hex(vectors.priv_a!);
    const ring = new Keyring();
    ring.addKeyVersion(1, hex(vectors.group_key!));
    ring.addKeyVersion(2, hex(vectors.group_key_2!));
    ring.save(tmp, priv);
    try {
      expect(existsSync(tmp)).toBe(true);
      const reloaded = Keyring.load(tmp, priv);
      expect(reloaded.currentVersion).toBe(2);
      expect(reloaded.keyForVersion(1)).toEqual(hex(vectors.group_key!));
      expect(reloaded.keyForVersion(2)).toEqual(hex(vectors.group_key_2!));
    } finally {
      rmSync(tmp);
    }
  });

  it("computes the same keyring KEK from the identity private key", () => {
    const kek = deriveKeyFromSecret(hex(vectors.priv_a!), hex(vectors.keyring_salt!), utf8("cpnet-keyring-v1"));
    const cipherText = hex(vectors.keyring_file!).subarray(16);
    const plain = decrypt(kek, cipherText);
    const parsed = JSON.parse(new TextDecoder().decode(plain)) as { current_version: number; keys: Record<string, string> };
    expect(parsed.current_version).toBe(2);
    expect(parsed.keys["1"]).toBe(Buffer.from(hex(vectors.group_key!)).toString("base64"));
  });

  it("derives the same public-key fingerprint", () => {
    expect(fingerprintOfPublicKey(hex(vectors.pub_a!))).toBe(vectors.fingerprint_a!);
  });

  it("saves and loads device private keys in the same PEM format, with distinct tags per key", () => {
    const kp = KeyPair.fromPrivateKey(hex(vectors.priv_a!));
    const identity = join(here, "tmp-device.key");
    const encryption = join(here, "tmp-encryption.key");
    kp.save(identity);
    KeyPair.fromPrivateKey(hex(vectors.enc_priv_a!)).save(encryption, ENCRYPTION_PEM_TAG);
    try {
      const loaded = KeyPair.load(identity);
      expect(loaded.privateKey).toEqual(hex(vectors.priv_a!));
      expect(loaded.publicKeyBytes()).toEqual(hex(vectors.pub_a!));
      expect(readFileSync(identity, "utf8")).toContain("-----BEGIN ECDH PRIVATE KEY-----");
      // The identity key file can never be loaded as the encryption key, and vice versa.
      expect(() => KeyPair.load(identity, ENCRYPTION_PEM_TAG)).toThrow("invalid PEM block type");
      expect(() => KeyPair.load(encryption)).toThrow("invalid PEM block type");
      const keys = DeviceKeys.load(identity, encryption);
      expect(keys.encryption.publicKeyBytes()).toEqual(hex(vectors.enc_pub_a!));
      // An install that predates protocol 3 gets its encryption key on first use.
      rmSync(encryption);
      const migrated = DeviceKeys.load(identity, encryption);
      expect(existsSync(encryption)).toBe(true);
      expect(migrated.identity.publicKeyBytes()).toEqual(hex(vectors.pub_a!));
      expect(migrated.encryption.publicKeyBytes()).not.toEqual(hex(vectors.enc_pub_a!));
      expect(DeviceKeys.load(identity, encryption).encryption.publicKeyBytes()).toEqual(migrated.encryption.publicKeyBytes());
    } finally {
      rmSync(identity, { force: true });
      rmSync(encryption, { force: true });
    }
  });
});

describe("protocol v3 golden vectors", () => {
  const keysA = new DeviceKeys(KeyPair.fromPrivateKey(hex(vectors.priv_a!)), KeyPair.fromPrivateKey(hex(vectors.enc_priv_a!)));
  const keysB = new DeviceKeys(KeyPair.fromPrivateKey(hex(vectors.priv_b!)), KeyPair.fromPrivateKey(hex(vectors.enc_priv_b!)));

  it("derives the same encryption keys and certification transcript", () => {
    expect(keysA.encryption.publicKeyBytes()).toEqual(hex(vectors.enc_pub_a!));
    expect(keysB.encryption.publicKeyBytes()).toEqual(hex(vectors.enc_pub_b!));
    expect(toHex(encryptionKeyTranscript(hex(vectors.pub_b!), hex(vectors.enc_pub_b!)))).toBe(vectors.encryption_key_transcript_b!);
  });

  it("verifies the Rust encryption-key certifications and produces verifiable ones", () => {
    expect(verifyEncryptionKey(hex(vectors.pub_b!), hex(vectors.enc_pub_b!), hex(vectors.encryption_key_sig_b!))).toEqual(hex(vectors.enc_pub_b!));
    expect(verifyEncryptionKey(hex(vectors.pub_a!), hex(vectors.enc_pub_a!), hex(vectors.encryption_key_sig_a!))).toEqual(hex(vectors.enc_pub_a!));
    expect(verifyEncryptionKey(hex(vectors.pub_b!), hex(vectors.enc_pub_b!), keysB.certifyEncryptionKey())).toEqual(hex(vectors.enc_pub_b!));
    // Wrong identity, swapped key, or tampered signature all fail.
    expect(() => verifyEncryptionKey(hex(vectors.pub_a!), hex(vectors.enc_pub_b!), hex(vectors.encryption_key_sig_b!))).toThrow("certification is invalid");
    expect(() => verifyEncryptionKey(hex(vectors.pub_b!), hex(vectors.enc_pub_a!), hex(vectors.encryption_key_sig_b!))).toThrow("certification is invalid");
    const bad = hex(vectors.encryption_key_sig_b!).slice();
    bad[bad.length - 1] ^= 1;
    expect(() => verifyEncryptionKey(hex(vectors.pub_b!), hex(vectors.enc_pub_b!), bad)).toThrow("certification is invalid");
  });

  it("builds the same v3 wrap AAD and reproduces the deterministic v3 wrap byte for byte", () => {
    const aad = wrapAad(1, vectors.sender_id!, vectors.recipient_id!);
    expect(toHex(aad)).toBe(vectors.wrap_v3_aad!);
    const blob = wrapGroupKeyV3Deterministic(
      hex(vectors.group_key!), hex(vectors.wrap_v3_eph_priv!), hex(vectors.nonce12!), hex(vectors.enc_pub_b!), aad,
    );
    expect(blob.length).toBe(WRAP_V3_LEN);
    expect(toHex(blob)).toBe(vectors.wrap_v3_blob!);
    const selfWrap = wrapGroupKeyV3Deterministic(
      hex(vectors.group_key!), hex(vectors.wrap_v3_eph_priv!), hex(vectors.nonce12!), hex(vectors.enc_pub_a!),
      wrapAad(1, vectors.sender_id!, vectors.sender_id!),
    );
    expect(toHex(selfWrap)).toBe(vectors.self_wrap_v3_blob!);
  });

  it("unwraps the Rust v3 wrap with the recipient's encryption key only, in its exact context", () => {
    const aad = hex(vectors.wrap_v3_aad!);
    const blob = hex(vectors.wrap_v3_blob!);
    expect(toHex(unwrapGroupKeyV3(blob, hex(vectors.enc_priv_b!), aad))).toBe(vectors.group_key!);
    // The identity key is never an ECDH key in v3; other contexts and tampering fail.
    expect(() => unwrapGroupKeyV3(blob, hex(vectors.priv_b!), aad)).toThrow();
    expect(() => unwrapGroupKeyV3(blob, hex(vectors.enc_priv_a!), aad)).toThrow();
    expect(() => unwrapGroupKeyV3(blob, hex(vectors.enc_priv_b!), wrapAad(2, vectors.sender_id!, vectors.recipient_id!))).toThrow();
    expect(() => unwrapGroupKeyV3(blob, hex(vectors.enc_priv_b!), wrapAad(1, vectors.recipient_id!, vectors.recipient_id!))).toThrow();
    const tampered = blob.slice();
    tampered[100] ^= 1;
    expect(() => unwrapGroupKeyV3(tampered, hex(vectors.enc_priv_b!), aad)).toThrow();
    expect(() => unwrapGroupKeyV3(blob.subarray(1), hex(vectors.enc_priv_b!), aad)).toThrow("unexpected wrap length");
    const badPoint = blob.slice();
    badPoint[1] ^= 0xff;
    expect(() => unwrapGroupKeyV3(badPoint, hex(vectors.enc_priv_b!), aad)).toThrow();
  });

  it("wraps with a fresh ephemeral key every time and the keyring imports both wrap generations", () => {
    const aad = wrapAad(1, vectors.sender_id!, vectors.recipient_id!);
    const one = wrapGroupKeyV3(hex(vectors.group_key!), hex(vectors.enc_pub_b!), aad);
    const two = wrapGroupKeyV3(hex(vectors.group_key!), hex(vectors.enc_pub_b!), aad);
    expect(one.length).toBe(WRAP_V3_LEN);
    expect(toHex(one.subarray(0, 65))).not.toBe(toHex(two.subarray(0, 65)));
    expect(toHex(unwrapGroupKeyV3(two, hex(vectors.enc_priv_b!), aad))).toBe(vectors.group_key!);

    const ring = new Keyring();
    ring.importWrapped(one, keysB, hex(vectors.pub_a!), vectors.sender_id!, vectors.recipient_id!, 1);
    expect(toHex(ring.keyForVersion(1))).toBe(vectors.group_key!);
    // A legacy 60-byte wrap created before the upgrade still imports, through the identity key.
    const legacy = encryptGroupKey(hex(vectors.group_key_2!), hex(vectors.priv_a!), hex(vectors.pub_b!));
    expect(legacy.length).toBe(WRAP_LEGACY_LEN);
    ring.importWrapped(legacy, keysB, hex(vectors.pub_a!), vectors.sender_id!, vectors.recipient_id!, 2);
    expect(toHex(ring.keyForVersion(2))).toBe(vectors.group_key_2!);
    ring.importWrapped(hex(vectors.gk_wrapped_fixed_nonce!), keysB, hex(vectors.pub_a!), vectors.sender_id!, vectors.recipient_id!, 1);
    expect(() => ring.importWrapped(one.subarray(0, 100), keysB, hex(vectors.pub_a!), vectors.sender_id!, vectors.recipient_id!, 3)).toThrow("unexpected wrapped key length");
    // A v3 wrap addressed to another recipient is not ours.
    expect(() => ring.importWrapped(one, keysB, hex(vectors.pub_a!), vectors.sender_id!, vectors.sender_id!, 3)).toThrow();
  });

  it("builds the same data and metadata AADs", () => {
    expect(toHex(clipboardDataAad(entryContext))).toBe(vectors.data_aad!);
    expect(toHex(clipboardMetadataAad(entryContext))).toBe(vectors.metadata_aad!);
    expect(() => clipboardDataAad({ ...entryContext, sentAt: 0 })).toThrow("invalid clipboard entry context");
    expect(() => clipboardDataAad({ ...entryContext, requestId: "0000000A-0000-4000-8000-000000000009" })).toThrow("invalid clipboard entry context");
    expect(() => clipboardDataAad({ ...entryContext, senderId: "not-a-uuid\n" })).toThrow("invalid clipboard entry context");
  });

  it("reproduces the v3 payload and metadata ciphertexts with the fixed salts and nonces", () => {
    const payloadKey = deriveKeyFromGroupKey(hex(vectors.group_key!), hex(vectors.payload_salt!));
    const payload = Buffer.concat([
      hex(vectors.payload_salt!), encryptWithNonce(payloadKey, hex(vectors.nonce12!), hex(vectors.plaintext!), clipboardDataAad(entryContext)),
    ]);
    expect(payload.toString("hex")).toBe(vectors.payload_v3_full!);
    const metadataKey = deriveKeyFromGroupKey(hex(vectors.group_key!), hex(vectors.metadata_salt!));
    const metadata = Buffer.concat([
      hex(vectors.metadata_salt!), encryptWithNonce(metadataKey, hex(vectors.metadata_nonce!), hex(vectors.metadata_json!), clipboardMetadataAad(entryContext)),
    ]);
    expect(metadata.toString("hex")).toBe(vectors.metadata_v3_full!);
    // Same key material, same nonce, different AAD than the legacy vector: the tag differs.
    expect(vectors.payload_v3_full).not.toBe(vectors.payload_full);
  });

  it("builds the same signature transcript and verifies the Rust sender signature", () => {
    const transcript = clipboardSignatureTranscript(entryContext, hex(vectors.payload_v3_full!), hex(vectors.metadata_v3_full!));
    expect(toHex(transcript)).toBe(vectors.signature_transcript!);
    expect(KeyPair.verifyMessage(hex(vectors.pub_a!), transcript, hex(vectors.sender_signature!))).toBe(true);
    expect(KeyPair.verifyMessage(hex(vectors.pub_b!), transcript, hex(vectors.sender_signature!))).toBe(false);
    const relabelled = clipboardSignatureTranscript({ ...entryContext, keyVersion: 2 }, hex(vectors.payload_v3_full!), hex(vectors.metadata_v3_full!));
    expect(KeyPair.verifyMessage(hex(vectors.pub_a!), relabelled, hex(vectors.sender_signature!))).toBe(false);
    expect(KeyPair.verifyMessage(hex(vectors.pub_a!), transcript, keysA.identity.signMessage(transcript))).toBe(true);
  });

  it("computes the same SAS commitment and 8-digit code, independent of the viewpoint", () => {
    expect(toHex(sasCommitment(hex(vectors.sas_nonce_approver!)))).toBe(vectors.sas_commit!);
    expect(sasCode(hex(vectors.sas_nonce_approver!), hex(vectors.sas_nonce_pending!), hex(vectors.pub_a!), hex(vectors.pub_b!))).toBe(vectors.sas_code!);
    expect(sasCode(hex(vectors.sas_nonce_approver!), hex(vectors.sas_nonce_pending!), hex(vectors.pub_b!), hex(vectors.pub_a!))).toBe(vectors.sas_code!);
    expect(vectors.sas_code).toMatch(/^[0-9]{4} [0-9]{4}$/);
    // Any other nonce or key changes the code (with overwhelming probability).
    expect(sasCode(hex(vectors.sas_nonce_pending!), hex(vectors.sas_nonce_approver!), hex(vectors.pub_a!), hex(vectors.pub_b!))).not.toBe(vectors.sas_code!);
    expect(sasCode(hex(vectors.sas_nonce_approver!), hex(vectors.sas_nonce_pending!), hex(vectors.pub_a!), hex(vectors.enc_pub_b!))).not.toBe(vectors.sas_code!);
    expect(() => sasCode(hex(vectors.sas_nonce_approver!).subarray(1), hex(vectors.sas_nonce_pending!), hex(vectors.pub_a!), hex(vectors.pub_b!))).toThrow("32 bytes");
  });

  it("derives the same full pairing code without any ECDH", () => {
    expect(pairingFingerprint(hex(vectors.pub_a!), hex(vectors.pub_b!))).toBe(vectors.pairing_fingerprint_ab!);
    expect(pairingFingerprint(hex(vectors.pub_b!), hex(vectors.pub_a!))).toBe(vectors.pairing_fingerprint_ab!);
    expect(vectors.pairing_fingerprint_ab).toMatch(/^[0-9A-F]{64}$/);
  });
});
