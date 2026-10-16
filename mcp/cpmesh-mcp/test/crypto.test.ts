/**
 * Golden-vector compatibility tests between the TypeScript crypto port and
 * the Rust desktop client implementation.
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
  KeyPair,
  Keyring,
  aesGcmDecrypt,
  aesGcmEncrypt,
  decrypt,
  decryptGroupKey,
  deriveApprovalCode,
  deriveKeyFromGroupKey,
  deriveKeyFromSecret,
  deriveSharedKey,
  encrypt,
  fingerprintOfPublicKey,
} from "../src/crypto.js";

const vectors = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "vectors.json"), "utf8"),
) as Record<string, string>;

const hex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
const utf8 = (s: string) => new TextEncoder().encode(s);

describe("golden vectors (Rust ↔ TS byte compatibility)", () => {
  it("derives the same ECDH x-coordinate", () => {
    const shared = p256.getSharedSecret(hex(vectors.priv_a!), hex(vectors.pub_b!));
    expect(Buffer.from(shared.slice(1, 33)).toString("hex")).toBe(vectors.ecdh_x_ab!);
  });

  it("derives the same ECDH shared key (group-key-wrap salt)", () => {
    const key = deriveSharedKey(
      hex(vectors.priv_a!),
      hex(vectors.pub_b!),
      utf8("group-key-wrap"),
    );
    expect(Buffer.from(key).toString("hex")).toBe(vectors.shared_key_wrap_ab!);
  });

  it("derives the same payload key from a group key", () => {
    const key = deriveKeyFromGroupKey(
      hex(vectors.group_key!),
      hex(vectors.payload_salt!),
    );
    expect(Buffer.from(key).toString("hex")).toBe(vectors.payload_key!);
  });

  it("produces identical AES-256-GCM ciphertext+tag with a fixed nonce", () => {
    const ct = aesGcmDecrypt(hex(vectors.payload_key!), hex(vectors.nonce12!), hex(vectors.aes_ct_tag!));
    expect(Buffer.from(ct).toString("utf8")).toBe("Hello from cpmesh MCP golden vectors");
    const reenc = aesGcmEncrypt(hex(vectors.payload_key!), hex(vectors.nonce12!), ct);
    expect(Buffer.from(reenc).toString("hex")).toBe(vectors.aes_ct_tag!);
  });

  it("decrypts a Rust-produced clipboard payload (salt||nonce||ct layout)", () => {
    const ring = new Keyring();
    ring.addKeyVersion(1, hex(vectors.group_key!));
    expect(ring.currentVersion).toBe(1);
    const plain = ring.decryptPayload(hex(vectors.payload_full!), 1);
    expect(Buffer.from(plain).toString("utf8")).toBe(
      "Hello from cpmesh MCP golden vectors",
    );
  });

  it("round-trips its own payloads and matches Rust entry layout", () => {
    const ring = new Keyring();
    ring.initGroupKey();
    const { data, keyVersion } = ring.encryptPayload(utf8("round trip"));
    // salt(16) + nonce(12) + tag(16) overhead
    expect(data.length).toBe(16 + 12 + 16 + "round trip".length);
    expect(ring.decryptPayload(data, keyVersion)).toEqual(utf8("round trip"));
  });

  it("decrypts a Rust-produced group-key wrap with a fixed nonce", () => {
    const gk = decryptGroupKey(
      hex(vectors.gk_wrapped_fixed_nonce!),
      hex(vectors.priv_b!),
      hex(vectors.pub_a!),
    );
    expect(Buffer.from(gk).toString("hex")).toBe(vectors.group_key!);
  });

  it("group-key wrap round-trips across independently generated key pairs", () => {
    const a = KeyPair.generate();
    const b = KeyPair.generate();
    const gk = hex(vectors.group_key!);
    // Rust side wraps with A's private key + B's public key…
    const wrapped = encrypt(
      deriveSharedKey(a.privateKey, b.publicKey, utf8("group-key-wrap")),
      gk,
    );
    // …and B unwraps with its private key + A's public key.
    const unwrapped = decryptGroupKey(wrapped, b.privateKey, a.publicKey);
    expect(unwrapped).toEqual(gk);
  });

  it("derives the same full 256-bit pairing fingerprint", () => {
    const code = deriveApprovalCode(
      hex(vectors.priv_a!),
      hex(vectors.pub_b!),
      hex(vectors.pub_a!),
    );
    expect(code).toBe(vectors.approval_code_ab!);
    // Symmetry: swapping roles yields the same code.
    const codeReverse = deriveApprovalCode(
      hex(vectors.priv_b!),
      hex(vectors.pub_a!),
      hex(vectors.pub_b!),
    );
    expect(codeReverse).toBe(vectors.approval_code_ab!);
  });

  it("verifies the Rust-generated public-key self-signature", () => {
    expect(
      KeyPair.verifyPublicKeySignature(hex(vectors.pub_a!), hex(vectors.sig_a_der!)),
    ).toBe(true);
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
    const tmp = join(dirname(fileURLToPath(import.meta.url)), "tmp-keyring.enc");
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
    const tmp = join(dirname(fileURLToPath(import.meta.url)), "tmp-keyring2.enc");
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

  it("computes the same keyring KEK from the device private key", () => {
    const kek = deriveKeyFromSecret(
      hex(vectors.priv_a!),
      hex(vectors.keyring_salt!),
      utf8("cpnet-keyring-v1"),
    );
    // The KEK decrypts the Rust keyring payload — verified via full load above;
    // here we pin the exact bytes for drift detection.
    const cipherText = hex(vectors.keyring_file!).subarray(16);
    const plain = decrypt(kek, cipherText);
    const parsed = JSON.parse(new TextDecoder().decode(plain)) as {
      current_version: number;
      keys: Record<string, string>;
    };
    expect(parsed.current_version).toBe(2);
    expect(parsed.keys["1"]).toBe(Buffer.from(hex(vectors.group_key!)).toString("base64"));
  });

  it("derives the same public-key fingerprint", () => {
    expect(fingerprintOfPublicKey(hex(vectors.pub_a!))).toBe(vectors.fingerprint_a!);
  });

  it("saves and loads device private keys in the same PEM format", () => {    const kp = KeyPair.fromPrivateKey(hex(vectors.priv_a!));
    const tmp = join(dirname(fileURLToPath(import.meta.url)), "tmp-device.key");
    kp.save(tmp);
    try {
      const loaded = KeyPair.load(tmp);
      expect(loaded.privateKey).toEqual(hex(vectors.priv_a!));
      expect(loaded.publicKeyBytes()).toEqual(hex(vectors.pub_a!));
    } finally {
      rmSync(tmp);
    }
  });
});
