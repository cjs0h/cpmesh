import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CpmeshApi, ApiError } from "../src/api.js";
import {
  DeviceKeys, KeyPair, certifiedTarget, encryptGroupKey, generateGroupKey, Keyring, signedWraps, toBase64, type WrapTarget,
} from "../src/crypto.js";
import { importKey, pinVerified, rotateKeys, senderIdentityKey } from "../src/membership.js";
import { loadMembership, statePaths } from "../src/state.js";
import { groupKeysSchema, WRAP_V3_LEN, type DeviceInfo, type StoreGroupKeyEntry, type VersionedGroupKey } from "../src/protocol.js";

const vectors: Record<string, string> = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
const hex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));

let home: string;
beforeEach(() => { home = mkdtempSync(join(tmpdir(), "cpmesh-trust-")); process.env.CPMESH_HOME = home; });
afterEach(() => { delete process.env.CPMESH_HOME; rmSync(home, { recursive: true, force: true }); });

function device() {
  const keys = DeviceKeys.generate();
  const identity = { id: randomUUID(), public_key: toBase64(keys.identity.publicKeyBytes()) };
  const target: WrapTarget = { identity, encryptionKey: keys.encryption.publicKeyBytes() };
  const listing: DeviceInfo = {
    ...identity, name: identity.id.slice(0, 8), online: true, status: "approved",
    encryption_key: toBase64(keys.encryption.publicKeyBytes()), encryption_key_sig: toBase64(keys.certifyEncryptionKey()),
  };
  return { keys, identity, target, listing };
}
type Device = ReturnType<typeof device>;
function wrapped(sender: Device, recipient: Device, members: Device[], version: number, key = generateGroupKey()): VersionedGroupKey {
  const wraps = signedWraps(sender.keys.identity, sender.identity.id, version, key, members.map((m) => m.target));
  const wrap = wraps.find((entry) => entry.device_id === recipient.identity.id)!;
  return { ...wrap, membership: wraps[0]!.membership, from_device_id: sender.identity.id, from_public_key: sender.identity.public_key, version };
}

describe("locally authenticated membership", () => {
  it("supports subscription-sized meshes without repeating the roster for every wrap", () => {
    const owner = device();
    const peers = Array.from({ length: 127 }, () => device());
    const roster = [owner.target, ...peers.map((peer) => peer.target)];
    const wraps = signedWraps(owner.keys.identity, owner.identity.id, 1, generateGroupKey(), roster);
    expect(wraps).toHaveLength(128);
    expect(wraps.filter((wrap) => wrap.membership !== undefined)).toHaveLength(1);
    expect(wraps.every((wrap) => Buffer.from(wrap.encrypted_key, "base64").length === WRAP_V3_LEN)).toBe(true);
    // Ephemeral-static: every wrap carries its own fresh ephemeral key.
    expect(new Set(wraps.map((wrap) => wrap.encrypted_key.slice(0, 88))).size).toBe(128);
    expect(Buffer.byteLength(JSON.stringify(wraps))).toBeLessThan(128 * 1024);
  });

  it("only wraps to encryption keys certified by the member's own identity key", () => {
    const member = device(), other = device();
    const target = certifiedTarget(member.identity, member.listing.encryption_key, member.listing.encryption_key_sig, "Laptop");
    expect(target.encryptionKey).toEqual(member.keys.encryption.publicKeyBytes());
    expect(() => certifiedTarget(member.identity, undefined, undefined, "Old phone")).toThrow(/"Old phone" has not published a certified encryption key; update it to protocol 3/);
    expect(() => certifiedTarget(member.identity, other.listing.encryption_key, other.listing.encryption_key_sig, "Laptop")).toThrow(/certification is invalid/);
    expect(() => certifiedTarget(member.identity, other.listing.encryption_key, member.listing.encryption_key_sig, "Laptop")).toThrow(/certification is invalid/);
    // The sender must be part of the roster it signs.
    expect(() => signedWraps(other.keys.identity, other.identity.id, 1, generateGroupKey(), [member.target])).toThrow("sender's own key");
  });

  it("rejects an unknown sender even with a valid self-signature, including legacy TOFU files", () => {
    const attacker = device(), honest = device();
    const key = wrapped(attacker, honest, [attacker, honest], 1);
    key.from_public_key_sig = toBase64(attacker.keys.identity.signPublicKey());
    writeFileSync(join(home, "pinned_keys.json"), JSON.stringify({ [attacker.identity.id]: attacker.identity.public_key }));
    const ring = new Keyring();
    expect(() => importKey(ring, honest.keys, honest.identity.id, key)).toThrow("not independently verified");
    expect(ring.currentVersion).toBe(0);
    expect(loadMembership().pins).toEqual({});
  });

  it("admits new members only through a pinned sender's authenticated transition", () => {
    const a = device(), b = device(), c = device();
    pinVerified(a.identity.id, a.identity.public_key);
    const ring = new Keyring();
    const roster = [a, b, c];
    const first = wrapped(a, b, roster, 1);
    importKey(ring, b.keys, b.identity.id, first);
    expect(loadMembership().pins[c.identity.id]).toBe(c.identity.public_key);
    const second = wrapped(c, b, [b, c], 2);
    importKey(ring, b.keys, b.identity.id, second);
    expect(loadMembership().revoked[a.identity.id]).toBe(2);
    const attemptedReadmission = wrapped(c, b, roster, 3);
    expect(() => importKey(ring, b.keys, b.identity.id, attemptedReadmission)).toThrow("re-admit");
    // A partially persisted keyring can still recover earlier, authenticated wraps.
    const recovered = new Keyring();
    importKey(recovered, b.keys, b.identity.id, first);
    importKey(recovered, b.keys, b.identity.id, second);
    expect(recovered.currentVersion).toBe(2);
    const before = ring.keyForVersion(2).slice();
    expect(() => importKey(ring, b.keys, b.identity.id, { ...second, version: 3 })).toThrow("signature");
    expect(() => importKey(ring, b.keys, b.identity.id, { ...second, membership: undefined, version: 3 })).toThrow("downgrade");
    // A wrap whose commitment matches but that was made for another recipient's key never opens.
    const forC = wrapped(c, c, [b, c], 3);
    expect(() => importKey(ring, b.keys, b.identity.id, { ...forC, membership: { ...forC.membership!, wrapped_key_hashes: {
      ...forC.membership!.wrapped_key_hashes, [b.identity.id]: forC.membership!.wrapped_key_hashes[c.identity.id]!,
    } } })).toThrow();
    expect(ring.keyForVersion(2)).toEqual(before);
    expect(ring.currentVersion).toBe(2);
  });

  it("imports the Rust v3 membership response with B's keys and keeps legacy wraps importable", () => {
    const keysB = new DeviceKeys(KeyPair.fromPrivateKey(hex(vectors.priv_b!)), KeyPair.fromPrivateKey(hex(vectors.enc_priv_b!)));
    pinVerified(vectors.sender_id!, Buffer.from(hex(vectors.pub_a!)).toString("base64"));
    const ring = new Keyring();
    const v3 = groupKeysSchema.parse(JSON.parse(vectors.group_keys_v3_json!)).keys[0]!;
    importKey(ring, keysB, vectors.recipient_id!, v3);
    expect(Buffer.from(ring.keyForVersion(1)).toString("hex")).toBe(vectors.group_key);
    expect(loadMembership().version).toBe(1);
    expect(loadMembership().pins[vectors.recipient_id!]).toBe(Buffer.from(hex(vectors.pub_b!)).toString("base64"));
    // The identity key alone cannot open a v3 wrap: a device without B's encryption key is locked out.
    const wrongEncryption = new DeviceKeys(keysB.identity, DeviceKeys.generate().encryption);
    expect(() => importKey(new Keyring(), wrongEncryption, vectors.recipient_id!, v3)).toThrow();
    // The legacy (static-static, 60-byte) response for the same version still imports through the identity key.
    const legacy = groupKeysSchema.parse(JSON.parse(vectors.group_keys_json!)).keys[0]!;
    const legacyRing = new Keyring();
    importKey(legacyRing, keysB, vectors.recipient_id!, legacy);
    expect(Buffer.from(legacyRing.keyForVersion(1)).toString("hex")).toBe(vectors.group_key);
  });

  it("restores historical keys and refuses same-version replacement", () => {
    const ring = new Keyring(), own = device();
    const aad = new TextEncoder().encode("history-context");
    ring.addKeyVersion(1, generateGroupKey());
    const ciphertext = ring.encryptPayload(Buffer.from("history"), aad);
    ring.addKeyVersion(2, generateGroupKey());
    ring.save(statePaths().keyring, own.keys.identity.privateKey);
    const restored = Keyring.load(statePaths().keyring, own.keys.identity.privateKey);
    expect(Buffer.from(restored.decryptPayload(ciphertext.data, 1, aad)).toString()).toBe("history");
    expect(() => restored.addKeyVersion(1, generateGroupKey())).toThrow("replace existing");
    writeFileSync(statePaths().keyring, "corrupted");
    expect(() => Keyring.load(statePaths().keyring, own.keys.identity.privateKey)).toThrow();
  });

  it("resolves sender identity keys from pins, learning a hash-only pin's key only when the hash matches", async () => {
    const a = device(), b = device();
    pinVerified(a.identity.id, a.identity.public_key);
    const listed = vi.fn(async () => [a.listing, b.listing]);
    expect(await senderIdentityKey(a.identity.id, 1, listed)).toEqual(a.keys.identity.publicKeyBytes());
    expect(listed).not.toHaveBeenCalled();
    await expect(senderIdentityKey(b.identity.id, 1, listed)).rejects.toThrow("not a verified member");
    // A hash-only pin (older state file) is upgraded from the relay listing only if SHA-256 matches.
    const hashOf = (key: string) => createHash("sha256").update(Buffer.from(key, "base64")).digest("hex");
    const trust = loadMembership();
    writeFileSync(statePaths().pinnedKeys, JSON.stringify({ ...trust, pins: { ...trust.pins, [b.identity.id]: hashOf(b.identity.public_key) } }));
    const impostor = { ...b.listing, public_key: a.identity.public_key };
    await expect(senderIdentityKey(b.identity.id, 1, async () => [a.listing, impostor])).rejects.toThrow("not a verified member");
    expect(await senderIdentityKey(b.identity.id, 1, listed)).toEqual(b.keys.identity.publicKeyBytes());
    expect(loadMembership().pins[b.identity.id]).toBe(b.identity.public_key);
    // Revocation epochs apply to the version an entry claims.
    const revokedTrust = loadMembership();
    writeFileSync(statePaths().pinnedKeys, JSON.stringify({ ...revokedTrust, revoked: { [a.identity.id]: 2 } }));
    expect(await senderIdentityKey(a.identity.id, 1, listed)).toEqual(a.keys.identity.publicKeyBytes());
    await expect(senderIdentityKey(a.identity.id, 2, listed)).rejects.toThrow("revoked");
  });

  it.each([false, true])("stages rotations and reconciles a lost response (accepted=%s)", async (accepted) => {
    const own = device();
    pinVerified(own.identity.id, own.identity.public_key);
    const ring = new Keyring();
    importKey(ring, own.keys, own.identity.id, wrapped(own, own, [own], 1));
    ring.save(statePaths().keyring, own.keys.identity.privateKey);
    const oldKey = ring.keyForVersion(1).slice();
    const api = new CpmeshApi("http://127.0.0.1");
    let committed: StoreGroupKeyEntry[] | null = null;
    // The relay lists a stale encryption key for us; our own target always uses the local key.
    vi.spyOn(api, "getDeviceKeys").mockResolvedValue({
      devices: [{ ...own.listing, encryption_key: toBase64(DeviceKeys.generate().encryption.publicKeyBytes()), encryption_key_sig: undefined }],
    });
    vi.spyOn(api, "getCurrentGroupKeys").mockImplementation(async () => ({
      current_version: committed ? 2 : 1, rotation_required: false,
      keys: committed ? committed.map((wrap) => ({
        ...wrap, version: 2, from_device_id: own.identity.id, from_public_key: own.identity.public_key,
      })) : [],
    }));
    vi.spyOn(api, "rotateGroupKey").mockImplementation(async (_previous, _next, wraps) => {
      expect(ring.currentVersion).toBe(1);
      expect(Keyring.load(statePaths().keyring, own.keys.identity.privateKey).currentVersion).toBe(1);
      expect(Buffer.from(wraps[0]!.encrypted_key, "base64").length).toBe(WRAP_V3_LEN);
      if (accepted) committed = wraps;
      throw accepted ? new Error("response lost after commit") : new ApiError(409, "conflict");
    });
    if (accepted) await rotateKeys(api, ring, own.keys, own.identity.id);
    else await expect(rotateKeys(api, ring, own.keys, own.identity.id)).rejects.toThrow("conflict");
    expect(ring.currentVersion).toBe(accepted ? 2 : 1);
    expect(ring.keyForVersion(1)).toEqual(oldKey);
    expect(Keyring.load(statePaths().keyring, own.keys.identity.privateKey).currentVersion).toBe(ring.currentVersion);
  });

  it("refuses to rotate while a verified member has no certified encryption key", async () => {
    const own = device(), legacyPeer = device();
    pinVerified(own.identity.id, own.identity.public_key);
    const ring = new Keyring();
    importKey(ring, own.keys, own.identity.id, wrapped(own, own, [own, legacyPeer], 1));
    expect(loadMembership().pins[legacyPeer.identity.id]).toBe(legacyPeer.identity.public_key);
    const api = new CpmeshApi("http://127.0.0.1");
    vi.spyOn(api, "getDeviceKeys").mockResolvedValue({
      devices: [own.listing, { ...legacyPeer.listing, name: "Old desktop", encryption_key: undefined, encryption_key_sig: undefined }],
    });
    vi.spyOn(api, "getCurrentGroupKeys").mockResolvedValue({ current_version: 1, rotation_required: false, keys: [] });
    const rotate = vi.spyOn(api, "rotateGroupKey").mockResolvedValue(undefined);
    await expect(rotateKeys(api, ring, own.keys, own.identity.id)).rejects.toThrow(/"Old desktop" has not published a certified encryption key; update it to protocol 3/);
    expect(rotate).not.toHaveBeenCalled();
    expect(ring.currentVersion).toBe(1);
  });

  it("imports a legacy static-static wrap from a pinned sender through the identity key", () => {
    const a = device(), b = device();
    pinVerified(a.identity.id, a.identity.public_key);
    const key = generateGroupKey();
    const legacy = encryptGroupKey(key, a.keys.identity.privateKey, b.keys.identity.publicKeyBytes());
    expect(legacy.length).toBe(60);
    const ring = new Keyring();
    importKey(ring, b.keys, b.identity.id, {
      version: 1, encrypted_key: toBase64(legacy), from_device_id: a.identity.id, from_public_key: a.identity.public_key,
    });
    expect(ring.keyForVersion(1)).toEqual(key);
  });
});
