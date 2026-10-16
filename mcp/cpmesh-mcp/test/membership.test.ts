import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CpmeshApi, ApiError } from "../src/api.js";
import { generateGroupKey, KeyPair, Keyring, signedWraps } from "../src/crypto.js";
import { importKey, pinVerified, rotateKeys } from "../src/membership.js";
import { loadMembership, statePaths } from "../src/state.js";
import type { DeviceIdentity, StoreGroupKeyEntry, VersionedGroupKey } from "../src/protocol.js";

let home: string;
beforeEach(() => { home = mkdtempSync(join(tmpdir(), "cpmesh-trust-")); process.env.CPMESH_HOME = home; });
afterEach(() => { delete process.env.CPMESH_HOME; rmSync(home, { recursive: true, force: true }); });
function device() {
  const pair = KeyPair.generate();
  return { pair, identity: { id: randomUUID(), public_key: Buffer.from(pair.publicKeyBytes()).toString("base64") } };
}
function wrapped(sender: ReturnType<typeof device>, recipient: DeviceIdentity, members: DeviceIdentity[], version: number, key = generateGroupKey()): VersionedGroupKey {
  const wraps = signedWraps(sender.pair, sender.identity.id, version, key, members);
  const wrap = wraps.find((entry) => entry.device_id === recipient.id)!;
  return { ...wrap, membership: wraps[0]!.membership, from_device_id: sender.identity.id, from_public_key: sender.identity.public_key, version };
}

describe("locally authenticated membership", () => {
  it("supports subscription-sized meshes without repeating the roster for every wrap", () => {
    const owner = device();
    const peers = Array.from({ length: 127 }, () => device());
    const roster = [owner.identity, ...peers.map((peer) => peer.identity)];
    const wraps = signedWraps(owner.pair, owner.identity.id, 1, generateGroupKey(), roster);
    expect(wraps).toHaveLength(128);
    expect(wraps.filter((wrap) => wrap.membership !== undefined)).toHaveLength(1);
    expect(Buffer.byteLength(JSON.stringify(wraps))).toBeLessThan(128 * 1024);
  });
  it("rejects an unknown sender even with a valid self-signature, including legacy TOFU files", () => {
    const attacker = device(), honest = device();
    const key = wrapped(attacker, honest.identity, [attacker.identity, honest.identity], 1);
    key.from_public_key_sig = Buffer.from(attacker.pair.signPublicKey()).toString("base64");
    writeFileSync(join(home, "pinned_keys.json"), JSON.stringify({ [attacker.identity.id]: attacker.identity.public_key }));
    const ring = new Keyring();
    expect(() => importKey(ring, honest.pair, honest.identity.id, key)).toThrow("not independently verified");
    expect(ring.currentVersion).toBe(0);
    expect(loadMembership().pins).toEqual({});
  });

  it("admits new members only through a pinned sender's authenticated transition", () => {
    const a = device(), b = device(), c = device();
    pinVerified(a.identity.id, a.identity.public_key);
    const ring = new Keyring();
    const roster = [a.identity, b.identity, c.identity];
    const first = wrapped(a, b.identity, roster, 1);
    importKey(ring, b.pair, b.identity.id, first);
    expect(loadMembership().pins[c.identity.id]).toBe(c.identity.public_key);
    const second = wrapped(c, b.identity, [b.identity, c.identity], 2);
    importKey(ring, b.pair, b.identity.id, second);
    expect(loadMembership().revoked[a.identity.id]).toBe(2);
    const attemptedReadmission = wrapped(c, b.identity, roster, 3);
    expect(() => importKey(ring, b.pair, b.identity.id, attemptedReadmission)).toThrow("re-admit");
    // A partially persisted keyring can still recover earlier, authenticated wraps.
    const recovered = new Keyring();
    importKey(recovered, b.pair, b.identity.id, first);
    importKey(recovered, b.pair, b.identity.id, second);
    expect(recovered.currentVersion).toBe(2);
    const before = ring.keyForVersion(2).slice();
    expect(() => importKey(ring, b.pair, b.identity.id, { ...second, version: 3 })).toThrow("signature");
    expect(() => importKey(ring, b.pair, b.identity.id, { ...second, membership: undefined, version: 3 })).toThrow("downgrade");
    expect(ring.keyForVersion(2)).toEqual(before);
    expect(ring.currentVersion).toBe(2);
  });

  it("restores historical keys and refuses same-version replacement", () => {
    const ring = new Keyring(), own = device();
    ring.addKeyVersion(1, generateGroupKey());
    const ciphertext = ring.encryptPayload(Buffer.from("history"));
    ring.addKeyVersion(2, generateGroupKey());
    ring.save(statePaths().keyring, own.pair.privateKey);
    const restored = Keyring.load(statePaths().keyring, own.pair.privateKey);
    expect(Buffer.from(restored.decryptPayload(ciphertext.data, 1)).toString()).toBe("history");
    expect(() => restored.addKeyVersion(1, generateGroupKey())).toThrow("replace existing");
    writeFileSync(statePaths().keyring, "corrupted");
    expect(() => Keyring.load(statePaths().keyring, own.pair.privateKey)).toThrow();
  });

  it.each([false, true])("stages rotations and reconciles a lost response (accepted=%s)", async (accepted) => {
    const own = device();
    pinVerified(own.identity.id, own.identity.public_key);
    const ring = new Keyring();
    importKey(ring, own.pair, own.identity.id, wrapped(own, own.identity, [own.identity], 1));
    ring.save(statePaths().keyring, own.pair.privateKey);
    const oldKey = ring.keyForVersion(1).slice();
    const api = new CpmeshApi("http://127.0.0.1");
    let committed: StoreGroupKeyEntry[] | null = null;
    vi.spyOn(api, "getDeviceKeys").mockResolvedValue({
      devices: [{ ...own.identity, name: "Own", online: true, status: "approved" }],
    });
    vi.spyOn(api, "getCurrentGroupKeys").mockImplementation(async () => ({
      current_version: committed ? 2 : 1, rotation_required: false,
      keys: committed ? committed.map((wrap) => ({
        ...wrap, version: 2, from_device_id: own.identity.id, from_public_key: own.identity.public_key,
      })) : [],
    }));
    vi.spyOn(api, "rotateGroupKey").mockImplementation(async (_previous, _next, wraps) => {
      expect(ring.currentVersion).toBe(1);
      expect(Keyring.load(statePaths().keyring, own.pair.privateKey).currentVersion).toBe(1);
      if (accepted) committed = wraps;
      throw accepted ? new Error("response lost after commit") : new ApiError(409, "conflict");
    });
    if (accepted) await rotateKeys(api, ring, own.pair, own.identity.id);
    else await expect(rotateKeys(api, ring, own.pair, own.identity.id)).rejects.toThrow("conflict");
    expect(ring.currentVersion).toBe(accepted ? 2 : 1);
    expect(ring.keyForVersion(1)).toEqual(oldKey);
    expect(Keyring.load(statePaths().keyring, own.pair.privateKey).currentVersion).toBe(ring.currentVersion);
  });
});
