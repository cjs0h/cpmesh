import { ApiError, type CpmeshApi } from "./api.js";
import { generateGroupKey, KeyPair, Keyring, membershipTranscript, signedWraps, wrappedKeyHash } from "./crypto.js";
import { loadMembership, saveMembership, statePaths } from "./state.js";
import type { DeviceIdentity, GroupKeysResponse, VersionedGroupKey } from "./protocol.js";

export class SecurityError extends Error {}
const publicBytes = (value: string) => new Uint8Array(Buffer.from(value, "base64"));
const publicBase64 = (pair: KeyPair) => Buffer.from(pair.publicKeyBytes()).toString("base64");

export function pinVerified(deviceId: string, publicKey: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(deviceId)) {
    throw new SecurityError("Invalid device identity");
  }
  const trust = loadMembership();
  if (trust.revoked[deviceId] !== undefined) throw new SecurityError("Device was revoked; register a new identity");
  if (trust.pins[deviceId] && trust.pins[deviceId] !== publicKey) throw new SecurityError("Verified device key changed");
  KeyPair.parsePublicKey(publicBytes(publicKey));
  saveMembership(trust.version, { ...trust.pins, [deviceId]: publicKey });
}

export function revokeDevice(deviceId: string): void {
  const trust = loadMembership();
  const revoked = { ...trust.revoked, [deviceId]: trust.revoked[deviceId] ?? trust.version + 1 };
  saveMembership(trust.version, trust.pins, revoked, true);
}

export function importKey(ring: Keyring, pair: KeyPair, ownId: string, key: VersionedGroupKey): void {
  const trust = loadMembership();
  if (trust.pins[key.from_device_id] !== key.from_public_key) {
    throw new SecurityError(`Device ${key.from_device_id} is not independently verified. Use cpmesh_verify_device; do not trust a relay-provided self-signature.`);
  }
  const revokedAt = trust.revoked[key.from_device_id];
  if (revokedAt !== undefined && key.version >= revokedAt) throw new SecurityError("Key sender has been revoked");
  const membership = key.membership;
  if (!membership && trust.version > 0 && key.version >= trust.version) throw new SecurityError("Refusing a legacy key downgrade after authenticated membership");
  if (membership) {
    const ids = new Set(membership.members.map((member) => member.id));
    if (ids.size !== membership.members.length ||
        !membership.members.some((m) => m.id === ownId && m.public_key === publicBase64(pair)) ||
        !membership.members.some((m) => m.id === key.from_device_id && m.public_key === key.from_public_key)) {
      throw new SecurityError("Invalid authenticated membership");
    }
    for (const member of membership.members) KeyPair.parsePublicKey(publicBytes(member.public_key));
    if (membership.wrapped_key_hashes[ownId] !== wrappedKeyHash(publicBytes(key.encrypted_key))) {
      throw new SecurityError("Wrapped key does not match the authenticated recipient commitment");
    }
    if (!KeyPair.verifyMessage(publicBytes(key.from_public_key), membershipTranscript(
      key.version, key.from_device_id, membership.members, membership.wrapped_key_hashes,
    ), publicBytes(membership.signature))) throw new SecurityError("Membership signature is invalid");
  }
  const candidate = ring.clone();
  candidate.decryptFromDevice(publicBytes(key.encrypted_key), pair.privateKey, publicBytes(key.from_public_key), key.version);
  if (membership && key.version >= trust.version) {
    const pins: Record<string, string> = {};
    for (const member of membership.members) {
      const epoch = trust.revoked[member.id];
      if (epoch !== undefined && key.version >= epoch) throw new SecurityError("Membership attempts to re-admit a revoked device");
      if (trust.pins[member.id] && trust.pins[member.id] !== member.public_key) throw new SecurityError("Verified member key changed");
      pins[member.id] = member.public_key;
    }
    if (key.version === trust.version) {
      const active = Object.keys(trust.pins).filter((id) => trust.revoked[id] === undefined);
      if (!trust.rotation_required && (Object.keys(pins).length !== active.length ||
          Object.entries(pins).some(([id, publicKey]) => trust.pins[id] !== publicKey))) {
        throw new SecurityError("Conflicting membership for an existing version");
      }
    } else {
      const revoked = { ...trust.revoked };
      for (const id of Object.keys(trust.pins)) {
        if (!pins[id] && revoked[id] === undefined) revoked[id] = key.version;
      }
      saveMembership(key.version, { ...trust.pins, ...pins }, revoked, false);
    }
  }
  ring.replaceWith(candidate);
}

async function trustedMembers(api: CpmeshApi, pair: KeyPair, ownId: string): Promise<DeviceIdentity[]> {
  pinVerified(ownId, publicBase64(pair));
  const trust = loadMembership();
  const { devices } = await api.getDeviceKeys();
  return devices.filter((d) => d.status === "approved").map((device) => {
    if (!device.public_key || trust.pins[device.id] !== device.public_key || trust.revoked[device.id] !== undefined) {
      throw new SecurityError(`Verify device ${device.name} with cpmesh_verify_device before distributing keys`);
    }
    return { id: device.id, public_key: device.public_key };
  });
}

export async function synchronizeKeys(api: CpmeshApi, ring: Keyring, pair: KeyPair, ownId: string): Promise<boolean> {
  pinVerified(ownId, publicBase64(pair));
  const candidate = ring.clone();
  let response: GroupKeysResponse;
  try {
    response = await api.getCurrentGroupKeys(candidate.currentVersion);
  } catch (error) {
    if (!(error instanceof ApiError) || error.status !== 404) throw error;
    const members = await trustedMembers(api, pair, ownId);
    if (members.length !== 1 || members[0]?.id !== ownId || candidate.currentVersion > 1) {
      throw new SecurityError("Missing mesh state is not a new mesh. Restore the keyring or verify an existing device.");
    }
    const groupKey = candidate.hasVersion(1) ? candidate.keyForVersion(1).slice() : generateGroupKey();
    const wraps = signedWraps(pair, ownId, 1, groupKey, members);
    groupKey.fill(0);
    let failure: unknown;
    try { await api.rotateGroupKey(0, 1, wraps); } catch (error) { failure = error; }
    try { response = await api.getCurrentGroupKeys(0); } catch (error) { throw failure ?? error; }
  }
  for (;;) {
    if (response.current_version < candidate.currentVersion || response.current_version < loadMembership().version) throw new SecurityError("Server key version rolled back");
    const before = candidate.currentVersion;
    for (const key of response.keys) importKey(candidate, pair, ownId, key);
    if (candidate.hasVersion(response.current_version)) break;
    if (candidate.currentVersion <= before) throw new SecurityError("Current wrapped key is missing; refusing to regenerate it");
    response = await api.getCurrentGroupKeys(candidate.currentVersion);
  }
  candidate.save(statePaths().keyring, pair.privateKey);
  ring.replaceWith(candidate);
  return loadMembership().rotation_required || loadMembership().version < response.current_version || response.rotation_required === true ||
    (response.rotation_due_at !== undefined && Date.parse(response.rotation_due_at) <= Date.now());
}

export async function rotateKeys(api: CpmeshApi, ring: Keyring, pair: KeyPair, ownId: string): Promise<void> {
  await synchronizeKeys(api, ring, pair, ownId);
  const members = await trustedMembers(api, pair, ownId);
  const version = ring.currentVersion + 1;
  const groupKey = generateGroupKey();
  const wraps = signedWraps(pair, ownId, version, groupKey, members);
  groupKey.fill(0);
  let failure: unknown;
  try { await api.rotateGroupKey(ring.currentVersion, version, wraps); } catch (error) { failure = error; }
  const required = await synchronizeKeys(api, ring, pair, ownId);
  if (!required && ring.currentVersion >= version) return;
  throw failure ?? new Error("Rotation was not confirmed; candidate key was not activated");
}
