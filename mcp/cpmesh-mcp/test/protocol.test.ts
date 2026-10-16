import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { clipboardAckSchema, groupKeysSchema } from "../src/protocol.js";
import { KeyPair, membershipTranscript } from "../src/crypto.js";

const vectors: Record<string, string> = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
describe("actual Rust serialization contracts", () => {
  it("registration cannot be used as a membership signing oracle", () => {
    const pair = KeyPair.generate();
    const maliciousChallenge = Buffer.from(vectors.membership_transcript!, "hex");
    const proof = Buffer.from(pair.signDeviceChallenge(maliciousChallenge.toString()), "base64");
    expect(KeyPair.verifyMessage(pair.publicKeyBytes(), maliciousChallenge, proof)).toBe(false);
    expect(KeyPair.verifyMessage(pair.publicKeyBytes(),
      Buffer.from(`cpmesh-device-proof-v1\n${maliciousChallenge.toString()}`), proof)).toBe(true);
  });
  it("rejects ambiguous commitments, including ones for other recipients", () => {
    const key = groupKeysSchema.parse(JSON.parse(vectors.group_keys_json!)).keys[0]!;
    const proof = key.membership!;
    const other = proof.members.find((member) => member.id === key.from_device_id)!;
    const hashes = { ...proof.wrapped_key_hashes, [other.id]: proof.wrapped_key_hashes[other.id] + "\ninjected:row" };
    expect(() => membershipTranscript(key.version, key.from_device_id, proof.members, hashes)).toThrow("invalid wrapped-key commitments");
  });
  it("parses Rust persistence acknowledgements and membership responses", () => {
    expect(clipboardAckSchema.parse(JSON.parse(vectors.clipboard_ack_json!)).status).toBe("accepted");
    const response = groupKeysSchema.parse(JSON.parse(vectors.group_keys_json!));
    const key = response.keys[0]!;
    const transcript = membershipTranscript(key.version, key.from_device_id, key.membership!.members, key.membership!.wrapped_key_hashes);
    expect(Buffer.from(transcript).toString("hex")).toBe(vectors.membership_transcript);
    expect(KeyPair.verifyMessage(
      Buffer.from(key.from_public_key, "base64"), transcript, Buffer.from(key.membership!.signature, "base64"),
    )).toBe(true);
    expect(vectors.approval_code_ab).toMatch(/^[0-9A-F]{64}$/);
  });
});
