import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  PAIRING_VERSION, PROTOCOL_VERSION, WRAP_V3_LEN, clipboardAckSchema, clipboardEntrySchema, clipboardNewSchema, groupKeysSchema,
} from "../src/protocol.js";
import { KeyPair, membershipTranscript, wrappedKeyHash } from "../src/crypto.js";

const vectors: Record<string, string> = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
describe("actual Rust serialization contracts", () => {
  it("speaks protocol 3 with pairing version 3", () => {
    expect(PROTOCOL_VERSION).toBe("3");
    expect(PAIRING_VERSION).toBe(3);
  });
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
  it("parses Rust persistence acknowledgements and legacy membership responses", () => {
    expect(clipboardAckSchema.parse(JSON.parse(vectors.clipboard_ack_json!)).status).toBe("accepted");
    const response = groupKeysSchema.parse(JSON.parse(vectors.group_keys_json!));
    const key = response.keys[0]!;
    const transcript = membershipTranscript(key.version, key.from_device_id, key.membership!.members, key.membership!.wrapped_key_hashes);
    expect(Buffer.from(transcript).toString("hex")).toBe(vectors.membership_transcript);
    expect(KeyPair.verifyMessage(
      Buffer.from(key.from_public_key, "base64"), transcript, Buffer.from(key.membership!.signature, "base64"),
    )).toBe(true);
    expect(vectors.pairing_fingerprint_ab).toMatch(/^[0-9A-F]{64}$/);
  });
  it("parses v3 membership responses: unchanged transcript format over 125-byte wraps", () => {
    const response = groupKeysSchema.parse(JSON.parse(vectors.group_keys_v3_json!));
    const key = response.keys[0]!;
    const wrap = Buffer.from(key.encrypted_key, "base64");
    expect(wrap.length).toBe(WRAP_V3_LEN);
    expect(wrap.toString("hex")).toBe(vectors.wrap_v3_blob);
    expect(key.membership!.wrapped_key_hashes[vectors.recipient_id!]).toBe(wrappedKeyHash(wrap));
    expect(key.membership!.wrapped_key_hashes[vectors.sender_id!]).toBe(wrappedKeyHash(Buffer.from(vectors.self_wrap_v3_blob!, "hex")));
    const transcript = membershipTranscript(key.version, key.from_device_id, key.membership!.members, key.membership!.wrapped_key_hashes);
    expect(Buffer.from(transcript).toString("hex")).toBe(vectors.membership_transcript_v3);
    expect(Buffer.from(transcript).toString("utf8").startsWith("cpmesh-membership-v2\n")).toBe(true);
    expect(Buffer.from(key.membership!.signature, "base64").toString("hex")).toBe(vectors.membership_signature_v3);
    expect(KeyPair.verifyMessage(Buffer.from(key.from_public_key, "base64"), transcript, Buffer.from(key.membership!.signature, "base64"))).toBe(true);
  });
  it("parses relay entries with and without the v3 signature fields", () => {
    const base = {
      id: "e1", user_id: "u1", device_id: vectors.sender_id!, device_name: "A", content_type: "text",
      encrypted_data: Buffer.from(vectors.payload_v3_full!, "hex").toString("base64"),
      metadata: Buffer.from(vectors.metadata_v3_full!, "hex").toString("base64"),
      created_at: "2026-01-01T00:00:00Z", key_version: 1,
    };
    expect(clipboardEntrySchema.parse(base).sender_signature).toBeUndefined();
    const signed = clipboardNewSchema.parse({ entry: {
      ...base, request_id: vectors.request_id, sent_at: 1_700_000_000_123,
      sender_signature: Buffer.from(vectors.sender_signature!, "hex").toString("base64"),
    } }).entry;
    expect(signed.sent_at).toBe(1_700_000_000_123);
    expect(() => clipboardEntrySchema.parse({ ...base, sent_at: -1 })).toThrow();
    expect(() => clipboardEntrySchema.parse({ ...base, request_id: "nope" })).toThrow();
    expect(() => clipboardEntrySchema.parse({ ...base, device_id: vectors.sender_id!.toUpperCase().replace("0", "A") })).toThrow();
  });
});
