/**
 * Sealing and opening clipboard entries (protocol v3). Port of
 * desktop-tauri/src-tauri/src/crypto/entry.rs.
 *
 * Every entry is bound to its context (key version, content type, sender,
 * request ID, sender clock) through AES-GCM associated data, and the sender
 * signs that context plus both ciphertexts with its identity key. A relay can
 * therefore neither relabel, splice, re-attribute nor replay an entry.
 */

import {
  type EntryContext,
  KeyPair,
  Keyring,
  clipboardDataAad,
  clipboardMetadataAad,
  clipboardSignatureTranscript,
} from "./crypto.js";

export type { EntryContext } from "./crypto.js";

export interface SealedEntry {
  encryptedData: Uint8Array;
  metadata: Uint8Array;
  keyVersion: number;
  signature: Uint8Array;
}

/**
 * Encrypts data and metadata under the current group key, bound to the
 * context, and signs the result. `context.keyVersion` is ignored: the current
 * version is used and returned.
 */
export function sealEntry(
  keyring: Keyring,
  identity: KeyPair,
  context: Omit<EntryContext, "keyVersion">,
  data: Uint8Array,
  metadataJson: Uint8Array,
): SealedEntry {
  const bound: EntryContext = { ...context, keyVersion: keyring.currentVersion };
  const { data: encryptedData, keyVersion } = keyring.encryptPayload(data, clipboardDataAad(bound));
  const metadata = keyring.encryptPayload(metadataJson, clipboardMetadataAad(bound)).data;
  const signature = identity.signMessage(clipboardSignatureTranscript(bound, encryptedData, metadata));
  return { encryptedData, metadata, keyVersion, signature };
}

/** Checks the sender's signature over the context and both ciphertexts. */
export function verifyEntrySignature(
  senderIdentity: Uint8Array,
  context: EntryContext,
  encryptedData: Uint8Array,
  metadata: Uint8Array,
  signature: Uint8Array,
): boolean {
  return KeyPair.verifyMessage(senderIdentity, clipboardSignatureTranscript(context, encryptedData, metadata), signature);
}

/**
 * Decrypts a verified entry at `context.keyVersion` — no other version is
 * tried, the AAD pins it. Returns the plaintext data and the metadata JSON
 * (empty when the entry carried none).
 */
export function openEntry(
  keyring: Keyring,
  context: EntryContext,
  encryptedData: Uint8Array,
  metadata: Uint8Array,
): { data: Uint8Array; metadataJson: Uint8Array } {
  const data = keyring.decryptPayload(encryptedData, context.keyVersion, clipboardDataAad(context));
  const metadataJson = metadata.length === 0
    ? new Uint8Array(0)
    : keyring.decryptPayload(metadata, context.keyVersion, clipboardMetadataAad(context));
  return { data, metadataJson };
}
