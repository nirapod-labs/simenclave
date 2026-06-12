// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import ExpoSecureEnclave, { type NativeKeyFacts } from "../../../modules/expo-secure-enclave";
import type { SecureEnclaveProvider } from "../provider";
import {
  type GenerateOptions,
  type KeyGate,
  type KeyRecord,
  PROTECTIONS,
  type Protection,
  type SignOptions,
  type SignatureRecord,
  type VerifyOptions,
} from "../types";

// Adapter over the first-party raw-SecKey native module. This is the full-fidelity provider: it
// drives every access-control gate, the protection class, permanent keys with an arbitrary tag,
// both sign modes, and the SecItem keychain operations. The class, protection, and a sequence ride
// in the application tag (exactly as the native console does), so a relaunch rebuilds each row from
// the keychain alone, with no app-side store.
const TAG_PREFIX = "dev.simenclave.example";

function utf8ToHex(text: string): string {
  let hex = "";
  for (const byte of new TextEncoder().encode(text)) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

function makeTag(gate: KeyGate, protection: Protection, seq: number): string {
  const protectionIndex = PROTECTIONS.findIndex((p) => p.id === protection);
  const uuid = `${Date.now().toString(16)}-${Math.floor(Math.random() * 1e9).toString(16)}`;
  return `${TAG_PREFIX}|v1|${gate}|${protectionIndex}|${seq}|${uuid}`;
}

function parseTag(tag: string): { gate: KeyGate; protection: Protection; seq: number } | null {
  const parts = tag.split("|");
  if (parts.length !== 6 || parts[0] !== TAG_PREFIX || parts[1] !== "v1") return null;
  const gate = parts[2] as KeyGate;
  const protectionIndex = Number(parts[3]);
  const seq = Number(parts[4]);
  const protection = PROTECTIONS[protectionIndex]?.id;
  if (!protection || Number.isNaN(seq)) return null;
  return { gate, protection, seq };
}

/**
 * Build the raw-SecKey provider: the full-fidelity {@link SecureEnclaveProvider} over the
 * first-party native module. It drives every access-control gate, the protection class, permanent
 * keys with an arbitrary tag, both sign modes, and the SecItem keychain ops. The gate, protection,
 * and a sequence ride in the application tag, so a relaunch rebuilds each row from the keychain.
 */
export function createRawProvider(): SecureEnclaveProvider {
  // The tag for each live handle, so deleteKey can also drop the keychain item.
  const tagByHandle = new Map<string, string | null>();
  let seq = 0;

  function record(
    facts: NativeKeyFacts,
    gate: KeyGate,
    protection: Protection,
    s: number,
  ): KeyRecord {
    tagByHandle.set(facts.handle, facts.tag);
    return {
      id: facts.handle,
      seq: s,
      gate,
      protection,
      hardwareBacked: facts.hardwareBacked,
      tokenID: facts.tokenID,
      publicKeyHex: facts.publicKeyHex,
      publicKeyBytes: facts.publicKeyBytes,
      createdAt: Date.now(),
      tag: facts.tag,
    };
  }

  return {
    id: "raw",
    name: "Raw SecKey",
    library: "first-party expo-secure-enclave",
    detail: "Issues SecKeyCreateRandomKey / SecKeyCreateSignature / SecItem* directly.",
    capabilities: {
      gates: ["silent", "biometry", "presence", "passcode"],
      protection: true,
      customTag: true,
      persist: true,
      signModes: ["digest", "message"],
      keychain: true,
      enumerate: true,
    },

    async isAvailable() {
      return ExpoSecureEnclave.isAvailable();
    },

    async generate({ gate, protection, persist }: GenerateOptions) {
      const next = seq + 1;
      const tag = persist ? makeTag(gate, protection, next) : null;
      const facts = await ExpoSecureEnclave.generate(gate, protection, persist, tag);
      seq = next;
      return record(facts, gate, protection, next);
    },

    async sign({ keyId, message, mode }: SignOptions): Promise<SignatureRecord> {
      const derHex = await ExpoSecureEnclave.sign(keyId, utf8ToHex(message), mode);
      return { derHex, bytes: derHex.length / 2, mode, verified: null };
    },

    async verify({ keyId, message, mode, signatureDerHex, tamper }: VerifyOptions) {
      return ExpoSecureEnclave.verify(keyId, utf8ToHex(message), mode, signatureDerHex, tamper);
    },

    async loadKeys() {
      const facts = await ExpoSecureEnclave.loadKeys();
      const out: KeyRecord[] = [];
      let maxSeq = 0;
      for (const f of facts) {
        const meta = f.tag ? parseTag(f.tag) : null;
        if (!meta) continue; // a tag in another shape is not one of ours
        maxSeq = Math.max(maxSeq, meta.seq);
        out.push(record(f, meta.gate, meta.protection, meta.seq));
      }
      seq = Math.max(seq, maxSeq);
      return out.sort((a, b) => b.seq - a.seq);
    },

    async deleteKey(keyId: string) {
      await ExpoSecureEnclave.deleteKey(keyId, tagByHandle.get(keyId) ?? null);
      tagByHandle.delete(keyId);
    },

    async keychainAdd(keyId: string, tag: string) {
      await ExpoSecureEnclave.keychainAdd(keyId, tag);
    },

    async keychainFind(tag: string) {
      const facts = await ExpoSecureEnclave.keychainFind(tag);
      if (!facts) return null;
      const meta = facts.tag ? parseTag(facts.tag) : null;
      return record(
        facts,
        meta?.gate ?? "silent",
        meta?.protection ?? "whenUnlockedThisDevice",
        meta?.seq ?? ++seq,
      );
    },

    async keychainDelete(tag: string) {
      await ExpoSecureEnclave.keychainDelete(tag);
    },
  };
}
