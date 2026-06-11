// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// The Secure Enclave domain, mirrored from the native SwiftUI console so the two example apps
// describe the same operations in the same words. A provider (below) turns these into the real
// native SecKey/SecItem calls; SimEnclave hooks those, so the UI never knows or cares whether it
// runs against a device's SEP or, in the Simulator, the host Mac's.

/** The access-control gate a key is created with: a real SecAccessControlCreateFlags set. */
export type KeyGate = "silent" | "biometry" | "presence" | "passcode";

export const KEY_GATES: { id: KeyGate; label: string; symbol: string }[] = [
  { id: "silent", label: "Silent", symbol: "lock" },
  { id: "biometry", label: "Biometry", symbol: "faceid" },
  { id: "presence", label: "Presence", symbol: "hand.raised" },
  { id: "passcode", label: "Passcode", symbol: "number" },
];

/** The keychain protection class a key is bound to. */
export type Protection =
  | "whenUnlockedThisDevice"
  | "whenUnlocked"
  | "afterFirstUnlockThisDevice"
  | "afterFirstUnlock";

export const PROTECTIONS: { id: Protection; label: string; short: string }[] = [
  { id: "whenUnlockedThisDevice", label: "When unlocked, this device", short: "WhenUnlocked" },
  { id: "whenUnlocked", label: "When unlocked", short: "WhenUnlocked" },
  {
    id: "afterFirstUnlockThisDevice",
    label: "After first unlock, this device",
    short: "AfterFirstUnlock",
  },
  { id: "afterFirstUnlock", label: "After first unlock", short: "AfterFirstUnlock" },
];

/** Digest mode signs a SHA-256 the app computed; message mode hands the raw message to the SEP. */
export type SignMode = "digest" | "message";

export const SIGN_MODES: { id: SignMode; label: string }[] = [
  { id: "digest", label: "Digest" },
  { id: "message", label: "Message" },
];

/** One key a provider has minted or loaded, with the facts the UI shows. */
export interface KeyRecord {
  id: string;
  seq: number;
  gate: KeyGate;
  protection: Protection;
  /** False when the private key is exportable, i.e. a software fallback, not the Secure Enclave. */
  hardwareBacked: boolean;
  tokenID: string;
  publicKeyHex: string;
  publicKeyBytes: number;
  createdAt: number;
  /** The application tag a permanent key is stored under, null for an ephemeral key. */
  tag: string | null;
}

/** The last signature a provider produced. */
export interface SignatureRecord {
  derHex: string;
  bytes: number;
  mode: SignMode;
  verified: boolean | null;
}

/** What a provider can actually do, so the UI can disable controls a provider does not support
 *  rather than fail at call time. The raw-SecKey provider drives all of them; the shape stays so a
 *  more constrained provider could be added without touching the screens. */
export interface ProviderCapabilities {
  gates: KeyGate[];
  /** Can the protection class be chosen, or is it fixed by the library? */
  protection: boolean;
  /** Can an arbitrary application tag be set (permanent keys, find-by-tag)? */
  customTag: boolean;
  persist: boolean;
  signModes: SignMode[];
  /** SecItem add / find / delete by tag. */
  keychain: boolean;
  /** Enumerate existing keys (SecItemCopyMatching with kSecMatchLimitAll). */
  enumerate: boolean;
}

export interface GenerateOptions {
  gate: KeyGate;
  protection: Protection;
  persist: boolean;
}

export interface SignOptions {
  keyId: string;
  message: string;
  mode: SignMode;
}

export interface VerifyOptions {
  keyId: string;
  message: string;
  mode: SignMode;
  signatureDerHex: string;
  /** Flip a byte of the input first, to prove a tampered message is rejected. */
  tamper: boolean;
}
