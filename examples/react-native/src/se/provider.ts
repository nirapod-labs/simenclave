// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import type {
  GenerateOptions,
  KeyRecord,
  ProviderCapabilities,
  SignOptions,
  SignatureRecord,
  VerifyOptions,
} from "./types";

// The seam the whole demo turns on. The UI talks to a SecureEnclaveProvider; two adapters
// implement it over two genuinely different React Native libraries, and the active one is
// switchable at runtime. Both adapters end up at the same native SecKey/SecItem C calls, which
// is exactly what SimEnclave hooks, so flipping the provider proves the tool is framework- and
// library-agnostic: it never sees React Native, only the Security framework calls underneath.
export interface SecureEnclaveProvider {
  /** Stable id used to persist the selection and key it in the picker. */
  readonly id: string;
  /** Human label for the picker. */
  readonly name: string;
  /** The npm package (or "first-party") this adapter drives, shown so the proof is legible. */
  readonly library: string;
  /** One line on how this adapter reaches the Secure Enclave. */
  readonly detail: string;
  /** What this adapter can actually do, so the UI disables what it cannot rather than failing. */
  readonly capabilities: ProviderCapabilities;

  /** Whether the underlying library reports a usable Secure Enclave on this device. */
  isAvailable(): Promise<boolean>;

  /** Mint a key and return its facts. Throws with a readable message on failure. */
  generate(options: GenerateOptions): Promise<KeyRecord>;

  /** Sign a message with the key named by `keyId`; returns the DER signature. */
  sign(options: SignOptions): Promise<SignatureRecord>;

  /** Verify a signature this provider produced, optionally over a tampered input. */
  verify(options: VerifyOptions): Promise<boolean>;

  /** Every key this provider can currently see (its native enumeration). */
  loadKeys(): Promise<KeyRecord[]>;

  /** Remove the key named by `keyId`. */
  deleteKey(keyId: string): Promise<void>;

  // The keychain-by-tag operations are optional: a provider exposes them only when
  // `capabilities.keychain` is true (the raw SecItem adapter), and the UI hides the tab otherwise.

  /** SecItemAdd the current key under `tag`. */
  keychainAdd?(keyId: string, tag: string): Promise<void>;

  /** SecItemCopyMatching the key stored under `tag`, or null if none. */
  keychainFind?(tag: string): Promise<KeyRecord | null>;

  /** SecItemDelete the key stored under `tag`. */
  keychainDelete?(tag: string): Promise<void>;
}
