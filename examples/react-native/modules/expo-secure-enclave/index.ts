// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import { requireNativeModule } from "expo";

import type { KeyGate, Protection, SignMode } from "../../src/se/types";

/** The facts the native module returns for a key. */
export interface NativeKeyFacts {
  handle: string;
  hardwareBacked: boolean;
  tokenID: string;
  publicKeyHex: string;
  publicKeyBytes: number;
  tag: string | null;
}

/** The raw SecKey/SecItem surface, implemented in Swift (ios/ExpoSecureEnclaveModule.swift). Every
 *  method is the real Security-framework call; SimEnclave hooks these in the Simulator. */
export interface ExpoSecureEnclaveNativeModule {
  isAvailable(): boolean;
  generate(
    gate: KeyGate,
    protection: Protection,
    persist: boolean,
    tag: string | null,
  ): Promise<NativeKeyFacts>;
  /** `messageHex` is the UTF-8 message as hex; the module hashes it for digest mode. Returns DER hex. */
  sign(handle: string, messageHex: string, mode: SignMode): Promise<string>;
  verify(
    handle: string,
    messageHex: string,
    mode: SignMode,
    signatureHex: string,
    tamper: boolean,
  ): Promise<boolean>;
  deleteKey(handle: string, tag: string | null): Promise<void>;
  loadKeys(): Promise<NativeKeyFacts[]>;
  keychainAdd(handle: string, tag: string): Promise<void>;
  keychainFind(tag: string): Promise<NativeKeyFacts | null>;
  keychainDelete(tag: string): Promise<void>;
}

export default requireNativeModule<ExpoSecureEnclaveNativeModule>("ExpoSecureEnclave");
