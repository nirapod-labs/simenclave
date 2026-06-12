// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import { createRawProvider } from "./providers/raw";

/**
 * The example's one Secure Enclave provider: the first-party raw-SecKey adapter, which reaches the
 * real hardware Secure Enclave through SimEnclave. A biometrics-library adapter was dropped because
 * that library mints a software-backed key, which contradicts this example's point (hardware keys).
 */
export const secureEnclaveProvider = createRawProvider();
