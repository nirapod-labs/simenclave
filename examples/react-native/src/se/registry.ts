// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import { createRawProvider } from "./providers/raw";

// One provider: the first-party raw-SecKey module that reaches the real hardware Secure Enclave
// through SimEnclave. A biometrics-library adapter was dropped because that library mints a
// software-backed key, which contradicts the point of this example (genuine hardware keys).
export const secureEnclaveProvider = createRawProvider();
