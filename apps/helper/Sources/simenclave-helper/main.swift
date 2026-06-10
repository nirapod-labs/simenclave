// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import Foundation
import SimEnclaveHelperKit
import SimEnclaveHostCore

#if canImport(Darwin)
import Darwin
#endif

// The M1 helper: own a Secure Enclave key and answer GENERATE and SIGN over an
// authenticated loopback channel. It mints a per-session capability token, writes
// it to a 0600 file (TokenFile), and gates every request on it. It prints one
// JSON readiness line with the bound port so a caller can discover where to
// connect, then serves until killed. The token is never printed.

let service = SecureEnclaveService()
guard service.isAvailable else {
    FileHandle.standardError.write(Data("simenclave-helper: no Secure Enclave on this host\n".utf8))
    exit(3)
}

let token = CapabilityToken()
do {
    try TokenFile.write(token, toDirectory: TokenFile.defaultDirectory())
} catch {
    FileHandle.standardError.write(Data("simenclave-helper: token file: \(error)\n".utf8))
    exit(1)
}

let listener = LoopbackListener(router: RequestRouter(service: service, gate: AuthGate(session: token)))
do {
    let requested = ProcessInfo.processInfo.environment["SIMENCLAVE_PORT"].flatMap { UInt16($0) } ?? 0
    try listener.start(port: requested)
} catch {
    FileHandle.standardError.write(Data("simenclave-helper: failed to start: \(error)\n".utf8))
    exit(1)
}

print("{\"ready\":true,\"port\":\(listener.port)}")
fflush(stdout)

RunLoop.current.run()
