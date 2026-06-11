// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

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
let tokenDirectory = TokenFile.defaultDirectory()
do {
    try TokenFile.write(token, toDirectory: tokenDirectory)
} catch {
    FileHandle.standardError.write(Data("simenclave-helper: token file: \(error)\n".utf8))
    exit(1)
}

// The session credential dies with the session: remove the token file on SIGINT
// and SIGTERM (the ways a CLI helper is normally stopped) and on a normal exit,
// the same hygiene the menubar's stop and quit paths have. A SIGKILL leaves the
// file; the next start then refuses loudly with the stale path, never truncates.
atexit { TokenFile.remove(fromDirectory: TokenFile.defaultDirectory()) }
let terminationSignals: [Int32] = [SIGINT, SIGTERM]
let signalSources: [DispatchSourceSignal] = terminationSignals.map { number in
    signal(number, SIG_IGN)
    let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
    source.setEventHandler {
        TokenFile.remove(fromDirectory: tokenDirectory)
        TokenFile.removePort(fromDirectory: tokenDirectory)
        exit(0)
    }
    source.resume()
    return source
}

let listener = LoopbackListener(router: RequestRouter(service: service, gate: AuthGate(session: token)))
do {
    let requested = ProcessInfo.processInfo.environment["SIMENCLAVE_PORT"].flatMap { UInt16($0) } ?? 0
    try listener.start(port: requested)
} catch {
    FileHandle.standardError.write(Data("simenclave-helper: failed to start: \(error)\n".utf8))
    // The token file exists by here; remove it on this failure path explicitly,
    // not only through the atexit backstop, so a start failure leaves nothing behind.
    TokenFile.remove(fromDirectory: tokenDirectory)
    exit(1)
}

TokenFile.writePort(listener.port, toDirectory: tokenDirectory)

print("{\"ready\":true,\"port\":\(listener.port)}")
fflush(stdout)

RunLoop.current.run()
