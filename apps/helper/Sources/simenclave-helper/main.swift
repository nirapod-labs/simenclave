import Foundation
import SimEnclaveHelperKit
import SimEnclaveHostCore

#if canImport(Darwin)
import Darwin
#endif

// The M0 helper: own a Secure Enclave key and answer GENERATE and SIGN over
// loopback. It prints one JSON readiness line with the bound port so a caller
// (the interposer, a test, or simenclavectl) can discover where to connect, then
// serves until killed. A signed menubar app and a capability token are M1.

let service = SecureEnclaveService()
guard service.isAvailable else {
    FileHandle.standardError.write(Data("simenclave-helper: no Secure Enclave on this host\n".utf8))
    exit(3)
}

let listener = LoopbackListener(router: RequestRouter(service: service))
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
