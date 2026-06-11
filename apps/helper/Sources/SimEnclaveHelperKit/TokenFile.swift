// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation

#if canImport(Darwin)
import Darwin
private func posixWrite(_ fd: Int32, _ buffer: UnsafeRawPointer, _ count: Int) -> Int {
    Darwin.write(fd, buffer, count)
}
private func posixRead(_ fd: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int) -> Int {
    Darwin.read(fd, buffer, count)
}
#else
import Glibc
private func posixWrite(_ fd: Int32, _ buffer: UnsafeRawPointer, _ count: Int) -> Int {
    Glibc.write(fd, buffer, count)
}
private func posixRead(_ fd: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int) -> Int {
    Glibc.read(fd, buffer, count)
}
#endif

/// Writes and reads the session token file with the creation invariants from
/// docs/design/m1-helper.md. The directory is `0700`, and if it already exists
/// it must be owned by the real uid, not a symlink, and not group or world
/// writable. The file is opened `O_CREAT | O_EXCL | O_NOFOLLOW` with mode set by
/// `fchmod` on the descriptor, and an existing path is refused, never truncated.
public enum TokenFile {
    /// Why a token-file operation was refused or failed.
    public enum TokenFileError: Error, Equatable {
        /// The directory failed an invariant: a symlink, not a directory, not
        /// owned by the user, or group or world writable.
        case directoryUnsafe(String)
        /// The token file already exists; it is refused, never truncated.
        case alreadyExists(String)
        /// An OS call failed; the message is the errno text.
        case system(String)
    }

    /// `~/Library/Application Support/SimEnclave`, overridable by `SIMENCLAVE_HOME`.
    public static func defaultDirectory() -> String {
        if let home = ProcessInfo.processInfo.environment["SIMENCLAVE_HOME"], !home.isEmpty {
            return home
        }
        return NSHomeDirectory() + "/Library/Application Support/SimEnclave"
    }

    /// The token file's path inside a directory.
    public static func path(inDirectory directory: String) -> String {
        directory + "/token"
    }

    /// Verify or create the directory, then write the token hex with `O_EXCL`
    /// and mode `0600`. Returns the file path. Throws if the path already exists.
    @discardableResult
    public static func write(_ token: CapabilityToken, toDirectory directory: String) throws -> String {
        try ensureSafeDirectory(directory)
        let filePath = path(inDirectory: directory)
        let descriptor = open(filePath, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0o600)
        if descriptor < 0 {
            if errno == EEXIST { throw TokenFileError.alreadyExists(filePath) }
            throw TokenFileError.system(errnoMessage())
        }
        defer { close(descriptor) }
        guard fchmod(descriptor, 0o600) == 0 else { throw TokenFileError.system(errnoMessage()) }
        try writeAll(descriptor, Data(token.hex.utf8))
        return filePath
    }

    /// Read and parse the token hex from the directory's token file.
    public static func read(fromDirectory directory: String) throws -> CapabilityToken {
        let descriptor = open(path(inDirectory: directory), O_RDONLY | O_NOFOLLOW)
        if descriptor < 0 { throw TokenFileError.system(errnoMessage()) }
        defer { close(descriptor) }
        var data = Data()
        var chunk = [UInt8](repeating: 0, count: 128)
        while true {
            let n = chunk.withUnsafeMutableBytes { posixRead(descriptor, $0.baseAddress!, $0.count) }
            if n < 0 { throw TokenFileError.system(errnoMessage()) }
            if n == 0 { break }
            data.append(contentsOf: chunk[0 ..< n])
        }
        let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let token = CapabilityToken(hex: text) else {
            throw TokenFileError.system("token file did not hold a 32-byte hex token")
        }
        return token
    }

    /// Remove the token file if present, so a clean restart is not blocked by its
    /// own stale file.
    public static func remove(fromDirectory directory: String) {
        unlink(path(inDirectory: directory))
    }

    /// The port file path: a non-secret companion to the token so a launcher (or the
    /// menubar's copy action) can discover where the running helper is bound, without
    /// scraping its stdout. The port is not a secret; only the token is.
    public static func portPath(inDirectory directory: String) -> String {
        directory + "/port"
    }

    /// Write the bound port as text. Best effort: a launcher convenience, not the
    /// security boundary, so a write failure is not fatal to the helper.
    public static func writePort(_ port: UInt16, toDirectory directory: String) {
        try? Data("\(port)\n".utf8).write(to: URL(fileURLWithPath: portPath(inDirectory: directory)))
    }

    /// Read the bound port a running helper wrote, or nil if absent or unparseable.
    public static func readPort(fromDirectory directory: String) -> UInt16? {
        guard let text = try? String(contentsOfFile: portPath(inDirectory: directory), encoding: .utf8)
        else { return nil }
        return UInt16(text.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Remove the port file, so it never outlives the helper that wrote it.
    public static func removePort(fromDirectory directory: String) {
        unlink(portPath(inDirectory: directory))
    }

    private static func ensureSafeDirectory(_ directory: String) throws {
        var info = stat()
        if lstat(directory, &info) != 0 {
            if errno == ENOENT {
                guard mkdir(directory, 0o700) == 0 else { throw TokenFileError.system(errnoMessage()) }
                return
            }
            throw TokenFileError.system(errnoMessage())
        }
        let mode = info.st_mode
        if (mode & mode_t(S_IFMT)) == mode_t(S_IFLNK) {
            throw TokenFileError.directoryUnsafe("\(directory) is a symlink")
        }
        if (mode & mode_t(S_IFMT)) != mode_t(S_IFDIR) {
            throw TokenFileError.directoryUnsafe("\(directory) is not a directory")
        }
        if info.st_uid != getuid() {
            throw TokenFileError.directoryUnsafe("\(directory) is not owned by the user")
        }
        if (mode & mode_t(S_IWGRP)) != 0 || (mode & mode_t(S_IWOTH)) != 0 {
            throw TokenFileError.directoryUnsafe("\(directory) is group or world writable")
        }
    }

    private static func writeAll(_ descriptor: Int32, _ data: Data) throws {
        try data.withUnsafeBytes { raw in
            let base = raw.baseAddress!
            var written = 0
            while written < raw.count {
                let n = posixWrite(descriptor, base + written, raw.count - written)
                if n <= 0 { throw TokenFileError.system(errnoMessage()) }
                written += n
            }
        }
    }

    private static func errnoMessage() -> String {
        String(cString: strerror(errno))
    }
}
