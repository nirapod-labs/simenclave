// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import AppKit
import Foundation
import Observation
import ServiceManagement
import SimEnclaveHelperKit
import SimEnclaveHostCore

/// A simulator app that has used the Secure Enclave this session, named by its bundle id and,
/// when the interposer announced it on HELLO, a sanitized display name. The count is the live
/// number of keys it holds: a GENERATE adds one, the matching DELETE removes it.
struct AppActivity: Identifiable {
    let id: String
    var name: String?
    var keys: Int
    var lastSeen: Date
}

/// The menubar's whole state and the helper lifecycle behind it: the on/off control, the
/// bound port, the connected apps, and the settings (fixed port, launch at login). The view
/// binds to this; it owns the `SecureEnclaveService` and the `LoopbackListener`.
@MainActor
@Observable
final class HelperModel {
    private(set) var running = false
    private(set) var port: UInt16 = 0
    private(set) var apps: [AppActivity] = []
    private(set) var totalOps = 0
    /// When the listener came up, for the settings uptime. Nil while stopped.
    private(set) var startedAt: Date?
    /// Maps a minted key handle to the bundle id that generated it, so a DELETE, which carries no
    /// app id, decrements the live count of the right app.
    private var handleOwner: [Data: String] = [:]

    /// A pinned port, so the scheme environment stays stable across restarts. 0 is ephemeral.
    var fixedPort: Int {
        didSet { UserDefaults.standard.set(fixedPort, forKey: Self.fixedPortKey) }
    }

    /// Start SimEnclave at login, via the login-items service.
    var launchAtLogin: Bool {
        didSet { setLaunchAtLogin(launchAtLogin) }
    }

    private let service = SecureEnclaveService(biometricGate: AppKitBiometricGate())
    private var listener: LoopbackListener?
    private var directory: String?
    private var observer: Observer?

    private static let fixedPortKey = "fixedPort"
    private static let lastPortKey = "lastPort"

    init() {
        fixedPort = UserDefaults.standard.integer(forKey: Self.fixedPortKey)
        launchAtLogin = SMAppService.mainApp.status == .enabled
        // Arm on launch, so opening SimEnclave makes the helper live without a click.
        start()
        // Any quit (Cmd-Q, logout, the Quit button) clears the simulator injection env, so a
        // later app never injects against a dead helper.
        NotificationCenter.default.addObserver(
            forName: NSApplication.willTerminateNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.clearInjection() }
        }
    }

    var secureEnclaveAvailable: Bool { service.isAvailable }

    /// The app's marketing version (CFBundleShortVersionString), or "dev" under `swift run`.
    var appVersion: String {
        (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? "dev"
    }

    /// The per-user directory the helper writes its token and port to.
    var dataDirectory: String { TokenFile.defaultDirectory() }

    /// The live total of keys the helper holds, read from the store so it counts keys whose app
    /// has dropped out of the connected-apps view, not just the currently connected ones.
    var totalKeys: Int { service.keyCount }

    /// Reveal the data directory in Finder, the settings "open data directory" action.
    func openDataDirectory() {
        NSWorkspace.shared.open(URL(fileURLWithPath: dataDirectory))
    }

    /// Drop every key the helper holds and clear the connected-apps view, the settings
    /// "reset all keys" action. The keys are in-session, so this releases them at once; a
    /// still-connected app that signs with a now-gone handle gets the device's item-not-found.
    func resetAllKeys() {
        service.reset()
        apps.removeAll()
        handleOwner.removeAll()
        totalOps = 0
    }

    var iconName: String {
        guard secureEnclaveAvailable else { return "exclamationmark.triangle" }
        return running ? "lock.shield.fill" : "lock.slash"
    }

    func toggle() { running ? stop() : start() }

    func start() {
        guard service.isAvailable, !running else { return }
        let dir = TokenFile.defaultDirectory()
        // A persistent token, reused across restarts, so an app injected once keeps
        // authenticating after the helper restarts instead of the connection dropping on a
        // freshly minted token.
        let token: CapabilityToken
        if let existing = try? TokenFile.read(fromDirectory: dir) {
            token = existing
        } else {
            token = CapabilityToken()
            do { try TokenFile.write(token, toDirectory: dir) } catch { return }
        }
        let obs = Observer(model: self)
        let router = RequestRouter(service: service, gate: AuthGate(session: token), observer: obs)
        // A stable port: the user's pinned port, else the port last bound, so a restart reuses
        // the same address and an already-injected app reconnects without re-injection. Fall
        // back to an ephemeral port only if the preferred one is unavailable.
        let preferred = fixedPort > 0 ? fixedPort : UserDefaults.standard.integer(forKey: Self.lastPortKey)
        var started = LoopbackListener(router: router)
        do {
            try started.start(port: UInt16(clamping: preferred))
        } catch {
            started = LoopbackListener(router: router)
            do { try started.start(port: 0) } catch { return }
        }
        observer = obs
        listener = started
        directory = dir
        port = started.port
        running = true
        startedAt = Date()
        UserDefaults.standard.set(Int(port), forKey: Self.lastPortKey)
        TokenFile.writePort(port, toDirectory: dir)
        applyInjection()
    }

    func stop() {
        clearInjection()
        listener?.stop()
        listener = nil
        // Keep the token file so a restart reuses the same token (stable connection); only the
        // port file goes, since the listener is down.
        if let directory { TokenFile.removePort(fromDirectory: directory) }
        directory = nil
        running = false
        port = 0
        startedAt = nil
    }

    /// Arm the booted simulators so any app they launch is injected automatically, the SimCam
    /// model: set the interposer and the helper's port and token in the simulator's `launchd`
    /// environment via `simctl spawn ... launchctl setenv`. Every app launched afterward,
    /// including ones tapped on the home screen, inherits it. Apps already running are not
    /// affected; launch SimEnclave before the app, like SimCam. Run off the main actor so the
    /// menubar does not hitch on the `simctl` spawns.
    private func applyInjection() {
        guard let dylib = Self.interposerDylib(), let directory,
              let token = try? TokenFile.read(fromDirectory: directory).hex else { return }
        let port = self.port
        Task.detached {
            let env = [
                ("DYLD_INSERT_LIBRARIES", dylib),
                ("SIMENCLAVE_PORT", String(port)),
                ("SIMENCLAVE_TOKEN", token),
            ]
            for udid in Self.bootedSimulators() {
                for (key, value) in env {
                    Self.runSimctl(["spawn", udid, "launchctl", "setenv", key, value])
                }
            }
        }
    }

    /// Clear the simulator injection env. Synchronous, so a Quit or toggle-off finishes the
    /// cleanup before the helper goes away and a stale port/token cannot mislead a later app.
    func clearInjection() {
        let keys = ["DYLD_INSERT_LIBRARIES", "SIMENCLAVE_PORT", "SIMENCLAVE_TOKEN"]
        for udid in Self.bootedSimulators() {
            for key in keys { Self.runSimctl(["spawn", udid, "launchctl", "unsetenv", key]) }
        }
    }

    /// The UDIDs of every booted simulator, parsed from `simctl list devices booted`.
    private nonisolated static func bootedSimulators() -> [String] {
        guard let output = runSimctlOutput(["list", "devices", "booted"]) else { return [] }
        let pattern = "[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let text = output as NSString
        return regex.matches(in: output, range: NSRange(location: 0, length: text.length))
            .map { text.substring(with: $0.range) }
    }

    @discardableResult
    private nonisolated static func runSimctl(_ arguments: [String]) -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        process.arguments = ["simctl"] + arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return -1 }
        process.waitUntilExit()
        return process.terminationStatus
    }

    private nonisolated static func runSimctlOutput(_ arguments: [String]) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        process.arguments = ["simctl"] + arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(data: data, encoding: .utf8)
    }

    /// The three lines a developer pastes into an Xcode scheme's environment.
    func schemeEnvironment() -> String? {
        guard running, let directory, let token = try? TokenFile.read(fromDirectory: directory).hex
        else { return nil }
        let dylib = Self.interposerDylib() ?? "# build it first: make dylib"
        return """
        DYLD_INSERT_LIBRARIES=\(dylib)
        SIMENCLAVE_PORT=\(port)
        SIMENCLAVE_TOKEN=\(token)
        """
    }

    /// Record a served op for the connected-apps view. Called on the main actor. A HELLO carries
    /// the app's identity and creates or names the entry; a GENERATE adds the minted key to the
    /// live count and remembers its owner; a DELETE removes it from the count. The display name,
    /// when present, is the router-sanitized one.
    func record(op: String, appID: String?, displayName: String?, handle: Data?) {
        totalOps += 1
        // A DELETE carries no app id; attribute it to the app that minted the handle, so the live
        // count drops for the right app.
        if op == "DELETE" {
            if let handle, let owner = handleOwner.removeValue(forKey: handle),
               let i = apps.firstIndex(where: { $0.id == owner }) {
                apps[i].keys = max(0, apps[i].keys - 1)
                apps[i].lastSeen = Date()
            }
            return
        }
        guard let appID else { return }
        let i: Int
        if let found = apps.firstIndex(where: { $0.id == appID }) {
            i = found
        } else {
            apps.insert(AppActivity(id: appID, name: displayName, keys: 0, lastSeen: Date()), at: 0)
            i = 0
        }
        if let displayName { apps[i].name = displayName }
        if op == "GENERATE", let handle {
            handleOwner[handle] = appID
            apps[i].keys += 1
        }
        apps[i].lastSeen = Date()
    }

    private func setLaunchAtLogin(_ on: Bool) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            FileHandle.standardError.write(Data("simenclave: login item: \(error)\n".utf8))
        }
    }

    /// Walk up from the running binary to the repo's built simulator interposer, so the
    /// copied scheme environment carries a real path in a dev checkout.
    private static func interposerDylib() -> String? {
        var dir = URL(fileURLWithPath: CommandLine.arguments[0])
            .resolvingSymlinksInPath().deletingLastPathComponent()
        for _ in 0 ..< 10 {
            let candidate = dir.appendingPathComponent("build-sim/bin/simenclave-interpose.dylib")
            if FileManager.default.fileExists(atPath: candidate.path) { return candidate.path }
            dir = dir.deletingLastPathComponent()
        }
        return nil
    }

    /// Bridges the router's off-main `served` callbacks onto the main actor.
    final class Observer: ServeObserver, @unchecked Sendable {
        weak var model: HelperModel?
        init(model: HelperModel) { self.model = model }
        func served(op: String, appID: String?, displayName: String?, handle: Data?) {
            Task { @MainActor [weak model] in
                model?.record(op: op, appID: appID, displayName: displayName, handle: handle)
            }
        }
    }
}
