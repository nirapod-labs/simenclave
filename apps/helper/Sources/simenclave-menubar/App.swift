// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

// The M1 helper as a menubar app. It runs the same loopback signing service as
// the CLI (SimEnclaveHelperKit) and adds a status item showing the bound port, a
// kill switch that stops the service and clears the token, and quit. It is an
// accessory app, so no dock icon, and it needs no entitlement: the Secure Enclave
// works ad-hoc. A signed, notarized .app bundle for distribution is M5.

import AppKit
import Foundation
import Security
import SimEnclaveHelperKit
import SimEnclaveHostCore

/// The real biometric gate, for the menubar (AppKit) helper. It brings the helper
/// foreground on the main thread, so the Mac Touch ID sheet is attributed and visible,
/// then signs on the calling connection thread, where SecKeyCreateSignature triggers the
/// SEP's biometric prompt and blocks for the human while the main run loop presents it.
/// Signing on the main thread would deadlock the very run loop the sheet needs, so it
/// stays on the connection thread. A custom prompt reason via a bound LAContext, and the
/// exact binding, are the refinement to confirm on real hardware; the prompt itself fires
/// from foreground plus the sign. This path is verified by a developer on the menubar
/// build, the same as the menubar UI; the headless suite drives the seam through a mock.
final class AppKitBiometricGate: BiometricGate {
    func promptedSign(key: SecKey, digest: Data, reason _: String) throws -> Data {
        DispatchQueue.main.sync { NSApp.activate(ignoringOtherApps: true) }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key, .ecdsaSignatureDigestX962SHA256, digest as CFData, &error
        ) as Data? else {
            throw Self.classify(error?.takeRetainedValue())
        }
        return signature
    }

    /// Classify the macOS sign error into a failure category the helper maps to the device
    /// error. The common OSStatus cases are covered here; the LAError-specific categories
    /// (lockout, not-enrolled, not-available) are a device-verified refinement, captured
    /// with the device-reference table before M4.
    private static func classify(_ error: CFError?) -> BiometricFailure {
        guard let error else { return .unknown }
        switch CFErrorGetCode(error) {
        case Int(errSecUserCanceled): return .userCanceled
        case Int(errSecAuthFailed): return .authenticationFailed
        default: return .unknown
        }
    }
}

/// The real app approver, for the menubar (AppKit) helper. It foregrounds and shows a
/// modal alert naming the connecting app, on the main thread; the developer allows or
/// denies. A convenience that names the app, not an access boundary. Verified by a
/// developer on the menubar build; the headless suite drives the seam through a mock.
final class AppKitApprover: AppApprover {
    func approve(appID: String) -> Bool {
        var allowed = false
        DispatchQueue.main.sync {
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.messageText = "Allow Secure Enclave access?"
            alert.informativeText = "Simulator app \(appID) wants to use the Secure Enclave."
            alert.addButton(withTitle: "Allow")
            alert.addButton(withTitle: "Deny")
            allowed = alert.runModal() == .alertFirstButtonReturn
        }
        return allowed
    }
}

/// The service lifecycle behind the menu: mint the token, write the file, start
/// the loopback listener, and tear all of it down on stop. This is the same kit
/// the CLI uses; the menu is only a face over it.
@MainActor
final class HelperController {
    private let service = SecureEnclaveService(biometricGate: AppKitBiometricGate())
    private var listener: LoopbackListener?
    private var tokenDirectory: String?
    private(set) var port: UInt16 = 0
    private(set) var running = false

    func start() -> Bool {
        guard service.isAvailable else { return false }
        let token = CapabilityToken()
        let directory = TokenFile.defaultDirectory()
        do {
            try TokenFile.write(token, toDirectory: directory)
        } catch {
            FileHandle.standardError.write(Data("simenclave-menubar: token file: \(error)\n".utf8))
            return false
        }
        let router = RequestRouter(
            service: service,
            gate: AuthGate(session: token),
            approval: ApprovalGate(approver: AppKitApprover()))
        let started = LoopbackListener(router: router)
        do {
            try started.start()
        } catch {
            TokenFile.remove(fromDirectory: directory)
            return false
        }
        listener = started
        tokenDirectory = directory
        port = started.port
        running = true
        print("{\"ready\":true,\"port\":\(port)}")
        fflush(stdout)
        return true
    }

    /// Stop serving and remove the token file, so a stale token never outlives
    /// the session. This is the kill switch and the clean-quit path.
    func stop() {
        listener?.stop()
        listener = nil
        if let directory = tokenDirectory {
            TokenFile.remove(fromDirectory: directory)
            tokenDirectory = nil
        }
        running = false
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let controller = HelperController()
    private var statusItem: NSStatusItem?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let started = controller.start()

        let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "SE"

        let menu = NSMenu()
        let status = NSMenuItem(
            title: started ? "Helper on 127.0.0.1:\(controller.port)" : "No Secure Enclave",
            action: nil,
            keyEquivalent: ""
        )
        status.isEnabled = false
        menu.addItem(status)
        menu.addItem(.separator())

        let stop = NSMenuItem(title: "Stop and clear token", action: #selector(killSwitch), keyEquivalent: "")
        stop.target = self
        menu.addItem(stop)

        let quit = NSMenuItem(title: "Quit", action: #selector(quit), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)

        statusItem.menu = menu
        self.statusItem = statusItem

        if !started {
            FileHandle.standardError.write(Data("simenclave-menubar: no Secure Enclave on this host\n".utf8))
        }
    }

    @objc private func killSwitch() {
        controller.stop()
        statusItem?.menu?.items.first?.title = "Stopped"
    }

    @objc private func quit() {
        controller.stop()
        NSApp.terminate(nil)
    }

    func applicationWillTerminate(_ notification: Notification) {
        controller.stop()
    }
}

@main
enum SimEnclaveMenubar {
    @MainActor
    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }
}
