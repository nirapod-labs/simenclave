// The M1 helper as a menubar app. It runs the same loopback signing service as
// the CLI (SimEnclaveHelperKit) and adds a status item showing the bound port, a
// kill switch that stops the service and clears the token, and quit. It is an
// accessory app, so no dock icon, and it needs no entitlement: the Secure Enclave
// works ad-hoc. A signed, notarized .app bundle for distribution is M5.

import AppKit
import Foundation
import SimEnclaveHelperKit
import SimEnclaveHostCore

/// The service lifecycle behind the menu: mint the token, write the file, start
/// the loopback listener, and tear all of it down on stop. This is the same kit
/// the CLI uses; the menu is only a face over it.
@MainActor
final class HelperController {
    private let service = SecureEnclaveService()
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
        let started = LoopbackListener(router: RequestRouter(service: service, gate: AuthGate(session: token)))
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
