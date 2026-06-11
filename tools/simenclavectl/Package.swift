// swift-tools-version:6.0
// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import PackageDescription

// simenclavectl drives a running helper from the terminal or an agent. The logic
// lives in a library target so it is unit-testable; the executable is a thin shell
// over it. It reuses the protocol package's codec and framing, so the CLI speaks
// the exact wire the interposer's C client does.
let package = Package(
    name: "simenclavectl",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(path: "../../packages/protocol/swift"),
    ],
    targets: [
        .target(
            name: "SimEnclaveCTLKit",
            dependencies: [.product(name: "SimEnclaveProtocol", package: "swift")]
        ),
        .executableTarget(
            name: "simenclavectl",
            dependencies: ["SimEnclaveCTLKit"]
        ),
        .testTarget(
            name: "SimEnclaveCTLKitTests",
            dependencies: ["SimEnclaveCTLKit"]
        ),
    ]
)
