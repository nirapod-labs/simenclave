// swift-tools-version:6.0
import PackageDescription

// M0 builds the helper as a SwiftPM command-line executable so the loopback
// signing path can be proven against the real Secure Enclave from an ad-hoc
// binary. M1 adds `simenclave-menubar`: the same kit behind an accessory menubar
// app (no dock icon, no entitlement, since the SE works ad-hoc). A signed,
// notarized `.app` bundle for distribution is M5; `com.apple.application-identifier`
// is for keychain persistence (M3).
let package = Package(
    name: "SimEnclaveHelper",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "simenclave-helper", targets: ["simenclave-helper"]),
        .executable(name: "simenclave-menubar", targets: ["simenclave-menubar"]),
        .library(name: "SimEnclaveHelperKit", targets: ["SimEnclaveHelperKit"]),
    ],
    dependencies: [
        .package(path: "../../packages/host-core"),
        .package(path: "../../packages/protocol/swift"),
    ],
    targets: [
        .target(
            name: "SimEnclaveHelperKit",
            dependencies: [
                .product(name: "SimEnclaveHostCore", package: "host-core"),
                .product(name: "SimEnclaveProtocol", package: "swift"),
            ]
        ),
        .executableTarget(
            name: "simenclave-helper",
            dependencies: ["SimEnclaveHelperKit"]
        ),
        .executableTarget(
            name: "simenclave-menubar",
            dependencies: [
                "SimEnclaveHelperKit",
                .product(name: "SimEnclaveHostCore", package: "host-core"),
            ]
        ),
        .testTarget(
            name: "SimEnclaveHelperKitTests",
            dependencies: ["SimEnclaveHelperKit"]
        ),
    ]
)
