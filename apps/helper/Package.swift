// swift-tools-version:6.0
import PackageDescription

// M0 builds the helper as a SwiftPM command-line executable so the loopback
// signing path can be proven against the real Secure Enclave from an ad-hoc
// binary. M1 wraps this same kit in the signed menubar app described in
// `project.yml`, which carries the `com.apple.application-identifier`
// entitlement for distribution.
let package = Package(
    name: "SimEnclaveHelper",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "simenclave-helper", targets: ["simenclave-helper"]),
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
        .testTarget(
            name: "SimEnclaveHelperKitTests",
            dependencies: ["SimEnclaveHelperKit"]
        ),
    ]
)
