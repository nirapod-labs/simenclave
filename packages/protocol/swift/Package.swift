// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "SimEnclaveProtocol",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "SimEnclaveProtocol", targets: ["SimEnclaveProtocol"]),
    ],
    targets: [
        .target(name: "SimEnclaveProtocol"),
        .testTarget(
            name: "SimEnclaveProtocolTests",
            dependencies: ["SimEnclaveProtocol"]
        ),
    ]
)
