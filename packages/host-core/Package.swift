// swift-tools-version: 6.0
import PackageDescription

let package: Package = Package(
    name: "SimEnclaveHostCore",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "SimEnclaveHostCore", targets: ["SimEnclaveHostCore"])
    ],
    targets: [
        .target(name: "SimEnclaveHostCore"),
        .testTarget(
            name: "SimEnclaveHostCoreTests",
            dependencies: ["SimEnclaveHostCore"]
        ),
    ]
)
