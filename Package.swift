// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "EntitySwiftCleanroom",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.5.1")
    ],
    targets: [
        .executableTarget(
            name: "EntitySwiftCleanroom",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")]
        ),
        .executableTarget(
            name: "AdoptionV32",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")]
        )
    ]
)
