// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "EntitySwiftCleanroom",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "EntitySwiftCleanroom", targets: ["EntitySwiftCleanroom"]),
        .executable(name: "AdoptionV32", targets: ["AdoptionV32"]),
        .executable(name: "RealityV33", targets: ["RealityV33"]),
        .executable(name: "PassportV34", targets: ["PassportV34"])
    ],
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
        ),
        .executableTarget(
            name: "RealityV33",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")]
        ),
        .executableTarget(
            name: "PassportV34",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")]
        )
    ]
)
