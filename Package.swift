// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Aether",
    defaultLocalization: "en",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "Aether", targets: ["Aether"])
    ],
    dependencies: [],
    targets: [
        .executableTarget(
            name: "Aether",
            dependencies: [],
            path: "Sources/Aether",
            resources: [
                .process("Resources")
            ]
        )
    ]
)
