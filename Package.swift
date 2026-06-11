// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "hush",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(name: "hush", path: "Sources/hush"),
        .testTarget(name: "hushTests", dependencies: ["hush"], path: "Tests/hushTests"),
    ]
)
