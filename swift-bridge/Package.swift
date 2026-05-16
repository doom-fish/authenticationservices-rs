// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "AuthServicesBridge",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "AuthServicesBridge",
            type: .static,
            targets: ["AuthServicesBridge"])
    ],
    targets: [
        .target(
            name: "AuthServicesBridge",
            path: "Sources/AuthServicesBridge",
            publicHeadersPath: "include")
    ]
)
