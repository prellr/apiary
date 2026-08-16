// swift-tools-version: 6.0
// apiary apple-speech sidecar — on-device speech-to-text and text-to-speech
// for macOS 26+ hosts. Pure equipment: it receives audio bytes or text on
// stdin, returns JSON on stdout, and never sees a credential, a manifest,
// or any agent material. See ../README.md for the contract.
import PackageDescription

let package = Package(
    name: "apple-speech",
    platforms: [.macOS("26.0")],
    targets: [
        .executableTarget(
            name: "apple-speech",
            path: "Sources/apple-speech"
        )
    ]
)
