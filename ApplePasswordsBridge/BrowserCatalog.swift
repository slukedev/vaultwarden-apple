import Foundation

/// Chromium browsers that can run Apple's iCloud Passwords extension headlessly.
/// Arc is left out: it keeps extensions per space in a layout this can't find reliably.
nonisolated struct ChromiumBrowser: Sendable, Equatable {
    var id: String
    var name: String
    /// The app bundle's name in /Applications and its executable's name.
    var appName: String
    /// Under ~/Library/Application Support.
    var dataDirectory: String

    static let all: [ChromiumBrowser] = [
        ChromiumBrowser(id: "chrome", name: "Google Chrome", appName: "Google Chrome", dataDirectory: "Google/Chrome"),
        ChromiumBrowser(id: "edge", name: "Microsoft Edge", appName: "Microsoft Edge", dataDirectory: "Microsoft Edge"),
        ChromiumBrowser(id: "brave", name: "Brave", appName: "Brave Browser", dataDirectory: "BraveSoftware/Brave-Browser"),
        ChromiumBrowser(id: "chromium", name: "Chromium", appName: "Chromium", dataDirectory: "Chromium"),
    ]

    var executable: URL? {
        let roots = [
            URL(fileURLWithPath: "/Applications"),
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications"),
        ]
        return roots
            .map { $0.appendingPathComponent("\(appName).app/Contents/MacOS/\(appName)") }
            .first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }

    var dataURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support")
            .appendingPathComponent(dataDirectory)
    }

    /// The newest installed copy of the iCloud Passwords extension in any profile.
    var extensionSource: URL? {
        let fileManager = FileManager.default
        let profiles = (try? fileManager.contentsOfDirectory(at: dataURL, includingPropertiesForKeys: nil)) ?? []
        let candidates: [URL] = profiles.flatMap { profile -> [URL] in
            let base = profile.appendingPathComponent("Extensions/\(ApplePasswordsBridgeIdentity.extensionID)")
            let versions = (try? fileManager.contentsOfDirectory(at: base, includingPropertiesForKeys: nil)) ?? []
            return versions.filter {
                fileManager.fileExists(atPath: $0.appendingPathComponent("background.js").path)
            }
        }
        return candidates.max {
            $0.lastPathComponent.compare($1.lastPathComponent, options: .numeric) == .orderedAscending
        }
    }

    static func installed() -> [ChromiumBrowser] {
        all.filter { $0.executable != nil }
    }

    static func summaries() -> [ApplePasswordsBrowser] {
        installed().map { ApplePasswordsBrowser(id: $0.id, name: $0.name, hasExtension: $0.extensionSource != nil) }
    }
}
