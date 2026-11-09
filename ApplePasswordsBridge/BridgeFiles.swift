import Foundation

/// The agent's working files, in ~/Library/Application Support/Vaultwarden/ApplePasswords,
/// readable only by this user. Rebuilt on every start so extension updates carry over.
nonisolated enum BridgeFiles {
    /// Where Apple installs the helper's native-messaging manifest for Chromium browsers.
    static let appleManifest = URL(fileURLWithPath: "/Library/Google/Chrome/NativeMessagingHosts/com.apple.passwordmanager.json")

    static var root: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Vaultwarden/ApplePasswords")
    }

    static var extensionURL: URL { root.appendingPathComponent("extension") }

    static func profileURL(for browser: ChromiumBrowser) -> URL {
        root.appendingPathComponent("profiles").appendingPathComponent(browser.id)
    }

    /// Copies the extension and appends the bridge script to its background worker.
    static func installExtension(from source: URL, port: UInt16, token: String) throws {
        let fileManager = FileManager.default
        try prepareRoot()
        try? fileManager.removeItem(at: extensionURL)
        try fileManager.copyItem(at: source, to: extensionURL)
        // Chrome refuses unpacked extensions that still carry Web Store signatures.
        try? fileManager.removeItem(at: extensionURL.appendingPathComponent("_metadata"))

        let background = extensionURL.appendingPathComponent("background.js")
        var script = try String(contentsOf: background, encoding: .utf8)
        script += try BridgeScript.source(port: port, token: token)
        try script.write(to: background, atomically: true, encoding: .utf8)
    }

    /// A fresh browser profile that knows where Apple's helper is.
    static func prepareProfile(for browser: ChromiumBrowser) throws -> URL {
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: appleManifest.path) else {
            throw ApplePasswordsError(.genericError, "Apple's password helper wasn't found. It ships with macOS 14 and later.")
        }
        try prepareRoot()
        let profile = profileURL(for: browser)
        try? fileManager.removeItem(at: profile)
        let hosts = profile.appendingPathComponent("NativeMessagingHosts")
        try fileManager.createDirectory(at: hosts, withIntermediateDirectories: true)
        try fileManager.copyItem(at: appleManifest, to: hosts.appendingPathComponent(appleManifest.lastPathComponent))
        return profile
    }

    static func removeAll() {
        try? FileManager.default.removeItem(at: root)
    }

    private static func prepareRoot() throws {
        let fileManager = FileManager.default
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    }
}
