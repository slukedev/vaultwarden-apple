import Foundation
import Security

/// An installed Chromium browser that Apple allows to start its Passwords helper: a
/// signed app with Chromium's helper apps and Apple's
/// `com.apple.developer.web-browser.public-key-credential` entitlement. The browser
/// itself is never modified and its real profile is never opened.
nonisolated struct ChromiumBrowser: Sendable, Equatable {
    var id: String
    var name: String
    var executable: URL

    static let requiredEntitlement = "com.apple.developer.web-browser.public-key-credential"

    var summary: ApplePasswordsBrowser { ApplePasswordsBrowser(id: id, name: name) }

    /// Google Chrome first, then the rest by name.
    static func installed() -> [ChromiumBrowser] {
        let fileManager = FileManager.default
        let roots = [
            URL(fileURLWithPath: "/Applications"),
            fileManager.homeDirectoryForCurrentUser.appendingPathComponent("Applications"),
        ]
        var seen = Set<String>()
        var found: [ChromiumBrowser] = []
        for root in roots {
            let apps = (try? fileManager.contentsOfDirectory(at: root, includingPropertiesForKeys: nil, options: .skipsHiddenFiles)) ?? []
            for app in apps where app.pathExtension.lowercased() == "app" {
                let resolved = app.resolvingSymlinksInPath().standardizedFileURL
                guard seen.insert(resolved.path).inserted, let browser = candidate(at: resolved) else { continue }
                found.append(browser)
            }
        }
        return found.sorted {
            let chrome0 = $0.id == "com.google.Chrome", chrome1 = $1.id == "com.google.Chrome"
            if chrome0 != chrome1 { return chrome0 }
            return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
    }

    private static func candidate(at app: URL) -> ChromiumBrowser? {
        guard let info = NSDictionary(contentsOf: app.appendingPathComponent("Contents/Info.plist")) as? [String: Any],
              info["CFBundlePackageType"] as? String == "APPL",
              let identifier = info["CFBundleIdentifier"] as? String,
              let executableName = info["CFBundleExecutable"] as? String,
              hasChromiumHelpers(app) else { return nil }

        let executable = app.appendingPathComponent("Contents/MacOS").appendingPathComponent(executableName)
        guard FileManager.default.isExecutableFile(atPath: executable.path),
              let signing = signingInformation(app),
              signing[kSecCodeInfoIdentifier as String] as? String == identifier,
              let entitlements = signing[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
              (entitlements[requiredEntitlement] as? Bool) == true else { return nil }

        let name = info["CFBundleDisplayName"] as? String ?? info["CFBundleName"] as? String
            ?? app.deletingPathExtension().lastPathComponent
        return ChromiumBrowser(id: identifier, name: name, executable: executable)
    }

    /// Chromium browsers keep helper apps in Contents/Frameworks/*.framework/Versions/*/Helpers.
    private static func hasChromiumHelpers(_ app: URL) -> Bool {
        let fileManager = FileManager.default
        let frameworks = app.appendingPathComponent("Contents/Frameworks")
        let names = (try? fileManager.contentsOfDirectory(atPath: frameworks.path)) ?? []
        for name in names where name.hasSuffix(".framework") {
            let versions = frameworks.appendingPathComponent(name).appendingPathComponent("Versions")
            for version in (try? fileManager.contentsOfDirectory(atPath: versions.path)) ?? [] {
                let helpers = versions.appendingPathComponent(version).appendingPathComponent("Helpers")
                let entries = (try? fileManager.contentsOfDirectory(atPath: helpers.path)) ?? []
                if entries.contains(where: { $0.hasSuffix(".app") }) { return true }
            }
        }
        return false
    }

    private static func signingInformation(_ app: URL) -> [String: Any]? {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(app as CFURL, [], &code) == errSecSuccess, let code else { return nil }
        // A valid signature, so a copied or tampered app doesn't qualify.
        guard SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSDoNotValidateResources), nil) == errSecSuccess else { return nil }
        var info: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation)
        guard SecCodeCopySigningInformation(code, flags, &info) == errSecSuccess else { return nil }
        return info as? [String: Any]
    }
}
