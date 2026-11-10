import Foundation
import Security

// Shared by the app and the ApplePasswordsBridge agent. Foundation and Security only,
// so it compiles in both targets and in the tests on every platform.
//
// How the connection works (the approach of github.com/araeyn/apple-passwords-bridge):
// macOS only lets Apple's PasswordManagerBrowserExtensionHelper run when an allowlisted
// browser starts it. The agent briefly starts an installed Chromium browser that carries
// Apple's passkey entitlement, headless and with a throwaway profile, and names itself as
// that browser's subprocess. When the browser launches it, the agent's subprocess replaces
// itself with Apple's helper, keeping pipes the agent handed it, and the browser is quit.
// The agent then pairs with the helper using Apple's PIN and talks to it directly.

// MARK: - Identity

nonisolated enum ApplePasswordsBridgeIdentity {
    /// Sandboxed apps may look up Mach services named under one of their App Groups.
    static let machServiceName = "group.xyz.0xmwehehe.vaultwardenApp.ApplePasswordsBridge"
    /// In Contents/Library/LaunchAgents of the app bundle.
    static let launchAgentPlistName = "xyz.0xmwehehe.vaultwardenApp.ApplePasswordsBridge.plist"
    static let appIdentifier = "xyz.0xmwehehe.vaultwardenApp"
    static let bridgeIdentifier = "xyz.0xmwehehe.vaultwardenApp.ApplePasswordsBridge"
    /// The origin of Apple's iCloud Passwords extension, which the helper expects as its argument.
    static let helperOrigin = "chrome-extension://pejdijmoenmkgeppbflobdenhhabjlaj/"

    /// A code requirement for a peer signed by the same team as this process. Builds
    /// signed to run locally have no team; they fall back to the identifier alone.
    static func codeRequirement(forIdentifier identifier: String) -> String {
        guard let team = currentTeamIdentifier() else {
            return "identifier \"\(identifier)\""
        }
        return "identifier \"\(identifier)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
    }

    static func currentTeamIdentifier() -> String? {
        #if os(macOS)
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var info: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(staticCode, flags, &info) == errSecSuccess,
              let info = info as? [String: Any] else { return nil }
        return info[kSecCodeInfoTeamIdentifier as String] as? String
        #else
        return nil
        #endif
    }
}

// MARK: - XPC

/// One method carrying JSON keeps the Objective-C surface small; the payloads are
/// `ApplePasswordsBridgeRequest` and `ApplePasswordsBridgeResponse`.
@objc(VWApplePasswordsBridgeXPC)
nonisolated protocol ApplePasswordsBridgeXPC {
    func perform(_ request: Data, withReply reply: @escaping @Sendable (Data) -> Void)
}

nonisolated enum ApplePasswordsBridgeRequest: Codable, Sendable, Equatable {
    case status
    /// Starts Apple's helper through `browserID` when that browser qualifies.
    case connect(browserID: String?)
    /// Shows Apple's pairing PIN on this Mac.
    case requestPIN
    case submitPIN(String)
    case accounts(site: String)
    case password(site: String, username: String)
    case save(site: String, username: String, password: String)
    case oneTimeCodes(site: String)
    /// Ends the helper and its pairing.
    case disconnect
}

nonisolated enum ApplePasswordsBridgeResponse: Codable, Sendable, Equatable {
    case status(ApplePasswordsBridgeStatus)
    case accounts([ApplePasswordsAccount])
    case codes([ApplePasswordsCode])
    case done
    case failure(String)
}

/// An installed Chromium browser Apple lets start its helper.
nonisolated struct ApplePasswordsBrowser: Codable, Sendable, Hashable, Identifiable {
    /// The app's bundle identifier.
    var id: String
    var name: String
}

nonisolated struct ApplePasswordsBridgeStatus: Codable, Sendable, Equatable {
    enum Phase: String, Codable, Sendable {
        /// Apple's helper isn't running.
        case stopped
        /// Starting Apple's helper.
        case starting
        /// The helper is running and waiting for the PIN.
        case needsPairing
        /// Paired: requests reach Apple Passwords.
        case ready
        case failed
    }

    var phase: Phase
    var browsers: [ApplePasswordsBrowser]
    var activeBrowserID: String?
    var message: String?
}

nonisolated struct ApplePasswordsAccount: Codable, Sendable, Hashable, Identifiable {
    var username: String
    var password: String?
    var sites: [String]
    var domain: String?
    var title: String?

    var id: String { "\(domain ?? sites.first ?? "")\u{1F}\(username)" }

    /// The site Apple Passwords filed the account under.
    var primarySite: String {
        domain ?? sites.first.flatMap(ApplePasswordsSite.host) ?? sites.first ?? ""
    }
}

nonisolated struct ApplePasswordsCode: Codable, Sendable, Hashable, Identifiable {
    var username: String
    var domain: String
    var code: String?
    var source: String?

    var id: String { "\(domain)\u{1F}\(username)\u{1F}\(source ?? "")" }
}

// MARK: - Errors

nonisolated enum ApplePasswordsStatusCode: Int, Sendable {
    case success = 0
    case genericError = 1
    case invalidParameter = 2
    case noResults = 3
    case failedToDelete = 4
    case failedToUpdate = 5
    case invalidMessageFormat = 6
    case duplicateItem = 7
    case unknownAction = 8
    case invalidSession = 9
    case serverError = 100

    var message: String {
        switch self {
        case .success: "Done."
        case .genericError: "Apple Passwords reported an error."
        case .invalidParameter: "Apple Passwords didn't accept the request."
        case .noResults: "No results."
        case .failedToDelete: "Apple Passwords couldn't delete the item."
        case .failedToUpdate: "Apple Passwords couldn't save the item."
        case .invalidMessageFormat: "Apple Passwords didn't understand the request."
        case .duplicateItem: "That account is already in Apple Passwords."
        case .unknownAction: "Apple Passwords doesn't support that request."
        case .invalidSession: "Apple Passwords isn't paired. Pair again with a new PIN."
        case .serverError: "Unexpected response from Apple Passwords."
        }
    }
}

nonisolated struct ApplePasswordsError: LocalizedError, Sendable, Equatable {
    var status: ApplePasswordsStatusCode
    var detail: String?

    init(_ status: ApplePasswordsStatusCode, _ detail: String? = nil) {
        self.status = status
        self.detail = detail
    }

    var errorDescription: String? { detail ?? status.message }
}

// MARK: - Sites

nonisolated enum ApplePasswordsSite {
    /// The host of a URL or bare domain the user typed or a vault item stores.
    static func host(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let candidate = trimmed.contains("://") ? trimmed : "https://\(trimmed)"
        guard let host = URLComponents(string: candidate)?.host?.lowercased(), !host.isEmpty,
              host.contains(".") || host == "localhost" else { return nil }
        return host
    }

    /// Verification-code lookups want a URL, not a bare domain.
    static func frameURL(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.contains("://") ? trimmed : "http://\(trimmed)"
    }
}

// MARK: - Commands

/// Commands of the helper's native-messaging protocol.
nonisolated enum ApplePasswordsCommand: Int, Sendable {
    case end = 0
    case handshake = 2
    case getLoginNamesForURL = 4
    case getPasswordForLoginName = 5
    case setPasswordForLoginNameAndURL = 6
    /// Unsolicited: Passwords was turned off or signed out; the pairing is gone.
    case passwordsDisabled = 9
    /// Unsolicited: the helper wants a new pairing.
    case reloginNeeded = 10
    case getCapabilities = 14
    case getOneTimeCodes = 16
    case didFillOneTimeCode = 17
}

nonisolated enum ApplePasswordsAction: Int, Sendable {
    case search = 2
    case maybeAdd = 4
    case ghostSearch = 5
}

// MARK: - Replies

nonisolated enum ApplePasswordsReply {
    /// Entries from a decrypted payload. The helper sends either an `Entries` array or
    /// numbered `Entry_N` keys.
    static func entries(from data: [String: Any]) throws -> [[String: Any]] {
        guard let status = data["STATUS"] as? Int else { throw ApplePasswordsError(.serverError) }
        if status == ApplePasswordsStatusCode.noResults.rawValue { return [] }
        guard status == ApplePasswordsStatusCode.success.rawValue else {
            throw ApplePasswordsError(ApplePasswordsStatusCode(rawValue: status) ?? .genericError)
        }
        if let entries = data["Entries"] as? [[String: Any]] { return entries }
        return data
            .filter { $0.key.hasPrefix("Entry_") }
            .sorted { $0.key.compare($1.key, options: .numeric) == .orderedAscending }
            .compactMap { $0.value as? [String: Any] }
    }

    static func accounts(from data: [String: Any]) throws -> [ApplePasswordsAccount] {
        try entries(from: data).map { entry in
            ApplePasswordsAccount(
                username: entry["USR"] as? String ?? "",
                password: (entry["PWD"] as? String).flatMap { $0.isEmpty ? nil : $0 },
                sites: entry["sites"] as? [String] ?? [],
                domain: entry["highLevelDomain"] as? String,
                title: entry["customTitle"] as? String
            )
        }
    }

    static func codes(from data: [String: Any]) throws -> [ApplePasswordsCode] {
        try entries(from: data).map { entry in
            ApplePasswordsCode(
                username: entry["username"] as? String ?? "",
                domain: entry["domain"] as? String ?? "",
                code: entry["code"] as? String,
                source: entry["source"] as? String
            )
        }
    }

    static func status(from data: [String: Any]) throws {
        guard let status = data["STATUS"] as? Int else { return }
        guard status == ApplePasswordsStatusCode.success.rawValue else {
            throw ApplePasswordsError(ApplePasswordsStatusCode(rawValue: status) ?? .genericError)
        }
    }
}
