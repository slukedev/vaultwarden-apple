import Foundation
import Security

// Shared by the app and the ApplePasswordsBridge agent. Foundation and Security only,
// so it compiles in both targets and in the tests on every platform.
//
// How the connection works (a Swift port of the approach in github.com/bendews/apw):
// macOS only lets allowlisted browsers talk to Apple's PasswordManagerBrowserExtensionHelper.
// The bridge agent therefore starts a headless Chromium browser with a private copy of
// Apple's own iCloud Passwords extension. A short script appended to that extension's
// background worker relays requests between the agent (over a loopback WebSocket that
// requires a random token) and the extension's already-encrypted session with the helper.
// Pairing uses Apple's PIN prompt, exactly as it does in a browser.

// MARK: - Identity

nonisolated enum ApplePasswordsBridgeIdentity {
    /// Sandboxed apps may look up Mach services named under one of their App Groups.
    static let machServiceName = "group.xyz.0xmwehehe.vaultwardenApp.ApplePasswordsBridge"
    /// In Contents/Library/LaunchAgents of the app bundle.
    static let launchAgentPlistName = "xyz.0xmwehehe.vaultwardenApp.ApplePasswordsBridge.plist"
    static let appIdentifier = "xyz.0xmwehehe.vaultwardenApp"
    static let bridgeIdentifier = "xyz.0xmwehehe.vaultwardenApp.ApplePasswordsBridge"
    /// The Chrome Web Store ID of Apple's iCloud Passwords extension.
    static let extensionID = "pejdijmoenmkgeppbflobdenhhabjlaj"

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
    /// Starts the browser, preferring `browserID` when it is installed with the extension.
    case connect(browserID: String?)
    /// Shows Apple's pairing PIN on this Mac.
    case requestPIN
    case submitPIN(String)
    case accounts(site: String)
    case password(site: String, username: String)
    case save(site: String, username: String, password: String)
    case oneTimeCodes(site: String)
    /// Quits the browser. The agent exits once nothing is connected.
    case disconnect
}

nonisolated enum ApplePasswordsBridgeResponse: Codable, Sendable, Equatable {
    case status(ApplePasswordsBridgeStatus)
    case accounts([ApplePasswordsAccount])
    case codes([ApplePasswordsCode])
    case done
    case failure(String)
}

nonisolated struct ApplePasswordsBrowser: Codable, Sendable, Hashable, Identifiable {
    var id: String
    var name: String
    var hasExtension: Bool
}

nonisolated struct ApplePasswordsBridgeStatus: Codable, Sendable, Equatable {
    enum Phase: String, Codable, Sendable {
        /// No browser running.
        case stopped
        /// The browser is starting or the extension hasn't connected yet.
        case starting
        /// Running, waiting for the PIN.
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
        case .serverError: "Unexpected response from the iCloud Passwords extension."
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

// MARK: - Extension messages

/// The commands the iCloud Passwords extension sends its native helper.
nonisolated enum ApplePasswordsCommand: Int, Sendable {
    case handshake = 2
    case getLoginNamesForURL = 4
    case getPasswordForLoginName = 5
    case setPasswordForLoginNameAndURL = 6
    case getOneTimeCodes = 16
    case didFillOneTimeCode = 17
}

nonisolated enum ApplePasswordsAction: Int, Sendable {
    case search = 2
    case maybeAdd = 4
    case ghostSearch = 5
}

/// What the agent sends the script inside the extension. `request` messages are
/// encrypted by the extension with its paired session key before they reach the helper.
nonisolated enum ApplePasswordsExtensionMessage {
    static func challenge() -> [String: Any] {
        ["kind": "handshake"]
    }

    static func verify(pin: String) -> [String: Any] {
        ["kind": "handshake", "pin": pin]
    }

    static func state() -> [String: Any] {
        ["kind": "state"]
    }

    static func accounts(site: String) -> [String: Any] {
        request(
            .getLoginNamesForURL, qid: "CmdGetLoginNames4URL", tab: 1, url: site,
            body: ["ACT": ApplePasswordsAction.ghostSearch.rawValue, "URL": site]
        )
    }

    static func password(site: String, username: String) -> [String: Any] {
        request(
            .getPasswordForLoginName, qid: "CmdGetPassword4LoginName", tab: 0, url: site,
            body: ["ACT": ApplePasswordsAction.search.rawValue, "URL": site, "USR": username]
        )
    }

    static func save(site: String, username: String, password: String) -> [String: Any] {
        request(
            .setPasswordForLoginNameAndURL, qid: "CmdSetPassword4LoginName_URL", tab: 0, url: nil,
            body: [
                "ACT": ApplePasswordsAction.maybeAdd.rawValue,
                "URL": "", "USR": "", "PWD": "",
                "NURL": site, "NUSR": username, "NPWD": password,
            ]
        )
    }

    static func oneTimeCodes(site: String) -> [String: Any] {
        request(
            .getOneTimeCodes, qid: "CmdDidFillOneTimeCode", tab: 0, url: nil,
            body: [
                "ACT": ApplePasswordsAction.ghostSearch.rawValue,
                "TYPE": "oneTimeCodes",
                "frameURLs": [ApplePasswordsSite.frameURL(site)],
            ]
        )
    }

    private static func request(
        _ command: ApplePasswordsCommand,
        qid: String,
        tab: Int,
        url: String?,
        body: [String: Any]
    ) -> [String: Any] {
        var message: [String: Any] = [
            "kind": "request",
            "cmd": command.rawValue,
            "qid": qid,
            "tabId": tab,
            "frameId": tab,
            "body": body,
        ]
        if let url { message["url"] = url }
        return message
    }
}

// MARK: - Extension replies

nonisolated enum ApplePasswordsReply {
    /// The script answers `{id, data}` on success and `{id, status, error}` otherwise.
    static func data(from reply: [String: Any]) throws -> [String: Any] {
        if let data = reply["data"] as? [String: Any] { return data }
        let code = (reply["status"] as? Int).flatMap { ApplePasswordsStatusCode(rawValue: $0) } ?? .serverError
        if code == .success { return ["STATUS": 0] }
        throw ApplePasswordsError(code, reply["error"] as? String)
    }

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
