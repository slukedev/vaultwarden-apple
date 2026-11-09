import CryptoKit
import Foundation
import Security

/// The App Group and Keychain group every Vaultwarden target shares.
nonisolated enum AutoFillContainer {
    static let appGroupIdentifier = "group.xyz.0xmwehehe.vaultwardenApp"

    static var keychainAccessGroup: String {
        let fallback = "5KQGTJX2K7.xyz.0xmwehehe.vaultwardenApp.shared"
        guard let configured = Bundle.main.object(
            forInfoDictionaryKey: "VaultSharedKeychainAccessGroup"
        ) as? String,
              configured != "xyz.0xmwehehe.vaultwardenApp.shared" else {
            return fallback
        }
        return configured
    }

    static var directory: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupIdentifier)
    }

    static func keychainQuery(service: String, account: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: keychainAccessGroup
        ]
        #if os(macOS)
        query[kSecUseDataProtectionKeychain as String] = true
        #endif
        return query
    }
}

/// What the Safari extension may know without unlocking the vault: keyed hashes of
/// the sites, usernames and passwords AutoFill can fill. It holds no names, hosts,
/// usernames or secrets, and the key never leaves this device's Keychain.
nonisolated struct AutoFillSiteIndex: Codable, Sendable, Equatable {
    /// How a password typed into a page relates to what the vault already has.
    enum Knowledge: String, Sendable {
        case saved
        case changedPassword
        case new
    }

    private static let version = 1
    private static let fileName = "autofill-sites.json"
    private static let keyService = "xyz.0xmwehehe.vaultwardenApp.autofill.site-index-key"

    let version: Int
    /// Hashed registrable domain to the number of logins for it.
    let domains: [String: Int]
    /// Hashed domain and username.
    let accounts: Set<String>
    /// Hashed domain, username and password.
    let credentials: Set<String>

    static let empty = Self(version: version, domains: [:], accounts: [], credentials: [])

    // MARK: Building

    /// One login, reduced to what the index hashes.
    struct Entry: Sendable {
        /// Registrable domains the login fills on.
        let sites: Set<String>
        let username: String
        let password: String
    }

    static func make(entries: [Entry], key: SymmetricKey) -> Self {
        var domains: [String: Int] = [:]
        var accounts: Set<String> = []
        var credentials: Set<String> = []
        for entry in entries where !entry.password.isEmpty {
            let user = normalizedUsername(entry.username)
            for site in entry.sites {
                domains[digest(["site", site], key: key), default: 0] += 1
                accounts.insert(digest(["account", site, user], key: key))
                credentials.insert(digest(["credential", site, user, entry.password], key: key))
            }
        }
        return Self(version: version, domains: domains, accounts: accounts, credentials: credentials)
    }

    // MARK: Questions

    func loginCount(forPage page: String, key: SymmetricKey) -> Int {
        guard let site = Self.site(page) else { return 0 }
        return domains[Self.digest(["site", site], key: key)] ?? 0
    }

    func knowledge(page: String, username: String, password: String, key: SymmetricKey) -> Knowledge {
        guard let site = Self.site(page), !password.isEmpty else { return .saved }
        let user = Self.normalizedUsername(username)
        if credentials.contains(Self.digest(["credential", site, user, password], key: key)) {
            return .saved
        }
        if accounts.contains(Self.digest(["account", site, user], key: key)) {
            return .changedPassword
        }
        return .new
    }

    private static func site(_ page: String) -> String? {
        AutoFillDomain.host(page).map(AutoFillDomain.registrableDomain)
    }

    private static func normalizedUsername(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    private static func digest(_ parts: [String], key: SymmetricKey) -> String {
        // Length-prefixed, so ("ab", "c") and ("a", "bc") never collide.
        var message = Data()
        for part in parts {
            let bytes = Data(part.utf8)
            withUnsafeBytes(of: UInt32(bytes.count).bigEndian) { message.append(contentsOf: $0) }
            message.append(bytes)
        }
        return HMAC<SHA256>.authenticationCode(for: message, using: key)
            .prefix(16)
            .map { String(format: "%02x", $0) }
            .joined()
    }

    // MARK: Storage

    static func publish(entries: [Entry]) throws {
        let key = try storedKey(createIfMissing: true)
        let index = make(entries: entries, key: key)
        guard let url = fileURL else { return }
        let data = try JSONEncoder().encode(index)
        #if os(macOS)
        try data.write(to: url, options: .atomic)
        #else
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #endif
    }

    /// The published index and its key, or nil before the app has published one.
    static func load() -> (index: Self, key: SymmetricKey)? {
        guard let url = fileURL,
              let data = try? Data(contentsOf: url),
              let index = try? JSONDecoder().decode(Self.self, from: data),
              index.version == version,
              let key = try? storedKey(createIfMissing: false) else { return nil }
        return (index, key)
    }

    static func clear() {
        if let url = fileURL { try? FileManager.default.removeItem(at: url) }
        SecItemDelete(AutoFillContainer.keychainQuery(service: keyService, account: "index") as CFDictionary)
    }

    private static var fileURL: URL? {
        AutoFillContainer.directory?.appendingPathComponent(fileName, isDirectory: false)
    }

    private static func storedKey(createIfMissing: Bool) throws -> SymmetricKey {
        let lookup = AutoFillContainer.keychainQuery(service: keyService, account: "index")
        var query = lookup
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data, data.count == 32 {
            return SymmetricKey(data: data)
        }
        guard createIfMissing, status == errSecItemNotFound else {
            throw AutoFillSiteIndexError.keychain(status)
        }
        let key = SymmetricKey(size: .bits256)
        var add = lookup
        add[kSecValueData as String] = key.withUnsafeBytes { Data($0) }
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw AutoFillSiteIndexError.keychain(addStatus) }
        return key
    }
}

nonisolated enum AutoFillSiteIndexError: Error {
    case keychain(OSStatus)
}

/// A login typed into a Safari page on the Mac, waiting for the person to save it.
/// Lives only in this device's Keychain, for ten minutes at most.
nonisolated struct SafariCapturedLogin: Codable, Sendable, Identifiable, Equatable {
    static let lifetime: TimeInterval = 600
    private static let service = "xyz.0xmwehehe.vaultwardenApp.safari.captured-login"

    let id: String
    let page: String
    let username: String
    let password: String
    let isPasswordChange: Bool
    let capturedAt: Date

    var host: String {
        guard let host = AutoFillDomain.host(page) else { return page }
        return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
    }

    var isExpired: Bool { Date().timeIntervalSince(capturedAt) > Self.lifetime }

    /// Keeps only the newest capture, so a stale one can never be saved by mistake.
    static func store(_ login: Self) throws {
        removeAll()
        var add = AutoFillContainer.keychainQuery(service: service, account: login.id)
        add[kSecValueData as String] = try JSONEncoder().encode(login)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw AutoFillSiteIndexError.keychain(status) }
    }

    static func load(id: String) -> Self? {
        var query = AutoFillContainer.keychainQuery(service: service, account: id)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let login = try? JSONDecoder().decode(Self.self, from: data) else { return nil }
        guard !login.isExpired else {
            remove(id: id)
            return nil
        }
        return login
    }

    /// The capture for a page on the same site, if one is waiting.
    static func pending(forPage page: String) -> Self? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccessGroup as String: AutoFillContainer.keychainAccessGroup,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        #if os(macOS)
        query[kSecUseDataProtectionKeychain as String] = true
        #endif
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let items = result as? [[String: Any]] else { return nil }
        let site = AutoFillDomain.host(page).map(AutoFillDomain.registrableDomain)
        for item in items {
            guard let id = item[kSecAttrAccount as String] as? String,
                  let login = load(id: id) else { continue }
            if AutoFillDomain.host(login.page).map(AutoFillDomain.registrableDomain) == site {
                return login
            }
        }
        return nil
    }

    static func remove(id: String) {
        SecItemDelete(AutoFillContainer.keychainQuery(service: service, account: id) as CFDictionary)
    }

    static func removeAll() {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccessGroup as String: AutoFillContainer.keychainAccessGroup
        ]
        #if os(macOS)
        query[kSecUseDataProtectionKeychain as String] = true
        #endif
        SecItemDelete(query as CFDictionary)
    }
}

/// Links the Safari extension uses to hand work to the app.
nonisolated enum SafariAppLink: Equatable, Sendable {
    static let scheme = "vaultwarden-app"

    case search(website: String)
    case newLogin(website: String)
    case saveLogin(id: String)

    var url: URL? {
        var components = URLComponents()
        components.scheme = Self.scheme
        switch self {
        case let .search(website):
            components.host = "search"
            components.queryItems = [URLQueryItem(name: "website", value: Self.origin(of: website) ?? "")]
        case let .newLogin(website):
            components.host = "new-login"
            components.queryItems = [URLQueryItem(name: "website", value: Self.origin(of: website) ?? "")]
        case let .saveLogin(id):
            components.host = "save-login"
            components.queryItems = [URLQueryItem(name: "id", value: id)]
        }
        return components.url
    }

    init?(url: URL) {
        guard url.scheme?.lowercased() == Self.scheme,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        let value: (String) -> String = { name in
            components.queryItems?.first { $0.name == name }?.value ?? ""
        }
        switch components.host?.lowercased() {
        case "search":
            self = .search(website: Self.origin(of: value("website")) ?? "")
        case "new-login":
            self = .newLogin(website: Self.origin(of: value("website")) ?? "")
        case "save-login":
            let id = value("id")
            guard !id.isEmpty, id.count <= 64 else { return nil }
            self = .saveLogin(id: id)
        default:
            return nil
        }
    }

    /// "https://example.com" for any page on that host. Paths and queries can hold
    /// tokens, so they never leave the page.
    static func origin(of page: String) -> String? {
        guard let components = URLComponents(string: page.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = components.scheme?.lowercased(), scheme == "https" || scheme == "http",
              let host = components.host?.lowercased(), !host.isEmpty else { return nil }
        var origin = URLComponents()
        origin.scheme = scheme
        origin.host = host
        origin.port = components.port
        return origin.string
    }
}
