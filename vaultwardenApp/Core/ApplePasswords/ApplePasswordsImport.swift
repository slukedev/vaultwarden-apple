import Foundation

/// Matching between Apple Passwords accounts and vault logins. Pure, so it is tested
/// without the agent.
nonisolated enum ApplePasswordsImport {
    /// Registrable domains of the vault's live logins, one lookup each.
    static func sites(in items: [VaultItem]) -> [String] {
        var seen = Set<String>()
        var sites: [String] = []
        for item in items where item.type == .login && !item.isDeleted && !item.isArchived {
            for uri in item.websiteURIs {
                guard let host = ApplePasswordsSite.host(uri), !AutoFillDomain.isIPAddress(host) else { continue }
                let site = AutoFillDomain.registrableDomain(host)
                if seen.insert(site).inserted { sites.append(site) }
            }
        }
        return sites.sorted()
    }

    /// Whether the vault already has a login for this account's site and user name.
    static func isInVault(_ account: ApplePasswordsAccount, items: [VaultItem]) -> Bool {
        let site = registrableSite(of: account)
        let username = account.username.lowercased()
        return items.contains { item in
            guard item.type == .login, !item.isDeleted, item.username.lowercased() == username else { return false }
            return item.websiteURIs.contains { uri in
                ApplePasswordsSite.host(uri).map(AutoFillDomain.registrableDomain) == site
            }
        }
    }

    /// Accounts missing from the vault, without duplicates.
    static func missing(_ accounts: [ApplePasswordsAccount], items: [VaultItem]) -> [ApplePasswordsAccount] {
        var seen = Set<String>()
        return accounts.filter { account in
            let key = "\(registrableSite(of: account))\u{1F}\(account.username.lowercased())"
            return !isInVault(account, items: items) && seen.insert(key).inserted
        }
    }

    /// A new login for the vault.
    static func vaultItem(for account: ApplePasswordsAccount, password: String) -> VaultItem {
        let host = ApplePasswordsSite.host(account.sites.first ?? "") ?? account.primarySite
        let name = account.title.flatMap { $0.isEmpty ? nil : $0 } ?? account.primarySite
        let extra = account.sites.dropFirst().compactMap(ApplePasswordsSite.host).map { "https://\($0)" }
        return VaultItem(
            name: name,
            username: account.username,
            password: password,
            uri: host.isEmpty ? "" : "https://\(host)",
            additionalURIs: extra.isEmpty ? nil : extra,
            type: .login
        )
    }

    private static func registrableSite(of account: ApplePasswordsAccount) -> String {
        let host = ApplePasswordsSite.host(account.primarySite) ?? account.primarySite.lowercased()
        return AutoFillDomain.registrableDomain(host)
    }
}
