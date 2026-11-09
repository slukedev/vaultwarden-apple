import AuthenticationServices
import CryptoKit
import Foundation
import Testing
@testable import vaultwardenApp

private func record(
    _ id: String,
    rules: [(String, AutoFillURIMatchType?)],
    username: String = "",
    password: String = "secret"
) -> AutoFillCredentialRecord {
    AutoFillCredentialRecord(
        id: id,
        name: id,
        username: username,
        password: password,
        serviceIdentifier: rules.first.flatMap { AutoFillSearch.displayHost($0.0) },
        totpSecret: nil,
        uriRules: rules.map { AutoFillURIRule(uri: $0.0, match: $0.1) }
    )
}

struct AutoFillRegistrableDomainTests {
    @Test(arguments: [
        ("accounts.google.com", "google.com"),
        ("google.com", "google.com"),
        ("shop.example.co.uk", "example.co.uk"),
        ("alice.github.io", "alice.github.io"),
        ("docs.alice.github.io", "alice.github.io"),
        ("github.io", "github.io"),
        ("store.blob.core.windows.net", "store.blob.core.windows.net"),
        ("my-app.vercel.app", "my-app.vercel.app"),
        ("WWW.Example.COM.", "example.com"),
        ("192.168.1.10", "192.168.1.10"),
        ("localhost", "localhost")
    ])
    func ownerScopedDomain(host: String, expected: String) {
        #expect(AutoFillDomain.registrableDomain(host) == expected)
    }

    @Test func oneHostingCustomerNeverGetsAnothersPassword() {
        let result = AutoFillPicker.sections(
            records: [record("alice", rules: [("https://alice.github.io", nil)])],
            context: .services(["https://mallory.github.io/login"], defaultMatchType: .baseDomain),
            usage: .empty
        )

        #expect(result.suggested.isEmpty)
    }

    @Test func theSameHostOutranksASiblingSubdomain() {
        let exactHost = record("login", rules: [("login.example.com", nil)])
        let sibling = record("www", rules: [("www.example.com", nil)])

        #expect(exactHost.bestMatch(serviceIdentifiers: ["https://login.example.com"]) == .host)
        #expect(sibling.bestMatch(serviceIdentifiers: ["https://login.example.com"]) == .baseDomain)
    }
}

struct AutoFillAppIdentifierTests {
    @Test(arguments: [
        ("ABCDE12345.com.Example.App", "iosapp://com.example.app"),
        ("com.example.app", "iosapp://com.example.app"),
        ("abcde12345.com.example.app", "iosapp://abcde12345.com.example.app")
    ])
    func appIDsBecomeVaultURIs(appID: String, expected: String) {
        #expect(AutoFillDomain.appURI(fromAppID: appID) == expected)
    }

    @Test func savedAppMatchesOnlyThatApp() {
        let app = record("app", rules: [("iosapp://com.example.app", nil)])

        #expect(app.bestMatch(serviceIdentifiers: ["iosapp://com.example.app"]) == .exact)
        #expect(app.bestMatch(serviceIdentifiers: ["iosapp://com.example.other"]) == nil)
        #expect(app.bestMatch(serviceIdentifiers: ["https://app.example.com"]) == nil)
    }

    @Test func websiteNeverMatchesAnApp() {
        let website = record("web", rules: [("https://example.com", nil)])

        #expect(website.bestMatch(serviceIdentifiers: ["iosapp://com.example"]) == nil)
    }

    @Test func appURIsAreNotShownAsWebsites() {
        let mixed = record("mixed", rules: [("iosapp://com.example.app", nil), ("example.com", nil)])

        #expect(AutoFillSearch.websites(for: mixed) == ["example.com"])
    }
}

struct AutoFillQuickTypeHostTests {
    @Test func everyMatchableWebsiteIsOffered() {
        let multi = record("multi", rules: [
            ("https://www.example.com/login", nil),
            ("https://accounts.example.org", .host),
            ("example.com/other", .startsWith),
            ("WWW.EXAMPLE.COM", .exact)
        ])

        #expect(AutoFillCredentialIdentityBuilder.suggestedHosts(for: multi, defaultMatchType: .baseDomain)
            == ["www.example.com", "accounts.example.org", "example.com"])
    }

    @Test func rulesThatCantMatchAHostAreSkipped() {
        let rules = record("rules", rules: [
            ("https://never.example", .never),
            ("^https://.*\\.example\\.net", .regularExpression),
            ("iosapp://com.example.app", nil),
            ("androidapp://com.example.app", nil)
        ])

        #expect(AutoFillCredentialIdentityBuilder.suggestedHosts(for: rules, defaultMatchType: .baseDomain).isEmpty)
    }

    @Test func defaultNeverHidesRulesWithoutTheirOwnMatch() {
        let rules = record("rules", rules: [("a.example", nil), ("b.example", .host)])

        #expect(AutoFillCredentialIdentityBuilder.suggestedHosts(for: rules, defaultMatchType: .never) == ["b.example"])
    }

    @Test func eachWebsiteGetsItsOwnPasswordIdentity() {
        let payload = AutoFillVaultPayload(
            schemaVersion: 4,
            accountReference: "account",
            generatedAt: Date(),
            credentials: [record("multi", rules: [("example.com", nil), ("example.org", nil)], username: "me")],
            passkeys: nil, passkeyCiphers: nil, cryptoContext: nil, writeSession: nil, userKey: nil,
            folders: nil, passkeyTargets: nil
        )

        let identities = AutoFillCredentialIdentityBuilder.identities(
            for: payload,
            usage: .empty,
            defaultMatchType: .baseDomain
        ).compactMap { $0 as? ASPasswordCredentialIdentity }

        #expect(identities.map(\.serviceIdentifier.identifier) == ["example.com", "example.org"])
        #expect(identities.allSatisfy { $0.recordIdentifier == "password|multi" && $0.serviceIdentifier.type == .domain })
    }
}

struct AutoFillMultiWordSearchTests {
    private let sections = AutoFillPickerSections(
        suggested: [],
        other: [
            AutoFillPickerEntry(record: record("work", rules: [("github.com", nil)], username: "me@work.test")),
            AutoFillPickerEntry(record: record("home", rules: [("github.com", nil)], username: "me@home.test")),
            AutoFillPickerEntry(record: record("mail", rules: [("mail.work.test", nil)], username: "me"))
        ],
        isContextual: false
    )

    @Test func everyWordMustAppear() {
        #expect(sections.filtered(by: "github work").other.map(\.id) == ["work"])
        #expect(sections.filtered(by: "  WORK   github ").other.map(\.id) == ["work"])
    }

    @Test func aPastedURLIsOneWord() {
        #expect(sections.filtered(by: "https://www.github.com/login?return=home").other.map(\.id) == ["work", "home"])
    }

    @Test func anUnmatchedWordFindsNothing() {
        #expect(sections.filtered(by: "github nowhere").other.isEmpty)
    }
}

struct AutoFillSiteIndexTests {
    private let key = SymmetricKey(size: .bits256)

    private func index(_ records: [AutoFillCredentialRecord]) -> AutoFillSiteIndex {
        AutoFillSiteIndex.make(
            entries: AutoFillSharedVault.siteIndexEntries(for: records, defaultMatchType: .baseDomain),
            key: key
        )
    }

    @Test func countsLoginsForTheWholeSite() {
        let index = index([
            record("a", rules: [("https://example.com", nil)], username: "a"),
            record("b", rules: [("login.example.com", nil)], username: "b"),
            record("c", rules: [("other.test", nil)], username: "c")
        ])

        #expect(index.loginCount(forPage: "https://www.example.com/sign-in", key: key) == 2)
        #expect(index.loginCount(forPage: "https://other.test", key: key) == 1)
        #expect(index.loginCount(forPage: "https://unknown.test", key: key) == 0)
    }

    @Test func tellsSavedChangedAndNewApart() {
        let index = index([record("a", rules: [("example.com", nil)], username: "Me@Example.com", password: "old")])
        let page = "https://accounts.example.com/login"

        #expect(index.knowledge(page: page, username: " me@example.com ", password: "old", key: key) == .saved)
        #expect(index.knowledge(page: page, username: "me@example.com", password: "new", key: key) == .changedPassword)
        #expect(index.knowledge(page: page, username: "someone", password: "old", key: key) == .new)
        #expect(index.knowledge(page: "https://elsewhere.test", username: "me@example.com", password: "old", key: key) == .new)
    }

    @Test func holdsNoReadableNamesOrSecrets() throws {
        let index = index([record("a", rules: [("example.com", nil)], username: "visible-user", password: "visible-secret")])

        let json = try #require(String(data: JSONEncoder().encode(index), encoding: .utf8))
        #expect(!json.contains("example"))
        #expect(!json.contains("visible"))
    }

    @Test func aDifferentKeyRecognizesNothing() {
        let index = index([record("a", rules: [("example.com", nil)], username: "me", password: "pw")])
        let otherKey = SymmetricKey(size: .bits256)

        #expect(index.loginCount(forPage: "example.com", key: otherKey) == 0)
        #expect(index.knowledge(page: "example.com", username: "me", password: "pw", key: otherKey) == .new)
    }
}

struct SafariAppLinkTests {
    @Test(arguments: [
        SafariAppLink.search(website: "https://example.com"),
        .newLogin(website: "https://login.example.com:8443"),
        .saveLogin(id: "6F9619FF-8B86-D011-B42D-00CF4FC964FF")
    ])
    func linksRoundTrip(link: SafariAppLink) throws {
        let url = try #require(link.url)

        #expect(SafariAppLink(url: url) == link)
    }

    @Test func pagesShareOnlyTheirOrigin() {
        #expect(SafariAppLink.origin(of: "https://Example.com/reset?token=secret#x") == "https://example.com")
        #expect(SafariAppLink.origin(of: "javascript:alert(1)") == nil)
        #expect(SafariAppLink.origin(of: "file:///etc/passwd") == nil)
    }

    @Test func foreignAndMalformedLinksAreIgnored() throws {
        #expect(SafariAppLink(url: try #require(URL(string: "otpauth://totp/x?secret=ABC"))) == nil)
        #expect(SafariAppLink(url: try #require(URL(string: "vaultwarden-app://delete-everything"))) == nil)
        #expect(SafariAppLink(url: try #require(URL(string: "vaultwarden-app://save-login"))) == nil)
    }

    @MainActor
    @Test func linksBecomeVaultActions() {
        #expect(HomeQuickAction(safariLink: .search(website: "https://www.github.com")) == .search(query: "github.com"))
        #expect(HomeQuickAction(safariLink: .saveLogin(id: "abc")) == .saveSafariLogin(id: "abc"))
    }
}
