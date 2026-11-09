import Foundation
import Testing
@testable import vaultwardenApp

struct ApplePasswordsSiteTests {
    @Test(arguments: [
        ("example.com", "example.com"),
        ("https://Accounts.Example.com/login?next=1", "accounts.example.com"),
        ("  github.com  ", "github.com"),
        ("http://localhost:8080", "localhost"),
    ])
    func host(_ input: String, _ expected: String) {
        #expect(ApplePasswordsSite.host(input) == expected)
    }

    @Test(arguments: ["", "   ", "not a site", "intranet"])
    func rejectsNonWebsites(_ input: String) {
        #expect(ApplePasswordsSite.host(input) == nil)
    }

    @Test func frameURLAddsScheme() {
        #expect(ApplePasswordsSite.frameURL("example.com") == "http://example.com")
        #expect(ApplePasswordsSite.frameURL("https://example.com") == "https://example.com")
    }
}

struct ApplePasswordsMessageTests {
    @Test func accountsLookupIsAGhostSearch() throws {
        let message = ApplePasswordsExtensionMessage.accounts(site: "example.com")
        #expect(message["kind"] as? String == "request")
        #expect(message["cmd"] as? Int == ApplePasswordsCommand.getLoginNamesForURL.rawValue)
        #expect(message["url"] as? String == "example.com")
        let body = try #require(message["body"] as? [String: Any])
        #expect(body["ACT"] as? Int == ApplePasswordsAction.ghostSearch.rawValue)
        #expect(body["URL"] as? String == "example.com")
        // Must serialize for the WebSocket.
        _ = try JSONSerialization.data(withJSONObject: message)
    }

    @Test func saveCarriesTheNewLogin() throws {
        let message = ApplePasswordsExtensionMessage.save(site: "example.com", username: "alice", password: "pw")
        #expect(message["cmd"] as? Int == ApplePasswordsCommand.setPasswordForLoginNameAndURL.rawValue)
        #expect(message["url"] == nil)
        let body = try #require(message["body"] as? [String: Any])
        #expect(body["ACT"] as? Int == ApplePasswordsAction.maybeAdd.rawValue)
        #expect(body["NURL"] as? String == "example.com")
        #expect(body["NUSR"] as? String == "alice")
        #expect(body["NPWD"] as? String == "pw")
    }

    @Test func codesUseAFrameURL() throws {
        let message = ApplePasswordsExtensionMessage.oneTimeCodes(site: "example.com")
        let body = try #require(message["body"] as? [String: Any])
        #expect(body["frameURLs"] as? [String] == ["http://example.com"])
        #expect(body["TYPE"] as? String == "oneTimeCodes")
    }

    @Test func handshakeCarriesThePIN() {
        #expect(ApplePasswordsExtensionMessage.challenge()["pin"] == nil)
        #expect(ApplePasswordsExtensionMessage.verify(pin: "123456")["pin"] as? String == "123456")
    }
}

struct ApplePasswordsReplyTests {
    @Test func readsEntriesArray() throws {
        let data: [String: Any] = [
            "STATUS": 0,
            "Entries": [
                ["USR": "alice", "PWD": "secret", "sites": ["https://example.com"], "highLevelDomain": "example.com"],
                ["USR": "bob", "sites": ["https://example.com"]],
            ],
        ]
        let accounts = try ApplePasswordsReply.accounts(from: data)
        #expect(accounts.map(\.username) == ["alice", "bob"])
        #expect(accounts[0].password == "secret")
        #expect(accounts[1].password == nil)
        #expect(accounts[0].primarySite == "example.com")
        #expect(accounts[1].primarySite == "example.com")
    }

    @Test func readsNumberedEntriesInOrder() throws {
        let data: [String: Any] = [
            "STATUS": 0,
            "Entry_10": ["USR": "third"],
            "Entry_2": ["USR": "second"],
            "Entry_1": ["USR": "first"],
        ]
        #expect(try ApplePasswordsReply.accounts(from: data).map(\.username) == ["first", "second", "third"])
    }

    @Test func noResultsIsEmpty() throws {
        #expect(try ApplePasswordsReply.accounts(from: ["STATUS": 3]).isEmpty)
    }

    @Test func errorStatusThrows() {
        #expect(throws: ApplePasswordsError(.invalidSession)) {
            try ApplePasswordsReply.accounts(from: ["STATUS": 9])
        }
    }

    @Test func scriptFailureThrowsItsMessage() {
        #expect(throws: ApplePasswordsError(.invalidSession, "Not paired")) {
            try ApplePasswordsReply.data(from: ["id": "1", "status": 9, "error": "Not paired"])
        }
    }

    @Test func readsCodes() throws {
        let data: [String: Any] = [
            "STATUS": 0,
            "Entries": [["username": "alice", "domain": "example.com", "code": "123456", "source": "totp"]],
        ]
        let codes = try ApplePasswordsReply.codes(from: data)
        #expect(codes == [ApplePasswordsCode(username: "alice", domain: "example.com", code: "123456", source: "totp")])
    }

    @Test func bridgeMessagesRoundTrip() throws {
        let requests: [ApplePasswordsBridgeRequest] = [
            .status, .connect(browserID: nil), .connect(browserID: "edge"), .requestPIN, .submitPIN("123456"),
            .accounts(site: "example.com"), .password(site: "example.com", username: "alice"),
            .save(site: "example.com", username: "alice", password: "pw"), .oneTimeCodes(site: "example.com"), .disconnect,
        ]
        for request in requests {
            let data = try JSONEncoder().encode(request)
            #expect(try JSONDecoder().decode(ApplePasswordsBridgeRequest.self, from: data) == request)
        }
    }
}

struct ApplePasswordsImportTests {
    private let vault = [
        VaultItem(name: "Example", username: "alice", password: "x", uri: "https://accounts.example.com/login"),
        VaultItem(name: "GitHub", username: "octo", password: "y", uri: "github.com"),
        VaultItem(name: "Note", type: .secureNote),
    ]

    @Test func sitesAreRegistrableDomains() {
        #expect(ApplePasswordsImport.sites(in: vault) == ["example.com", "github.com"])
    }

    @Test func matchesBySiteAndUserName() {
        let alice = ApplePasswordsAccount(username: "Alice", sites: ["https://www.example.com"], domain: "example.com")
        let bob = ApplePasswordsAccount(username: "bob", sites: ["https://example.com"], domain: "example.com")
        #expect(ApplePasswordsImport.isInVault(alice, items: vault))
        #expect(!ApplePasswordsImport.isInVault(bob, items: vault))
        #expect(ApplePasswordsImport.missing([alice, bob, bob], items: vault) == [bob])
    }

    @Test func buildsALogin() {
        let account = ApplePasswordsAccount(
            username: "bob",
            sites: ["https://example.com", "https://login.example.net"],
            domain: "example.com",
            title: nil
        )
        let item = ApplePasswordsImport.vaultItem(for: account, password: "pw")
        #expect(item.type == .login)
        #expect(item.name == "example.com")
        #expect(item.username == "bob")
        #expect(item.password == "pw")
        #expect(item.uri == "https://example.com")
        #expect(item.additionalURIs == ["https://login.example.net"])
    }
}
