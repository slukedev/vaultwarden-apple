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

struct APBigUIntTests {
    @Test func hexRoundTrip() throws {
        let value = try #require(APBigUInt(hex: "0x00ff0102030405060708090a0b0c0d0e0f"))
        #expect(ApplePasswordsSecretSession.hex(value.bytes) == "ff0102030405060708090a0b0c0d0e0f")
        #expect(value.paddedBytes(20).count == 20)
        #expect(APBigUInt(bytes: [0, 0]).bytes == [0])
        #expect(APBigUInt(bytes: [0, 0]).isZero)
    }

    @Test func arithmetic() throws {
        let a = try #require(APBigUInt(hex: "ffffffffffffffffffffffff"))
        let b = try #require(APBigUInt(hex: "10000000000000003"))
        #expect(a * b == APBigUInt(hex: "10000000000000002fffffffefffffffffffffffd"))
        let c = try #require(APBigUInt(hex: "ffffffffffffffffffffffffffffffff"))
        #expect(c + c == APBigUInt(hex: "1fffffffffffffffffffffffffffffffe"))
        #expect(c - APBigUInt(hex: "10000000000000000")! == APBigUInt(hex: "fffffffffffffffeffffffffffffffff"))
        #expect(b < a)
    }

    @Test func montgomeryPower() throws {
        #expect(APMontgomery(modulus: APBigUInt(1_000_003)).power(APBigUInt(3), APBigUInt(200)) == APBigUInt(333_986))
        let m61 = try #require(APBigUInt(hex: "1fffffffffffffff"))
        let exponent = try #require(APBigUInt(hex: "10000000000000005"))
        #expect(APMontgomery(modulus: m61).power(APBigUInt(7), exponent) == APBigUInt(hex: String(558545864083284007, radix: 16)))
        let m127 = try #require(APBigUInt(hex: "7fffffffffffffffffffffffffffffff"))
        let base = try #require(APBigUInt(hex: "deadbeef"))
        let power = try #require(APBigUInt(hex: "123456789abcdef"))
        let result = APMontgomery(modulus: m127).power(base, power)
        #expect(result == APBigUInt(hex: "5927e79cd78b029b869a6485f3a645e2"))
        #expect(APMontgomery(modulus: m127).power(APBigUInt(9), APBigUInt(0)) == APBigUInt(1))
    }
}

/// Vectors from an independent Python implementation of RFC 5054 SRP-6a with Apple's
/// framing, checked against a server-side computation of the same secret.
struct ApplePasswordsSRPTests {
    static let usernameBytes = [UInt8](1...16)
    static let privateKey = [UInt8](32..<64)
    static let salt = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    static let iv = [UInt8](200..<216)

    private func bytes(_ hex: String) -> [UInt8] { APBigUInt(hex: hex)!.paddedBytes(hex.count / 2) }

    @Test func hexSessionMatchesReference() throws {
        var session = ApplePasswordsSecretSession(usesBase64: false, usernameBytes: Self.usernameBytes, privateKey: Self.privateKey)
        #expect(session.username == "0x0102030405060708090a0b0c0d0e0f10")
        #expect(ApplePasswordsSecretSession.hex(session.publicKey.bytes) == "6823a16e8d3da8dda8a489cbe3a749a0381059e67fe720588d2abf43325a134c4f04f54ec63e53a89701e337f53bddd7c4251b1efb7066710786abb4d657d14642d954734f2b2c683febf971038b9d63c9372664108ca8c06c7318f7e375fd86222602ee939a6df598fac3e65a384191556ff015fb2a484d901c12090f8bf5dd430d5b2fe9eadca8ab478d0e77835de48a5b7fdd79e2e39200495806a41095bbeea594d53def231f92f5536d89d42210c720b0e0ba45277a7c136179d7fc1c2cd8500abf42fb277b31e4e111154f334e01b26d842d016a6f4b45d54eb43a7af8bad817ac4bd5e9a1b5870be4e8c64a774d7cf99ed0df2d85a0d7dac8d7978fc09c4b05e840eb7c32ab8a0d3e76e954606c6f19f73ffbffdce10f0143d027a6a291de46f98ba1ef731fcde654cf6c35a3bc0239340b247250d2433c1a8653856283ec656b1dc4f6c78ab489aa46a07a1953b168b194c9517b3af831d8cb60257446709568fbd56bf2cfab568bc6428a0289c574b223835ddd3acf3bebd5ca8590")
        try session.setServer(publicKey: APBigUInt(hex: "12fc0fa92af955137bfe2084ba325a92be99c636d911c75f072605bbc8a38c88a1ec68650525310a7eb4a91654b2b643324948f9a6f77523c7106a00e743e56913d64c37a0908dedb0170ac251281aadd7f04e1039dad2ad12987dc390a65f807a05dc6d84caef34a2d94954108f112f4bb84b8d3c112ab06de507e8a9073a5c493b30302d233f1f0b71843510940b4ecfc6cd71e2f84bc530cf83330578b52fd01e600c2967fbba7b620b06b6b7ab7c96314aa64f02858b08268dfc57084b878ac5d7e850e700644f72d746381f495f839cea9d80fd58bdc9095da88568d55d81589ba843e5b4c758bb7ea3ee4a25c7ebc6f83493e0d09d0157c312f23a87d9f957d7c8b7cd141409671c39b18302d4391eac4a0dea803a58821bf9625354435dffcff2056fc50aee539338925cbf400bbf455fe7da17bf2a7bd05f7a5daa6add62bc5161395dfce247230410e77e9ad4720d9e9b7e8e04ec699ab3f4259a0779163f5ca40482e126646bbf64ae7ab0998928318d76fc0efc51463b96623629")!, salt: APBigUInt(hex: Self.salt)!)
        try session.applyPIN("123456")
        #expect(ApplePasswordsSecretSession.hex(session.sharedKey!.paddedBytes(32)) == "6de3ebd6f2a2a32f29c698c066656f9b43da4c7457c1c89f3d437b0ce34e527c")
        let proof = try session.clientProof()
        #expect(ApplePasswordsSecretSession.hex(proof) == "225d3175a4e198ebfa847e063d94ee3513634e23a75b9300f9f306c3153150c3")
        #expect(ApplePasswordsSecretSession.hex(try session.expectedServerProof(for: proof)) == "94d34c46e9550e2f93c4a6a9bcafaa388fe65aadfbd7424de28af58e01fe5524")

        let sealed = try session.encrypt(Data(#"{"ACT":5,"URL":"example.com"}"#.utf8), iv: Self.iv)
        #expect(ApplePasswordsSecretSession.hex(sealed) == "17b1e1e1bcf69a37aa8e4d77f9a5fc6a7691945199f5b393022b1fedd4dfa89a6f53aa002144d5108957228afec8c9cacbcccdcecfd0d1d2d3d4d5d6d7")
        let opened = try session.decrypt(bytes("c8c9cacbcccdcecfd0d1d2d3d4d5d6d717b1f3f6a980f551a496280997c2a83c6180904fcba38dc64311219d8babf3c3791853b547f4bdd024c905338f0336066647ddfcfd127f3a"))
        #expect(String(decoding: opened, as: UTF8.self) == #"{"STATUS":0,"Entries":[{"USR":"alice"}]}"#)
    }

    @Test func base64SessionMatchesReference() throws {
        var session = ApplePasswordsSecretSession(usesBase64: true, usernameBytes: Self.usernameBytes, privateKey: Self.privateKey)
        #expect(session.username == "AQIDBAUGBwgJCgsMDQ4PEA==")
        try session.setServer(publicKey: APBigUInt(hex: "92fe3b5a9ec3726dd70da47bab64b7266bbb68355708699e0fbe48766d356c0662da5bc9cb1b979ca47ae040b0e74c0668e92e025c3e17a1bf1b625fab71ff4e6ee4e5c500a574c29b4c4f6897157b48c97a0da9e24af87347e2f8c4de8acbfb63ae8edde66a7e1f18dc37eb3a193f9564851862106a823580f35c5542629e79da988ddc2ac59694fa4a1cf9b8398e0a1cbbf81c4f16e58cd81092d7988bb60c26f40159709cc7da3884cfa28f9ee5393f0216e9e9fbc4ab24b21c0adfd09ff89279cb3701a567b0ce02504a7ae29e0e5424a25c123c7f27baed7b462cf735d3ce0c4ab2c9adc6d2913c52d14859bd5e897886502e547440d3741b560ed397f1dca3d892ed454bf6bc25bae8ce52b9ef0b1ac8e246622419f39c5a25684eceeadf57bf386773c881541a95e2646474433ab7cbd96dda676c59d1b4cb2e47ee55c53bb50625d4d210bd2139d97d9ac283d4624befce0c82aaeade80976e889b3c24df5c97083f1f54cce00a43e5bd439d455a8d6567f03f8199ca92c2b7d1ff35")!, salt: APBigUInt(hex: Self.salt)!)
        try session.applyPIN("123456")
        #expect(ApplePasswordsSecretSession.hex(session.sharedKey!.paddedBytes(32)) == "ebbe8561ef3dc285e5dca24a4c02c60ad9dd72a9eb1c0f1d1eef46fe0f4e49a0")
        let proof = try session.clientProof()
        #expect(ApplePasswordsSecretSession.hex(proof) == "4862ce2362390c21663241c84b976c3bd9455f5607b6e19db599a257782095cd")
        #expect(ApplePasswordsSecretSession.hex(try session.expectedServerProof(for: proof)) == "3e62d5a9890bfd1c3245d3296f061e851fbd7d00941353895aae75d24efa99b5")
    }

    @Test func wrongPINGivesADifferentProof() throws {
        var right = ApplePasswordsSecretSession(usesBase64: false, usernameBytes: Self.usernameBytes, privateKey: Self.privateKey)
        try right.setServer(publicKey: APBigUInt(hex: "12fc0fa92af955137bfe2084ba325a92be99c636d911c75f072605bbc8a38c88a1ec68650525310a7eb4a91654b2b643324948f9a6f77523c7106a00e743e56913d64c37a0908dedb0170ac251281aadd7f04e1039dad2ad12987dc390a65f807a05dc6d84caef34a2d94954108f112f4bb84b8d3c112ab06de507e8a9073a5c493b30302d233f1f0b71843510940b4ecfc6cd71e2f84bc530cf83330578b52fd01e600c2967fbba7b620b06b6b7ab7c96314aa64f02858b08268dfc57084b878ac5d7e850e700644f72d746381f495f839cea9d80fd58bdc9095da88568d55d81589ba843e5b4c758bb7ea3ee4a25c7ebc6f83493e0d09d0157c312f23a87d9f957d7c8b7cd141409671c39b18302d4391eac4a0dea803a58821bf9625354435dffcff2056fc50aee539338925cbf400bbf455fe7da17bf2a7bd05f7a5daa6add62bc5161395dfce247230410e77e9ad4720d9e9b7e8e04ec699ab3f4259a0779163f5ca40482e126646bbf64ae7ab0998928318d76fc0efc51463b96623629")!, salt: APBigUInt(hex: Self.salt)!)
        var wrong = right
        try right.applyPIN("123456")
        try wrong.applyPIN("654321")
        #expect(try right.clientProof() != wrong.clientProof())
    }

    @Test func rejectsOutOfRangeServerKey() {
        var session = ApplePasswordsSecretSession(usesBase64: false, usernameBytes: Self.usernameBytes, privateKey: Self.privateKey)
        #expect(throws: ApplePasswordsError.self) { try session.setServer(publicKey: APBigUInt(0), salt: APBigUInt(1)) }
        #expect(throws: ApplePasswordsError.self) { try session.setServer(publicKey: ApplePasswordsSecretSession.prime, salt: APBigUInt(1)) }
    }
}

struct ApplePasswordsNativeMessageTests {
    private func session() -> ApplePasswordsSecretSession {
        ApplePasswordsSecretSession(usesBase64: false, usernameBytes: ApplePasswordsSRPTests.usernameBytes, privateKey: ApplePasswordsSRPTests.privateKey)
    }

    private func pake(_ message: [String: Any]) throws -> String {
        try JSONSerialization.data(withJSONObject: message).base64EncodedString()
    }

    private func decodePAKE(_ message: [String: Any]) throws -> [String: Any] {
        let msg = try #require(message["msg"] as? [String: Any])
        let encoded = try #require(msg["PAKE"] as? String)
        let data = try #require(Data(base64Encoded: encoded))
        let object = try JSONSerialization.jsonObject(with: data)
        return try #require(object as? [String: Any])
    }

    @Test func challengeCarriesTheClientKey() throws {
        let session = session()
        let message = try ApplePasswordsNativeMessage.challenge(session)
        #expect(message["cmd"] as? Int == 2)
        let pake = try decodePAKE(message)
        #expect(pake["TID"] as? String == session.username)
        #expect(pake["MSG"] as? Int == 0)
        #expect(pake["A"] as? String == "0x" + ApplePasswordsSecretSession.hex(session.publicKey.bytes))
        #expect(pake["PROTO"] as? [Int] == [1])
    }

    @Test func fullPairing() throws {
        var session = session()
        let hello: [String: Any] = ["cmd": 2, "payload": ["PAKE": try pake([
            "TID": session.username, "MSG": 1, "PROTO": 1,
            "B": "0x12fc0fa92af955137bfe2084ba325a92be99c636d911c75f072605bbc8a38c88a1ec68650525310a7eb4a91654b2b643324948f9a6f77523c7106a00e743e56913d64c37a0908dedb0170ac251281aadd7f04e1039dad2ad12987dc390a65f807a05dc6d84caef34a2d94954108f112f4bb84b8d3c112ab06de507e8a9073a5c493b30302d233f1f0b71843510940b4ecfc6cd71e2f84bc530cf83330578b52fd01e600c2967fbba7b620b06b6b7ab7c96314aa64f02858b08268dfc57084b878ac5d7e850e700644f72d746381f495f839cea9d80fd58bdc9095da88568d55d81589ba843e5b4c758bb7ea3ee4a25c7ebc6f83493e0d09d0157c312f23a87d9f957d7c8b7cd141409671c39b18302d4391eac4a0dea803a58821bf9625354435dffcff2056fc50aee539338925cbf400bbf455fe7da17bf2a7bd05f7a5daa6add62bc5161395dfce247230410e77e9ad4720d9e9b7e8e04ec699ab3f4259a0779163f5ca40482e126646bbf64ae7ab0998928318d76fc0efc51463b96623629", "s": "0x" + ApplePasswordsSRPTests.salt,
        ])]]
        try ApplePasswordsNativeMessage.readChallenge(hello, into: &session)
        #expect(session.hasChallenge)
        try session.applyPIN("123456")
        let proof = try session.clientProof()
        let verify = try decodePAKE(try ApplePasswordsNativeMessage.verification(session, proof: proof))
        #expect(verify["M"] as? String == "225d3175a4e198ebfa847e063d94ee3513634e23a75b9300f9f306c3153150c3")

        let accepted: [String: Any] = ["cmd": 2, "payload": ["PAKE": try pake([
            "TID": session.username, "MSG": 3, "ErrCode": 0,
            "HAMK": "0x94d34c46e9550e2f93c4a6a9bcafaa388fe65aadfbd7424de28af58e01fe5524",
        ])]]
        try ApplePasswordsNativeMessage.readVerification(accepted, session: session, proof: proof)

        let wrongPIN: [String: Any] = ["cmd": 2, "payload": ["PAKE": try pake(["TID": session.username, "MSG": 3, "ErrCode": 1])]]
        #expect(throws: ApplePasswordsError.self) { try ApplePasswordsNativeMessage.readVerification(wrongPIN, session: session, proof: proof) }

        let forged: [String: Any] = ["cmd": 2, "payload": ["PAKE": try pake([
            "TID": session.username, "MSG": 3, "ErrCode": 0, "HAMK": "0x" + String(repeating: "00", count: 32),
        ])]]
        #expect(throws: ApplePasswordsError.self) { try ApplePasswordsNativeMessage.readVerification(forged, session: session, proof: proof) }
    }

    @Test func encryptedQueryRoundTrip() throws {
        var session = session()
        try session.setServer(publicKey: APBigUInt(hex: "12fc0fa92af955137bfe2084ba325a92be99c636d911c75f072605bbc8a38c88a1ec68650525310a7eb4a91654b2b643324948f9a6f77523c7106a00e743e56913d64c37a0908dedb0170ac251281aadd7f04e1039dad2ad12987dc390a65f807a05dc6d84caef34a2d94954108f112f4bb84b8d3c112ab06de507e8a9073a5c493b30302d233f1f0b71843510940b4ecfc6cd71e2f84bc530cf83330578b52fd01e600c2967fbba7b620b06b6b7ab7c96314aa64f02858b08268dfc57084b878ac5d7e850e700644f72d746381f495f839cea9d80fd58bdc9095da88568d55d81589ba843e5b4c758bb7ea3ee4a25c7ebc6f83493e0d09d0157c312f23a87d9f957d7c8b7cd141409671c39b18302d4391eac4a0dea803a58821bf9625354435dffcff2056fc50aee539338925cbf400bbf455fe7da17bf2a7bd05f7a5daa6add62bc5161395dfce247230410e77e9ad4720d9e9b7e8e04ec699ab3f4259a0779163f5ca40482e126646bbf64ae7ab0998928318d76fc0efc51463b96623629")!, salt: APBigUInt(hex: ApplePasswordsSRPTests.salt)!)
        try session.applyPIN("123456")

        let message = try ApplePasswordsNativeMessage.accounts(session, site: "example.com")
        #expect(message["cmd"] as? Int == 4)
        #expect(message["url"] as? String == "example.com")
        let payload = try #require(message["payload"] as? [String: Any])
        #expect(payload["QID"] as? String == "CmdGetLoginNames4URL")
        let smsg = try #require(ApplePasswordsNativeMessage.object(payload["SMSG"]))
        #expect(smsg["TID"] as? String == session.username)

        let reply: [String: Any] = ["cmd": 4, "payload": ["SMSG": [
            "TID": session.username,
            "SDATA": "0xc8c9cacbcccdcecfd0d1d2d3d4d5d6d717b1f3f6a980f551a496280997c2a83c6180904fcba38dc64311219d8babf3c3791853b547f4bdd024c905338f0336066647ddfcfd127f3a",
        ]]]
        let body = try ApplePasswordsNativeMessage.readQuery(reply, session: session)
        #expect(try ApplePasswordsReply.accounts(from: body).map(\.username) == ["alice"])

        let otherSession: [String: Any] = ["cmd": 4, "payload": ["SMSG": #"{"TID":"0xff","SDATA":"0x00"}"#]]
        #expect(throws: ApplePasswordsError.self) { try ApplePasswordsNativeMessage.readQuery(otherSession, session: session) }
        #expect(try ApplePasswordsNativeMessage.readQuery(["cmd": 6], session: session)["STATUS"] as? Int == 0)
    }

    @Test func saveAndCodesBodies() throws {
        var session = session()
        try session.setServer(publicKey: APBigUInt(hex: "12fc0fa92af955137bfe2084ba325a92be99c636d911c75f072605bbc8a38c88a1ec68650525310a7eb4a91654b2b643324948f9a6f77523c7106a00e743e56913d64c37a0908dedb0170ac251281aadd7f04e1039dad2ad12987dc390a65f807a05dc6d84caef34a2d94954108f112f4bb84b8d3c112ab06de507e8a9073a5c493b30302d233f1f0b71843510940b4ecfc6cd71e2f84bc530cf83330578b52fd01e600c2967fbba7b620b06b6b7ab7c96314aa64f02858b08268dfc57084b878ac5d7e850e700644f72d746381f495f839cea9d80fd58bdc9095da88568d55d81589ba843e5b4c758bb7ea3ee4a25c7ebc6f83493e0d09d0157c312f23a87d9f957d7c8b7cd141409671c39b18302d4391eac4a0dea803a58821bf9625354435dffcff2056fc50aee539338925cbf400bbf455fe7da17bf2a7bd05f7a5daa6add62bc5161395dfce247230410e77e9ad4720d9e9b7e8e04ec699ab3f4259a0779163f5ca40482e126646bbf64ae7ab0998928318d76fc0efc51463b96623629")!, salt: APBigUInt(hex: ApplePasswordsSRPTests.salt)!)
        try session.applyPIN("123456")
        let save = try ApplePasswordsNativeMessage.save(session, site: "example.com", username: "alice", password: "pw")
        #expect(save["cmd"] as? Int == 6)
        #expect(save["url"] == nil)
        let codes = try ApplePasswordsNativeMessage.oneTimeCodes(session, site: "example.com")
        #expect(codes["cmd"] as? Int == 16)
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
