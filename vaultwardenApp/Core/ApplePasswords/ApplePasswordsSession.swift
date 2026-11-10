import CryptoKit
import Foundation

// The protocol Apple's PasswordManagerBrowserExtensionHelper speaks over native
// messaging: an SRP-6a pairing (RFC 5054, 3072-bit group, SHA-256) whose password is the
// PIN macOS shows, then AES-GCM messages keyed by the first 16 bytes of the shared key.
// Message shapes follow the public reverse-engineering in au2001/icloud-passwords-firefox
// (Apache-2.0), bendews/apw (GPL-3.0) and araeyn/apple-passwords-bridge.

/// One pairing with the helper. The key exists only in this process's memory; the
/// helper forgets it when it exits, so every new helper process pairs again.
nonisolated struct ApplePasswordsSecretSession: Sendable {
    static let prime = APBigUInt(hex: """
        FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD\
        EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
        EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
        83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
        E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
        15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
        ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
        BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
        """)!
    static let generator = APBigUInt(5)
    static let primeByteCount = 384
    static let group = APMontgomery(modulus: prime)

    let usesBase64: Bool
    /// The session identifier (TID) in its wire form.
    let username: String
    private let privateKey: APBigUInt
    /// A = g^a mod N.
    let publicKey: APBigUInt
    private(set) var serverPublicKey: APBigUInt?
    private(set) var salt: APBigUInt?
    /// K = H(S), set once the PIN has been applied.
    private(set) var sharedKey: APBigUInt?

    /// Fixed `usernameBytes` and `privateKey` are for tests only.
    init(usesBase64: Bool, usernameBytes: [UInt8]? = nil, privateKey: [UInt8]? = nil) {
        self.usesBase64 = usesBase64
        let identifier = usernameBytes ?? Self.randomBytes(16)
        username = usesBase64 ? Data(identifier).base64EncodedString() : "0x" + Self.hex(identifier)
        self.privateKey = APBigUInt(bytes: privateKey ?? Self.randomBytes(32))
        publicKey = Self.group.power(Self.generator, self.privateKey)
    }

    var hasChallenge: Bool { serverPublicKey != nil && salt != nil }
    var isPaired: Bool { sharedKey != nil }

    // MARK: - Wire encoding

    func serialize(_ bytes: [UInt8], prefix: Bool = true) -> String {
        usesBase64 ? Data(bytes).base64EncodedString() : (prefix ? "0x" : "") + Self.hex(bytes)
    }

    func deserialize(_ text: String) throws -> [UInt8] {
        if usesBase64 {
            guard let data = Data(base64Encoded: text) else { throw ApplePasswordsError(.serverError, "Apple Passwords sent malformed data.") }
            return [UInt8](data)
        }
        guard let value = APBigUInt(hex: text) else { throw ApplePasswordsError(.serverError, "Apple Passwords sent malformed data.") }
        // Keep leading zero bytes the helper sent.
        let digits = (text.hasPrefix("0x") ? text.count - 2 : text.count)
        return value.paddedBytes((digits + 1) / 2)
    }

    // MARK: - Handshake

    mutating func resetHandshake() {
        serverPublicKey = nil
        salt = nil
        sharedKey = nil
    }

    mutating func setServer(publicKey: APBigUInt, salt: APBigUInt) throws {
        // RFC 5054: B must be in (0, N).
        guard !publicKey.isZero, publicKey < Self.prime else {
            throw ApplePasswordsError(.serverError, "Apple Passwords sent an invalid key.")
        }
        serverPublicKey = publicKey
        self.salt = salt
        sharedKey = nil
    }

    /// Derives K from the PIN: S = (B - k·g^x)^(a + u·x) mod N.
    mutating func applyPIN(_ pin: String) throws {
        guard let serverPublicKey, let salt else {
            throw ApplePasswordsError(.invalidSession, "Ask for a new PIN first.")
        }
        let n = Self.primeByteCount
        let u = APBigUInt(bytes: Self.sha256(publicKey.paddedBytes(n), serverPublicKey.paddedBytes(n)))
        guard !u.isZero else { throw ApplePasswordsError(.serverError, "Apple Passwords sent an invalid key.") }
        let k = APBigUInt(bytes: Self.sha256(Self.prime.bytes, Self.generator.paddedBytes(n)))
        let inner = Self.sha256(Array("\(username):\(pin)".utf8))
        let x = APBigUInt(bytes: Self.sha256(salt.bytes, inner))

        let group = Self.group
        let kv = group.multiplyModulo(k, group.power(Self.generator, x))
        let base = group.subtractModulo(serverPublicKey, kv)
        let secret = group.power(base, privateKey + u * x)
        sharedKey = APBigUInt(bytes: Self.sha256(secret.bytes))
    }

    /// M = H(H(N) xor H(g) | H(I) | s | A | B | K).
    func clientProof() throws -> [UInt8] {
        guard let serverPublicKey, let salt, let sharedKey else {
            throw ApplePasswordsError(.invalidSession, "Enter the PIN first.")
        }
        let hN = Self.sha256(Self.prime.bytes)
        let hg = Self.sha256(Self.generator.paddedBytes(Self.primeByteCount))
        let xored = zip(hN, hg).map { $0 ^ $1 }
        return Self.sha256(
            xored,
            Self.sha256(Array(username.utf8)),
            salt.bytes,
            publicKey.bytes,
            serverPublicKey.bytes,
            sharedKey.bytes
        )
    }

    /// HAMK = H(A | M | K), what the helper must send back.
    func expectedServerProof(for proof: [UInt8]) throws -> [UInt8] {
        guard let sharedKey else { throw ApplePasswordsError(.invalidSession, "Enter the PIN first.") }
        return Self.sha256(publicKey.bytes, proof, sharedKey.bytes)
    }

    // MARK: - Messages

    private var encryptionKey: SymmetricKey {
        get throws {
            guard let sharedKey else { throw ApplePasswordsError(.invalidSession) }
            return SymmetricKey(data: Data(sharedKey.paddedBytes(32).prefix(16)))
        }
    }

    /// Outgoing: ciphertext | tag | IV (the helper reads the IV from the end).
    func encrypt(_ plaintext: Data, iv: [UInt8]? = nil) throws -> [UInt8] {
        let ivBytes = iv ?? Self.randomBytes(16)
        let nonce = try AES.GCM.Nonce(data: Data(ivBytes))
        let box = try AES.GCM.seal(plaintext, using: try encryptionKey, nonce: nonce)
        return [UInt8](box.ciphertext) + [UInt8](box.tag) + ivBytes
    }

    /// Incoming: IV | ciphertext | tag.
    func decrypt(_ data: [UInt8]) throws -> Data {
        guard data.count >= 32 else { throw ApplePasswordsError(.serverError, "Apple Passwords sent a short message.") }
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: Data(data.prefix(16))),
            ciphertext: Data(data.dropFirst(16).dropLast(16)),
            tag: Data(data.suffix(16))
        )
        return try AES.GCM.open(box, using: try encryptionKey)
    }

    // MARK: - Helpers

    static func sha256(_ parts: [UInt8]...) -> [UInt8] {
        var hasher = SHA256()
        for part in parts { hasher.update(data: part) }
        return [UInt8](hasher.finalize())
    }

    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    static func randomBytes(_ count: Int) -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        return (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
    }

    static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        return zip(a, b).reduce(0) { $0 | ($1.0 ^ $1.1) } == 0
    }
}

/// Builds the helper's native-messaging messages and reads its replies.
nonisolated enum ApplePasswordsNativeMessage {
    static let browserName = "Chrome"
    static let protocolVersion = "1.0"

    static func capabilities() -> [String: Any] { ["cmd": ApplePasswordsCommand.getCapabilities.rawValue] }
    static func end() -> [String: Any] { ["cmd": ApplePasswordsCommand.end.rawValue] }

    /// Asks for a challenge; macOS shows the PIN.
    static func challenge(_ session: ApplePasswordsSecretSession) throws -> [String: Any] {
        let pake: [String: Any] = [
            "TID": session.username,
            "MSG": 0,
            "A": session.serialize(session.publicKey.bytes),
            "VER": protocolVersion,
            "PROTO": [1],
        ]
        return ["cmd": ApplePasswordsCommand.handshake.rawValue,
                "msg": ["QID": "m0", "PAKE": try base64JSON(pake), "HSTBRSR": browserName]]
    }

    static func verification(_ session: ApplePasswordsSecretSession, proof: [UInt8]) throws -> [String: Any] {
        let pake: [String: Any] = [
            "TID": session.username,
            "MSG": 2,
            "M": session.serialize(proof, prefix: false),
        ]
        return ["cmd": ApplePasswordsCommand.handshake.rawValue,
                "msg": ["QID": "m2", "PAKE": try base64JSON(pake), "HSTBRSR": browserName]]
    }

    /// Reads the server hello into the session.
    static func readChallenge(_ reply: [String: Any], into session: inout ApplePasswordsSecretSession) throws {
        let pake = try readPAKE(reply, session: session)
        if let code = pake["ErrCode"], !(code is NSNull) {
            throw ApplePasswordsError(.serverError, "Apple Passwords refused to pair (error \(code)).")
        }
        guard "\(pake["MSG"] ?? "")" == "1" else { throw ApplePasswordsError(.serverError, "Unexpected pairing reply.") }
        if let proto = pake["PROTO"], "\(proto)" != "1" {
            throw ApplePasswordsError(.serverError, "This version of Apple Passwords pairs differently.")
        }
        guard let b = pake["B"] as? String, let s = pake["s"] as? String else {
            throw ApplePasswordsError(.serverError, "Unexpected pairing reply.")
        }
        try session.setServer(publicKey: APBigUInt(bytes: session.deserialize(b)), salt: APBigUInt(bytes: session.deserialize(s)))
    }

    /// Checks the helper's answer to the PIN proof.
    static func readVerification(_ reply: [String: Any], session: ApplePasswordsSecretSession, proof: [UInt8]) throws {
        let pake = try readPAKE(reply, session: session)
        guard "\(pake["MSG"] ?? "")" == "3" else { throw ApplePasswordsError(.serverError, "Unexpected pairing reply.") }
        let code = (pake["ErrCode"] as? Int) ?? Int("\(pake["ErrCode"] ?? "0")") ?? 0
        if code == 1 { throw ApplePasswordsError(.invalidSession, "That PIN didn't work. Ask for a new one and try again.") }
        guard code == 0 else { throw ApplePasswordsError(.serverError, "Apple Passwords refused to pair (error \(code)).") }
        guard let hamk = pake["HAMK"] as? String,
              ApplePasswordsSecretSession.constantTimeEqual(try session.deserialize(hamk), try session.expectedServerProof(for: proof)) else {
            throw ApplePasswordsError(.serverError, "Apple Passwords couldn't be verified. Pair again.")
        }
    }

    /// An encrypted request: `{cmd, tabId, frameId, url?, payload: {QID, SMSG: "{TID, SDATA}"}}`.
    static func query(
        _ session: ApplePasswordsSecretSession,
        command: ApplePasswordsCommand,
        qid: String,
        url: String?,
        body: [String: Any],
        iv: [UInt8]? = nil
    ) throws -> [String: Any] {
        let plaintext = try JSONSerialization.data(withJSONObject: body)
        let smsg: [String: Any] = ["TID": session.username, "SDATA": session.serialize(try session.encrypt(plaintext, iv: iv))]
        let smsgText = String(decoding: try JSONSerialization.data(withJSONObject: smsg), as: UTF8.self)
        var message: [String: Any] = [
            "cmd": command.rawValue,
            "tabId": 0,
            "frameId": 0,
            "payload": ["QID": qid, "SMSG": smsgText],
        ]
        if let url { message["url"] = url }
        return message
    }

    /// The decrypted body of a reply to `query`, or `{STATUS: 0}` for an empty acknowledgement.
    static func readQuery(_ reply: [String: Any], session: ApplePasswordsSecretSession) throws -> [String: Any] {
        guard let payload = object(reply["payload"]) else {
            return ["STATUS": (reply["STATUS"] as? Int) ?? 0]
        }
        guard let smsg = object(payload["SMSG"]) else { throw ApplePasswordsError(.serverError) }
        guard smsg["TID"] as? String == session.username else {
            throw ApplePasswordsError(.serverError, "Apple Passwords answered a different session.")
        }
        guard let sdata = smsg["SDATA"] as? String else { throw ApplePasswordsError(.serverError) }
        let plaintext = try session.decrypt(try session.deserialize(sdata))
        guard let body = (try? JSONSerialization.jsonObject(with: plaintext)) as? [String: Any] else {
            throw ApplePasswordsError(.serverError)
        }
        return body
    }

    // Request bodies.

    static func accounts(_ session: ApplePasswordsSecretSession, site: String) throws -> [String: Any] {
        try query(session, command: .getLoginNamesForURL, qid: "CmdGetLoginNames4URL", url: site,
                  body: ["ACT": ApplePasswordsAction.ghostSearch.rawValue, "URL": site])
    }

    static func password(_ session: ApplePasswordsSecretSession, site: String, username: String) throws -> [String: Any] {
        try query(session, command: .getPasswordForLoginName, qid: "CmdGetPassword4LoginName", url: site,
                  body: ["ACT": ApplePasswordsAction.search.rawValue, "URL": site, "USR": username])
    }

    static func save(_ session: ApplePasswordsSecretSession, site: String, username: String, password: String) throws -> [String: Any] {
        try query(session, command: .setPasswordForLoginNameAndURL, qid: "CmdNewAccount4URL", url: nil,
                  body: ["ACT": ApplePasswordsAction.maybeAdd.rawValue, "URL": "", "USR": "", "PWD": "",
                         "NURL": site, "NUSR": username, "NPWD": password])
    }

    static func oneTimeCodes(_ session: ApplePasswordsSecretSession, site: String) throws -> [String: Any] {
        try query(session, command: .getOneTimeCodes, qid: "CmdDidFillOneTimeCode", url: nil,
                  body: ["ACT": ApplePasswordsAction.ghostSearch.rawValue, "TYPE": "oneTimeCodes",
                         "frameURLs": [ApplePasswordsSite.frameURL(site)]])
    }

    // MARK: - Helpers

    private static func readPAKE(_ reply: [String: Any], session: ApplePasswordsSecretSession) throws -> [String: Any] {
        guard let payload = object(reply["payload"]), let encoded = payload["PAKE"] as? String,
              let data = Data(base64Encoded: encoded),
              let pake = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw ApplePasswordsError(.serverError, "Unexpected pairing reply.")
        }
        guard pake["TID"] as? String == session.username else {
            throw ApplePasswordsError(.serverError, "Apple Passwords answered a different session.")
        }
        return pake
    }

    /// A JSON object that may arrive as an object or as a JSON string.
    static func object(_ value: Any?) -> [String: Any]? {
        if let object = value as? [String: Any] { return object }
        if let text = value as? String, let data = text.data(using: .utf8) {
            return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        }
        return nil
    }

    private static func base64JSON(_ object: [String: Any]) throws -> String {
        try JSONSerialization.data(withJSONObject: object).base64EncodedString()
    }
}
