import Foundation

/// Owns Apple's helper process and the pairing with it, and answers the app's requests.
actor BridgeController {
    private var channel: HelperChannel?
    private var session: ApplePasswordsSecretSession?
    private var browser: ChromiumBrowser?
    private var phase: ApplePasswordsBridgeStatus.Phase = .stopped
    private var message: String?
    private var browserCache: (date: Date, browsers: [ChromiumBrowser])?

    func handle(_ request: ApplePasswordsBridgeRequest) async -> ApplePasswordsBridgeResponse {
        do {
            switch request {
            case .status:
                return .status(status())
            case .connect(let browserID):
                try await connect(preferring: browserID)
                return .status(status())
            case .requestPIN:
                try await requestPIN()
                return .done
            case .submitPIN(let pin):
                try await submitPIN(pin)
                return .status(status())
            case .accounts(let site):
                let session = try paired()
                let body = try await query(ApplePasswordsNativeMessage.accounts(session, site: try host(site)), expecting: [4], timeout: .seconds(10))
                return .accounts(try ApplePasswordsReply.accounts(from: body))
            case .password(let site, let username):
                let session = try paired()
                // No timeout: Apple may ask for Touch ID first.
                let body = try await query(ApplePasswordsNativeMessage.password(session, site: try host(site), username: username), expecting: [5], timeout: nil)
                return .accounts(try ApplePasswordsReply.accounts(from: body))
            case .save(let site, let username, let password):
                guard !password.isEmpty else { throw ApplePasswordsError(.invalidParameter, "There's no password to save.") }
                let session = try paired()
                let message = try ApplePasswordsNativeMessage.save(session, site: try host(site), username: username, password: password)
                // macOS asks the user to confirm in its own prompt; the helper's
                // acknowledgement is often empty or late, so a timeout isn't a failure.
                do {
                    let body = try await query(message, expecting: [6, 4], timeout: .seconds(5))
                    try ApplePasswordsReply.status(from: body)
                } catch let error as ApplePasswordsError where error.status == .serverError && error.detail?.contains("in time") == true {}
                return .done
            case .oneTimeCodes(let site):
                let session = try paired()
                let body = try await query(ApplePasswordsNativeMessage.oneTimeCodes(session, site: try host(site)), expecting: [16, 17], timeout: .seconds(10))
                return .codes(try ApplePasswordsReply.codes(from: body))
            case .disconnect:
                stop()
                return .status(status())
            }
        } catch {
            return .failure(error.localizedDescription)
        }
    }

    func stop() {
        if let channel {
            channel.post(ApplePasswordsNativeMessage.end())
            channel.close()
        }
        channel = nil
        session = nil
        browser = nil
        phase = .stopped
        message = nil
    }

    // MARK: - Helper lifecycle

    private func connect(preferring browserID: String?) async throws {
        if let channel, channel.isOpen, browserID == nil || browserID == browser?.id {
            return
        }
        stop()

        let browsers = installedBrowsers(refresh: true)
        guard let chosen = browsers.first(where: { $0.id == browserID }) ?? browsers.first else {
            fail("Install Google Chrome, Microsoft Edge, Brave or another Chromium browser. Vaultwarden starts it hidden for a moment to reach Apple Passwords.")
            throw ApplePasswordsError(.genericError, message)
        }

        phase = .starting
        message = nil
        do {
            let helper = try await Task.detached { try HelperLauncher.launch(through: chosen) }.value
            let channel = HelperChannel(writeFD: helper.writeFD, readFD: helper.readFD)
            channel.onEvent = { [weak self] command in
                Task { await self?.helperEvent(command) }
            }
            self.channel = channel
            browser = chosen

            let reply = try await channel.request(ApplePasswordsNativeMessage.capabilities(), expecting: [14], timeout: .seconds(25))
            let capabilities = reply["capabilities"] as? [String: Any] ?? [:]
            if let version = capabilities["secretSessionVersion"] as? Int, version != 1 {
                throw ApplePasswordsError(.genericError, "This version of Apple Passwords pairs in a way Vaultwarden doesn't support yet.")
            }
            let usesBase64 = (capabilities["shouldUseBase64"] as? Bool) ?? false
            session = await Task.detached { ApplePasswordsSecretSession(usesBase64: usesBase64) }.value
            phase = .needsPairing
        } catch {
            stop()
            fail(error.localizedDescription)
            throw error
        }
    }

    private func helperEvent(_ command: Int?) {
        guard let command else {
            // The helper exited, which ends the pairing.
            guard channel != nil else { return }
            channel = nil
            session = nil
            fail("Apple's Passwords helper stopped. Connect again.")
            return
        }
        if command == ApplePasswordsCommand.passwordsDisabled.rawValue || command == ApplePasswordsCommand.reloginNeeded.rawValue {
            session?.resetHandshake()
            phase = .needsPairing
        }
    }

    // MARK: - Pairing

    private func requestPIN() async throws {
        guard let channel, channel.isOpen, var session else {
            throw ApplePasswordsError(.invalidSession, "Apple Passwords isn't connected. Connect again.")
        }
        session.resetHandshake()
        let reply = try await channel.request(try ApplePasswordsNativeMessage.challenge(session), expecting: [2], timeout: .seconds(15))
        try ApplePasswordsNativeMessage.readChallenge(reply, into: &session)
        self.session = session
        phase = .needsPairing
    }

    private func submitPIN(_ pin: String) async throws {
        let digits = pin.filter(\.isNumber)
        guard !digits.isEmpty else { throw ApplePasswordsError(.invalidParameter, "Enter the PIN shown on this Mac.") }
        guard let channel, channel.isOpen, var session else {
            throw ApplePasswordsError(.invalidSession, "Apple Passwords isn't connected. Connect again.")
        }
        guard session.hasChallenge else {
            throw ApplePasswordsError(.invalidSession, "That PIN has expired. Show a new PIN and try again.")
        }
        do {
            // The 3072-bit arithmetic takes a moment; keep it off the actor.
            let challenged = session
            session = try await Task.detached { () throws -> ApplePasswordsSecretSession in
                var copy = challenged
                try copy.applyPIN(digits)
                return copy
            }.value
            let proof = try session.clientProof()
            let reply = try await channel.request(try ApplePasswordsNativeMessage.verification(session, proof: proof), expecting: [2], timeout: .seconds(15))
            try ApplePasswordsNativeMessage.readVerification(reply, session: session, proof: proof)
            self.session = session
            phase = .ready
            message = nil
        } catch {
            // A failed attempt spends the challenge; the next try needs a new PIN.
            session.resetHandshake()
            self.session = session
            phase = .needsPairing
            throw error
        }
    }

    // MARK: - Queries

    private func paired() throws -> ApplePasswordsSecretSession {
        guard let channel, channel.isOpen, let session, session.isPaired, phase == .ready else {
            throw ApplePasswordsError(.invalidSession, "Apple Passwords isn't paired. Pair again with a new PIN.")
        }
        return session
    }

    private func query(_ message: [String: Any], expecting commands: Set<Int>, timeout: Duration?) async throws -> [String: Any] {
        guard let channel, let session else { throw ApplePasswordsError(.invalidSession) }
        let reply = try await channel.request(message, expecting: commands, timeout: timeout)
        let body = try ApplePasswordsNativeMessage.readQuery(reply, session: session)
        if body["STATUS"] as? Int == ApplePasswordsStatusCode.invalidSession.rawValue {
            self.session?.resetHandshake()
            phase = .needsPairing
        }
        return body
    }

    // MARK: - Status

    private func status() -> ApplePasswordsBridgeStatus {
        if channel?.isOpen == false {
            channel = nil
            session = nil
            if phase != .failed { fail("Apple's Passwords helper stopped. Connect again.") }
        }
        return ApplePasswordsBridgeStatus(
            phase: phase,
            browsers: installedBrowsers(refresh: false).map(\.summary),
            activeBrowserID: channel == nil ? nil : browser?.id,
            message: message
        )
    }

    private func installedBrowsers(refresh: Bool) -> [ChromiumBrowser] {
        if !refresh, let browserCache, Date().timeIntervalSince(browserCache.date) < 60 {
            return browserCache.browsers
        }
        let browsers = ChromiumBrowser.installed()
        browserCache = (Date(), browsers)
        return browsers
    }

    private func fail(_ text: String) {
        phase = .failed
        message = text
    }

    private func host(_ site: String) throws -> String {
        guard let host = ApplePasswordsSite.host(site) else {
            throw ApplePasswordsError(.invalidParameter, "Enter a website, like example.com.")
        }
        return host
    }
}
