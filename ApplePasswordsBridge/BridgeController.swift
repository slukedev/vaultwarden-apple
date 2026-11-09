import Foundation

/// Owns the browser session and answers the app's requests in order.
actor BridgeController {
    private var session: BrowserSession?
    private var phase: ApplePasswordsBridgeStatus.Phase = .stopped
    private var message: String?

    func handle(_ request: ApplePasswordsBridgeRequest) async -> ApplePasswordsBridgeResponse {
        do {
            switch request {
            case .status:
                return .status(await status())
            case .connect(let browserID):
                try await connect(preferring: browserID)
                return .status(await status())
            case .requestPIN:
                _ = try await running().link.send(ApplePasswordsExtensionMessage.challenge())
                return .done
            case .submitPIN(let pin):
                let digits = pin.filter(\.isNumber)
                guard !digits.isEmpty else { throw ApplePasswordsError(.invalidParameter, "Enter the PIN shown on this Mac.") }
                _ = try await running().link.send(ApplePasswordsExtensionMessage.verify(pin: digits))
                // The extension finishes the exchange with the helper on its own.
                for _ in 0..<20 {
                    if try await isPaired() { break }
                    try await Task.sleep(for: .milliseconds(250))
                }
                return .status(await status())
            case .accounts(let site):
                let data = try await query(ApplePasswordsExtensionMessage.accounts(site: try host(site)))
                return .accounts(try ApplePasswordsReply.accounts(from: data))
            case .password(let site, let username):
                let data = try await query(ApplePasswordsExtensionMessage.password(site: try host(site), username: username))
                return .accounts(try ApplePasswordsReply.accounts(from: data))
            case .save(let site, let username, let password):
                guard !password.isEmpty else { throw ApplePasswordsError(.invalidParameter, "There's no password to save.") }
                let data = try await query(ApplePasswordsExtensionMessage.save(site: try host(site), username: username, password: password))
                try ApplePasswordsReply.status(from: data)
                return .done
            case .oneTimeCodes(let site):
                let data = try await query(ApplePasswordsExtensionMessage.oneTimeCodes(site: try host(site)))
                return .codes(try ApplePasswordsReply.codes(from: data))
            case .disconnect:
                stop()
                return .status(await status())
            }
        } catch {
            return .failure(error.localizedDescription)
        }
    }

    func stop() {
        session?.stop()
        session = nil
        phase = .stopped
        message = nil
    }

    // MARK: - Browser

    private func connect(preferring browserID: String?) async throws {
        if let session, session.isRunning, browserID == nil || session.browser.id == browserID {
            return
        }
        stop()

        let installed = ChromiumBrowser.installed()
        guard !installed.isEmpty else {
            fail("Install Google Chrome, Microsoft Edge, Brave or Chromium, then add the iCloud Passwords extension to it.")
            throw ApplePasswordsError(.genericError, message)
        }
        let usable = installed.filter { $0.extensionSource != nil }
        guard let browser = usable.first(where: { $0.id == browserID }) ?? usable.first else {
            fail("Add the iCloud Passwords extension to \(installed.map(\.name).formatted(.list(type: .or))), then try again.")
            throw ApplePasswordsError(.genericError, message)
        }

        phase = .starting
        message = nil
        do {
            let session = try await BrowserSession.launch(browser)
            self.session = session
            guard await session.link.waitForConnection(timeout: .seconds(20)) else {
                stop()
                fail("The iCloud Passwords extension didn't start in \(browser.name). Open \(browser.name) once, make sure the extension is turned on, then try again.")
                throw ApplePasswordsError(.genericError, message)
            }
            phase = try await isPaired() ? .ready : .needsPairing
        } catch {
            if phase != .failed { fail(error.localizedDescription) }
            throw error
        }
    }

    private func running() throws -> BrowserSession {
        guard let session, session.isRunning, session.link.isConnected else {
            throw ApplePasswordsError(.invalidSession, "Apple Passwords isn't connected. Connect again in Settings.")
        }
        return session
    }

    private func isPaired() async throws -> Bool {
        let reply = try await running().link.send(ApplePasswordsExtensionMessage.state())
        let data = try ApplePasswordsReply.data(from: reply)
        return data["paired"] as? Bool ?? false
    }

    private func query(_ message: [String: Any]) async throws -> [String: Any] {
        let reply = try await running().link.send(message)
        do {
            return try ApplePasswordsReply.data(from: reply)
        } catch let error as ApplePasswordsError where error.status == .invalidSession {
            phase = .needsPairing
            throw error
        }
    }

    private func status() async -> ApplePasswordsBridgeStatus {
        if let session {
            if !session.isRunning {
                self.session = nil
                fail("\(session.browser.name) quit. Connect again.")
            } else if phase == .needsPairing || phase == .ready, session.link.isConnected {
                phase = ((try? await isPaired()) ?? false) ? .ready : .needsPairing
            }
        }
        return ApplePasswordsBridgeStatus(
            phase: phase,
            browsers: ChromiumBrowser.summaries(),
            activeBrowserID: session?.browser.id,
            message: message
        )
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
