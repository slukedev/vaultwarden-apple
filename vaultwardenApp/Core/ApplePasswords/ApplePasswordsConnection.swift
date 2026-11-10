#if os(macOS)
import Combine
import Foundation
import ServiceManagement

/// The app's side of the Apple Passwords connection: registers the bundled agent with
/// launchd and talks to it over XPC. Mac only; iOS has no Apple Passwords helper.
@MainActor
final class ApplePasswordsConnection: ObservableObject {
    static let shared = ApplePasswordsConnection()

    enum AgentState: Equatable {
        case off
        /// Registered but waiting for the user in System Settings ▸ General ▸ Login Items.
        case requiresApproval
        case on
        case unavailable(String)
    }

    @Published private(set) var agentState: AgentState = .off
    @Published private(set) var status: ApplePasswordsBridgeStatus?
    @Published private(set) var isWorking = false

    static let preferredBrowserKey = "applePasswords.browser"

    var preferredBrowserID: String? {
        get { UserDefaults.standard.string(forKey: Self.preferredBrowserKey) }
        set { UserDefaults.standard.set(newValue, forKey: Self.preferredBrowserKey) }
    }

    var isReady: Bool { agentState == .on && status?.phase == .ready }

    private let service = SMAppService.agent(plistName: ApplePasswordsBridgeIdentity.launchAgentPlistName)
    private var connection: NSXPCConnection?

    private init() {
        refreshAgentState()
    }

    // MARK: - Agent

    func refreshAgentState() {
        switch service.status {
        case .enabled: agentState = .on
        case .requiresApproval: agentState = .requiresApproval
        case .notRegistered: agentState = .off
        case .notFound: agentState = .unavailable(L10n.string("This copy of Vaultwarden doesn't include the Apple Passwords agent."))
        @unknown default: agentState = .off
        }
    }

    func turnOn() {
        do {
            try service.register()
        } catch {
            refreshAgentState()
            if agentState != .requiresApproval {
                agentState = .unavailable(error.localizedDescription)
            }
            return
        }
        refreshAgentState()
    }

    func turnOff() async {
        if agentState == .on {
            _ = try? await perform(.disconnect)
        }
        connection?.invalidate()
        connection = nil
        status = nil
        try? await service.unregister()
        refreshAgentState()
    }

    func openLoginItemsSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    // MARK: - Session

    func refreshStatus() async {
        refreshAgentState()
        guard agentState == .on else { status = nil; return }
        if case .status(let value) = try? await perform(.status) {
            status = value
        }
    }

    /// Starts Apple's helper if needed. Throws with the agent's explanation on failure.
    func connect() async throws {
        let response = try await working { try await self.perform(.connect(browserID: self.preferredBrowserID)) }
        if case .status(let value) = response { status = value }
        if status?.phase == .failed, let message = status?.message {
            throw ApplePasswordsError(.genericError, message)
        }
    }

    func requestPIN() async throws {
        if status?.phase != .needsPairing && status?.phase != .ready {
            try await connect()
        }
        _ = try await working { try await self.perform(.requestPIN) }
    }

    /// Returns whether pairing finished.
    func submitPIN(_ pin: String) async throws -> Bool {
        let response = try await working { try await self.perform(.submitPIN(pin)) }
        if case .status(let value) = response { status = value }
        return status?.phase == .ready
    }

    func disconnectBrowser() async {
        if case .status(let value) = try? await perform(.disconnect) { status = value }
    }

    // MARK: - Apple Passwords

    /// Accounts saved for a site, without passwords.
    func accounts(for site: String) async throws -> [ApplePasswordsAccount] {
        try await requireReady()
        guard case .accounts(let accounts) = try await perform(.accounts(site: site)) else { return [] }
        return accounts
    }

    /// The password for one account. Apple may ask to authenticate on this Mac first.
    func password(for site: String, username: String) async throws -> String {
        try await requireReady()
        guard case .accounts(let accounts) = try await perform(.password(site: site, username: username)),
              let password = (accounts.first { $0.username == username } ?? accounts.first)?.password else {
            throw ApplePasswordsError(.noResults, L10n.string("Apple Passwords didn't return a password for that account."))
        }
        return password
    }

    func save(site: String, username: String, password: String) async throws {
        try await requireReady()
        _ = try await perform(.save(site: site, username: username, password: password))
    }

    func oneTimeCodes(for site: String) async throws -> [ApplePasswordsCode] {
        try await requireReady()
        guard case .codes(let codes) = try await perform(.oneTimeCodes(site: site)) else { return [] }
        return codes
    }

    // MARK: - XPC

    private func requireReady() async throws {
        guard agentState == .on else {
            throw ApplePasswordsError(.invalidSession, L10n.string("Turn on Apple Passwords in Settings first."))
        }
        if status == nil { await refreshStatus() }
        guard status?.phase == .ready else {
            throw ApplePasswordsError(.invalidSession, L10n.string("Pair with Apple Passwords in Settings first."))
        }
    }

    private func working<T>(_ body: () async throws -> T) async throws -> T {
        isWorking = true
        defer { isWorking = false }
        return try await body()
    }

    private func perform(_ request: ApplePasswordsBridgeRequest) async throws -> ApplePasswordsBridgeResponse {
        let payload = try JSONEncoder().encode(request)
        let connection = currentConnection()
        let data: Data = try await withCheckedThrowingContinuation { continuation in
            let once = ResumeOnce(continuation)
            let proxy = connection.remoteObjectProxyWithErrorHandler { error in
                once.resume(throwing: ApplePasswordsError(.serverError, L10n.string("Couldn't reach the Apple Passwords agent: ") + error.localizedDescription))
            }
            guard let bridge = proxy as? ApplePasswordsBridgeXPC else {
                once.resume(throwing: ApplePasswordsError(.serverError))
                return
            }
            bridge.perform(payload) { once.resume(returning: $0) }
        }
        let response = try JSONDecoder().decode(ApplePasswordsBridgeResponse.self, from: data)
        if case .failure(let message) = response {
            throw ApplePasswordsError(.genericError, message)
        }
        return response
    }

    private func currentConnection() -> NSXPCConnection {
        if let connection { return connection }
        let connection = NSXPCConnection(machServiceName: ApplePasswordsBridgeIdentity.machServiceName, options: [])
        connection.remoteObjectInterface = NSXPCInterface(with: ApplePasswordsBridgeXPC.self)
        connection.setCodeSigningRequirement(
            ApplePasswordsBridgeIdentity.codeRequirement(forIdentifier: ApplePasswordsBridgeIdentity.bridgeIdentifier)
        )
        connection.invalidationHandler = { [weak self] in
            Task { @MainActor in
                self?.connection = nil
                self?.status = nil
            }
        }
        connection.interruptionHandler = { [weak self] in
            // The agent restarted, which took Apple's helper and the pairing with it.
            Task { @MainActor in self?.status = nil }
        }
        connection.resume()
        self.connection = connection
        return connection
    }
}

/// XPC can call both the error handler and the reply; only the first one counts.
private nonisolated final class ResumeOnce<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, Error>?

    init(_ continuation: CheckedContinuation<T, Error>) {
        self.continuation = continuation
    }

    func resume(returning value: T) {
        take()?.resume(returning: value)
    }

    func resume(throwing error: Error) {
        take()?.resume(throwing: error)
    }

    private func take() -> CheckedContinuation<T, Error>? {
        lock.withLock {
            defer { continuation = nil }
            return continuation
        }
    }
}
#endif
