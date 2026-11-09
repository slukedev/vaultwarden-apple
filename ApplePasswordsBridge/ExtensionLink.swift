import Foundation
import Network

/// A WebSocket server on 127.0.0.1 that the bridge script inside the extension connects
/// to. The first message must carry the random token written into that script; any
/// other client is closed. One request is in flight at a time, as the script expects.
nonisolated final class ExtensionLink: @unchecked Sendable {
    let token = UUID().uuidString + UUID().uuidString
    private let queue = DispatchQueue(label: "xyz.0xmwehehe.vaultwardenApp.ApplePasswordsBridge.link")
    private var listener: NWListener?
    private var client: NWConnection?
    private var pending: (id: String, continuation: CheckedContinuation<[String: Any], Error>)?
    private var busy = false
    private var turnWaiters: [CheckedContinuation<Void, Never>] = []

    var isConnected: Bool { queue.sync { client != nil } }

    /// Starts listening and returns the port the script should use.
    func start() async throws -> UInt16 {
        let parameters = NWParameters.tcp
        let webSocket = NWProtocolWebSocket.Options()
        webSocket.autoReplyPing = true
        parameters.defaultProtocolStack.applicationProtocols.insert(webSocket, at: 0)
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        let listener = try NWListener(using: parameters)
        self.listener = listener

        listener.newConnectionHandler = { [weak self] connection in
            self?.accept(connection)
        }

        return try await withCheckedThrowingContinuation { continuation in
            var resumed = false
            listener.stateUpdateHandler = { state in
                guard !resumed else { return }
                switch state {
                case .ready:
                    resumed = true
                    continuation.resume(returning: listener.port?.rawValue ?? 0)
                case .failed(let error):
                    resumed = true
                    continuation.resume(throwing: error)
                default:
                    break
                }
            }
            listener.start(queue: queue)
        }
    }

    func stop() {
        queue.sync {
            listener?.cancel()
            listener = nil
            client?.cancel()
            client = nil
            pending?.continuation.resume(throwing: ApplePasswordsError(.serverError, "The browser stopped."))
            pending = nil
        }
    }

    /// Waits until the script connects, or the timeout passes.
    func waitForConnection(timeout: Duration) async -> Bool {
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline {
            if isConnected { return true }
            try? await Task.sleep(for: .milliseconds(200))
        }
        return isConnected
    }

    /// Sends one message to the script and waits for its answer.
    func send(_ message: [String: Any], timeout: Duration = .seconds(30)) async throws -> [String: Any] {
        await takeTurn()
        defer { releaseTurn() }

        let id = UUID().uuidString
        var outgoing = message
        outgoing["id"] = id
        let data = try JSONSerialization.data(withJSONObject: outgoing)

        let timeoutTask = Task { [weak self] in
            try? await Task.sleep(for: timeout)
            guard !Task.isCancelled else { return }
            self?.finish(id: id, with: .failure(ApplePasswordsError(.serverError, "The iCloud Passwords extension didn't answer in time.")))
        }
        defer { timeoutTask.cancel() }

        return try await withCheckedThrowingContinuation { continuation in
            queue.async {
                guard let client = self.client else {
                    continuation.resume(throwing: ApplePasswordsError(.invalidSession, "The iCloud Passwords extension isn't connected."))
                    return
                }
                self.pending = (id, continuation)
                let metadata = NWProtocolWebSocket.Metadata(opcode: .text)
                let context = NWConnection.ContentContext(identifier: "message", metadata: [metadata])
                client.send(content: data, contentContext: context, isComplete: true, completion: .contentProcessed { error in
                    if let error { self.finish(id: id, with: .failure(error)) }
                })
            }
        }
    }

    // MARK: - Connections

    private func accept(_ connection: NWConnection) {
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let self, let connection else { return }
            switch state {
            case .failed, .cancelled:
                if self.client === connection {
                    self.client = nil
                    self.pending?.continuation.resume(throwing: ApplePasswordsError(.serverError, "The iCloud Passwords extension disconnected."))
                    self.pending = nil
                }
            default:
                break
            }
        }
        connection.start(queue: queue)
        receive(on: connection, authenticated: false)
    }

    private func receive(on connection: NWConnection, authenticated: Bool) {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if error != nil {
                connection.cancel()
                return
            }
            guard let data, let message = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
                connection.cancel()
                return
            }

            if !authenticated {
                guard self.client == nil, let token = message["token"] as? String, Self.constantTimeEqual(token, self.token) else {
                    connection.cancel()
                    return
                }
                self.client = connection
                self.receive(on: connection, authenticated: true)
                return
            }

            if let id = message["id"] as? String {
                self.finishOnQueue(id: id, with: .success(message))
            }
            self.receive(on: connection, authenticated: true)
        }
    }

    private func finish(id: String, with result: Result<[String: Any], Error>) {
        queue.async { self.finishOnQueue(id: id, with: result) }
    }

    private func finishOnQueue(id: String, with result: Result<[String: Any], Error>) {
        guard let pending, pending.id == id else { return }
        self.pending = nil
        pending.continuation.resume(with: result)
    }

    // MARK: - One request at a time

    private func takeTurn() async {
        await withCheckedContinuation { continuation in
            queue.async {
                if self.busy {
                    self.turnWaiters.append(continuation)
                } else {
                    self.busy = true
                    continuation.resume()
                }
            }
        }
    }

    private func releaseTurn() {
        queue.async {
            if self.turnWaiters.isEmpty {
                self.busy = false
            } else {
                self.turnWaiters.removeFirst().resume()
            }
        }
    }

    private static func constantTimeEqual(_ lhs: String, _ rhs: String) -> Bool {
        let a = Array(lhs.utf8), b = Array(rhs.utf8)
        guard a.count == b.count else { return false }
        return zip(a, b).reduce(0) { $0 | ($1.0 ^ $1.1) } == 0
    }
}
