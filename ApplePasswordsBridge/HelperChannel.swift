import Darwin
import Foundation

/// Native messaging with Apple's helper over its stdin and stdout: each message is a
/// little-endian UInt32 length and that many bytes of JSON. Replies carry no request
/// ID, only the command number, so requests go one at a time.
nonisolated final class HelperChannel: @unchecked Sendable {
    private let writeFD: Int32
    private let readFD: Int32
    private let lock = NSLock()
    private var waiter: (commands: Set<Int>, continuation: CheckedContinuation<[String: Any], Error>)?
    private var open = true
    private var busy = false
    private var turnWaiters: [CheckedContinuation<Void, Never>] = []

    /// Called on the reader thread for messages nobody asked for, and once with nil when
    /// the helper exits.
    var onEvent: (@Sendable (Int?) -> Void)?

    init(writeFD: Int32, readFD: Int32) {
        self.writeFD = writeFD
        self.readFD = readFD
        let thread = Thread { [weak self] in self?.readLoop() }
        thread.name = "Apple Passwords helper"
        thread.start()
    }

    var isOpen: Bool { lock.withLock { open } }

    /// Sends `message` and waits for a reply whose `cmd` is one of `commands`.
    /// A nil timeout waits as long as it takes, for prompts like Touch ID.
    func request(_ message: [String: Any], expecting commands: Set<Int>, timeout: Duration?) async throws -> [String: Any] {
        await takeTurn()
        defer { releaseTurn() }

        let data = try JSONSerialization.data(withJSONObject: message)
        let timeoutTask = timeout.map { limit in
            Task { [weak self] in
                try? await Task.sleep(for: limit)
                guard !Task.isCancelled else { return }
                self?.finish(.failure(ApplePasswordsError(.serverError, "Apple Passwords didn't answer in time.")))
            }
        }
        defer { timeoutTask?.cancel() }

        return try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            guard open else {
                lock.unlock()
                continuation.resume(throwing: ApplePasswordsError(.invalidSession, "Apple's Passwords helper isn't running. Connect again."))
                return
            }
            waiter = (commands, continuation)
            lock.unlock()
            if !self.send(data) {
                finish(.failure(ApplePasswordsError(.serverError, "Apple's Passwords helper stopped.")))
            }
        }
    }

    /// Sends without waiting for a reply.
    func post(_ message: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: message) else { return }
        _ = send(data)
    }

    func close() {
        lock.lock()
        let wasOpen = open
        open = false
        lock.unlock()
        guard wasOpen else { return }
        Darwin.close(writeFD)
        // The read loop ends when the helper sees stdin close and exits.
    }

    // MARK: - I/O

    private func send(_ data: Data) -> Bool {
        var length = UInt32(data.count).littleEndian
        let header = withUnsafeBytes(of: &length) { [UInt8]($0) }
        return HelperLauncher.writeAll(writeFD, header + [UInt8](data))
    }

    private func readLoop() {
        while true {
            guard let header = readExactly(4) else { break }
            let length = header.withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self)) }
            guard length > 0, length <= 1 << 24, let body = readExactly(Int(length)) else { break }
            guard let message = (try? JSONSerialization.jsonObject(with: Data(body))) as? [String: Any] else { continue }
            let command = (message["cmd"] as? Int) ?? -1

            lock.lock()
            if let waiter, waiter.commands.contains(command) {
                self.waiter = nil
                lock.unlock()
                waiter.continuation.resume(returning: message)
            } else {
                lock.unlock()
                onEvent?(command)
            }
        }

        lock.lock()
        open = false
        let pending = waiter
        waiter = nil
        lock.unlock()
        Darwin.close(readFD)
        pending?.continuation.resume(throwing: ApplePasswordsError(.invalidSession, "Apple's Passwords helper stopped. Connect again."))
        onEvent?(nil)
    }

    private func readExactly(_ count: Int) -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            let got = buffer[offset...].withUnsafeMutableBytes { read(readFD, $0.baseAddress, $0.count) }
            if got < 0 && errno == EINTR { continue }
            guard got > 0 else { return nil }
            offset += got
        }
        return buffer
    }

    private func finish(_ result: Result<[String: Any], Error>) {
        lock.lock()
        let pending = waiter
        waiter = nil
        lock.unlock()
        pending?.continuation.resume(with: result)
    }

    // MARK: - One request at a time

    private func takeTurn() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if busy {
                turnWaiters.append(continuation)
                lock.unlock()
            } else {
                busy = true
                lock.unlock()
                continuation.resume()
            }
        }
    }

    private func releaseTurn() {
        lock.lock()
        if turnWaiters.isEmpty {
            busy = false
            lock.unlock()
        } else {
            let next = turnWaiters.removeFirst()
            lock.unlock()
            next.resume()
        }
    }
}
