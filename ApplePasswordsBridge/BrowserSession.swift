import Foundation

/// One headless browser running the patched extension, and the link to it.
nonisolated final class BrowserSession: @unchecked Sendable {
    let browser: ChromiumBrowser
    let link: ExtensionLink
    private let process: Process

    var isRunning: Bool { process.isRunning }

    private init(browser: ChromiumBrowser, link: ExtensionLink, process: Process) {
        self.browser = browser
        self.link = link
        self.process = process
    }

    static func launch(_ browser: ChromiumBrowser) async throws -> BrowserSession {
        guard let executable = browser.executable else {
            throw ApplePasswordsError(.genericError, "\(browser.name) isn't installed.")
        }
        guard let source = browser.extensionSource else {
            throw ApplePasswordsError(.genericError, "Install the iCloud Passwords extension in \(browser.name) first.")
        }

        let link = ExtensionLink()
        let port = try await link.start()
        do {
            try BridgeFiles.installExtension(from: source, port: port, token: link.token)
            let profile = try BridgeFiles.prepareProfile(for: browser)
            let debuggingPort = UInt16.random(in: 9500...9899)

            let process = Process()
            process.executableURL = executable
            process.arguments = [
                "--user-data-dir=\(profile.path)",
                "--remote-debugging-address=127.0.0.1",
                "--remote-debugging-port=\(debuggingPort)",
                "--remote-allow-origins=http://127.0.0.1:\(debuggingPort)",
                "--enable-unsafe-extension-debugging",
                "--headless=new",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-background-timer-throttling",
                "--disable-backgrounding-occluded-windows",
            ]
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            try process.run()

            let session = BrowserSession(browser: browser, link: link, process: process)
            do {
                try await DevTools.loadUnpackedExtension(at: BridgeFiles.extensionURL, port: debuggingPort)
            } catch {
                session.stop()
                throw error
            }
            return session
        } catch {
            link.stop()
            throw error
        }
    }

    func stop() {
        link.stop()
        if process.isRunning {
            process.terminate()
        }
    }
}

/// Loads the unpacked extension through the Chrome DevTools Protocol, which works in
/// headless mode where `--load-extension` is ignored by current Chrome releases.
nonisolated enum DevTools {
    static func loadUnpackedExtension(at url: URL, port: UInt16) async throws {
        let endpoint = try await debuggerURL(port: port)
        let task = URLSession.shared.webSocketTask(with: endpoint)
        task.resume()
        defer { task.cancel(with: .normalClosure, reason: nil) }

        let command: [String: Any] = [
            "id": 1,
            "method": "Extensions.loadUnpacked",
            "params": ["path": url.path],
        ]
        let data = try JSONSerialization.data(withJSONObject: command)
        try await task.send(.string(String(decoding: data, as: UTF8.self)))

        let deadline = ContinuousClock.now + .seconds(15)
        while ContinuousClock.now < deadline {
            let message = try await task.receive()
            let text: String
            switch message {
            case .string(let value): text = value
            case .data(let value): text = String(decoding: value, as: UTF8.self)
            @unknown default: continue
            }
            guard let reply = (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any],
                  reply["id"] as? Int == 1 else { continue }
            if let error = reply["error"] as? [String: Any] {
                throw ApplePasswordsError(.genericError, "The browser didn't load the extension: \(error["message"] as? String ?? "unknown error").")
            }
            return
        }
        throw ApplePasswordsError(.genericError, "The browser didn't load the extension in time.")
    }

    private static func debuggerURL(port: UInt16) async throws -> URL {
        let versionURL = URL(string: "http://127.0.0.1:\(port)/json/version")!
        for _ in 0..<60 {
            if let (data, _) = try? await URLSession.shared.data(from: versionURL),
               let info = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
               let value = info["webSocketDebuggerUrl"] as? String,
               let url = URL(string: value) {
                return url
            }
            try await Task.sleep(for: .milliseconds(250))
        }
        throw ApplePasswordsError(.genericError, "The browser didn't start.")
    }
}
