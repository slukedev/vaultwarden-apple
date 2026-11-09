import Foundation

// ApplePasswordsBridge: a per-user launch agent bundled inside Vaultwarden.app and
// registered with SMAppService. launchd starts it on demand when the app connects to
// its Mach service. It runs outside the app sandbox because it has to start a browser
// and read that browser's extensions folder.

nonisolated final class BridgeService: NSObject, NSXPCListenerDelegate, ApplePasswordsBridgeXPC, @unchecked Sendable {
    private let controller = BridgeController()
    private let lock = NSLock()
    private var connectionCount = 0

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: ApplePasswordsBridgeXPC.self)
        connection.exportedObject = self
        connection.invalidationHandler = { [weak self] in self?.connectionEnded() }
        lock.withLock { connectionCount += 1 }
        connection.resume()
        return true
    }

    func perform(_ request: Data, withReply reply: @escaping @Sendable (Data) -> Void) {
        let decoded = try? JSONDecoder().decode(ApplePasswordsBridgeRequest.self, from: request)
        Task {
            let response: ApplePasswordsBridgeResponse
            if let decoded {
                response = await controller.handle(decoded)
            } else {
                response = .failure("Vaultwarden and its Apple Passwords agent are different versions. Restart Vaultwarden.")
            }
            reply((try? JSONEncoder().encode(response)) ?? Data())
        }
    }

    /// The browser, and with it the pairing, stays up for the whole login session, so
    /// Apple's PIN is needed about once per login instead of every time Vaultwarden opens.
    /// launchd stops the agent at logout; Turn Off in Settings stops it sooner.
    private func connectionEnded() {
        lock.withLock { connectionCount = max(0, connectionCount - 1) }
    }

    func stopBrowser() async {
        await controller.stop()
    }
}

let service = BridgeService()
let listener = NSXPCListener(machServiceName: ApplePasswordsBridgeIdentity.machServiceName)
listener.setConnectionCodeSigningRequirement(
    ApplePasswordsBridgeIdentity.codeRequirement(forIdentifier: ApplePasswordsBridgeIdentity.appIdentifier)
)
listener.delegate = service
listener.resume()

var signalSources: [DispatchSourceSignal] = []
for signalNumber in [SIGTERM, SIGINT] {
    signal(signalNumber, SIG_IGN)
    let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: .main)
    source.setEventHandler {
        Task {
            await service.stopBrowser()
            exit(0)
        }
    }
    source.resume()
    signalSources.append(source)
}

dispatchMain()
