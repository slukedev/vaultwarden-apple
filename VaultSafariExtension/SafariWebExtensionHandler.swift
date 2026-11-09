import Foundation
import SafariServices
#if os(macOS)
import AppKit
#endif

/// Answers the extension's questions from the site index the app publishes. It never
/// sees the vault: only keyed hashes, plus a login the person typed on the Mac,
/// held in the Keychain until they save or dismiss it.
nonisolated final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let message = item?.userInfo?[SFExtensionMessageKey] as? [String: Any] ?? [:]
        let response = NSExtensionItem()
        response.userInfo = [SFExtensionMessageKey: SafariExtensionResponder.reply(to: message)]
        context.completeRequest(returningItems: [response], completionHandler: nil)
    }
}

nonisolated enum SafariExtensionResponder {
    #if os(macOS)
    private static let isMac = true
    #else
    private static let isMac = false
    #endif

    static func reply(to message: [String: Any]) -> [String: Any] {
        let page = (message["page"] as? String) ?? ""
        switch message["type"] as? String {
        case "config":
            // iPhone and iPad already save passwords through the system prompt.
            return ["capturesLogins": isMac, "canOpenApp": isMac]
        case "status":
            guard let loaded = AutoFillSiteIndex.load() else { return ["ready": false, "count": 0] }
            return ["ready": true, "count": loaded.index.loginCount(forPage: page, key: loaded.key)]
        case "capture":
            return capture(message, page: page)
        case "pending":
            let login = (message["id"] as? String).flatMap(SafariCapturedLogin.load(id:))
                ?? SafariCapturedLogin.pending(forPage: page)
            guard let login else { return [:] }
            return [
                "id": login.id,
                "action": login.isPasswordChange ? "update" : "save",
                "host": login.host,
                "username": login.username
            ]
        case "dismiss":
            if let id = message["id"] as? String { SafariCapturedLogin.remove(id: id) }
            return ["ok": true]
        case "save":
            guard let id = message["id"] as? String, SafariCapturedLogin.load(id: id) != nil else {
                return ["ok": false]
            }
            return ["ok": open(SafariAppLink.saveLogin(id: id))]
        case "open":
            let link: SafariAppLink = message["action"] as? String == "new"
                ? .newLogin(website: page)
                : .search(website: page)
            return ["ok": open(link)]
        default:
            return [:]
        }
    }

    private static func capture(_ message: [String: Any], page: String) -> [String: Any] {
        guard isMac,
              let password = message["password"] as? String, !password.isEmpty,
              password.count <= 1_024,
              let origin = SafariAppLink.origin(of: page) else { return ["action": "none"] }
        let username = String(((message["username"] as? String) ?? "").prefix(512))
        let knowledge: AutoFillSiteIndex.Knowledge
        if let loaded = AutoFillSiteIndex.load() {
            knowledge = loaded.index.knowledge(page: origin, username: username, password: password, key: loaded.key)
        } else {
            knowledge = .new
        }
        guard knowledge != .saved else { return ["action": "none"] }
        let login = SafariCapturedLogin(
            id: UUID().uuidString,
            page: origin,
            username: username,
            password: password,
            isPasswordChange: knowledge == .changedPassword,
            capturedAt: Date()
        )
        do {
            try SafariCapturedLogin.store(login)
        } catch {
            return ["action": "none"]
        }
        return ["action": login.isPasswordChange ? "update" : "save", "id": login.id, "host": login.host]
    }

    private static func open(_ link: SafariAppLink) -> Bool {
        #if os(macOS)
        guard let url = link.url else { return false }
        return NSWorkspace.shared.open(url)
        #else
        return false
        #endif
    }
}
