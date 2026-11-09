#if os(macOS)
import SwiftUI

/// Settings ▸ Apple Passwords: turns the agent on, pairs with Apple's PIN, looks up
/// accounts and codes, and brings Apple Passwords logins into the vault.
struct ApplePasswordsSettingsView: View {
    @EnvironmentObject private var store: AppStore
    @ObservedObject private var connection = ApplePasswordsConnection.shared
    @Environment(\.scenePhase) private var scenePhase

    @State private var pin = ""
    @State private var pinRequested = false
    @State private var errorMessage: String?

    @State private var site = ""
    @State private var lookup: Lookup?
    @State private var isSearching = false

    @State private var scan = ImportScan()

    private static let extensionURL = URL(string: "https://chromewebstore.google.com/detail/icloud-passwords/pejdijmoenmkgeppbflobdenhhabjlaj")!

    private var canManageVault: Bool { store.isAuthenticated && store.isLocked == false }

    var body: some View {
        Form {
            SettingsHero(
                Text("Apple Passwords"),
                subtitle: heroLine,
                systemImage: "key.horizontal.fill",
                tint: .gray
            ) {
                if connection.agentState == .off {
                    Button("Turn On") { connection.turnOn() }
                }
            }

            switch connection.agentState {
            case .off:
                aboutSection
            case .requiresApproval:
                Section {
                    SettingsDetailRow(
                        title: Text("Allow in Login Items"),
                        detail: Text("Turn on Vaultwarden under Allow in the Background in System Settings ▸ General ▸ Login Items & Extensions. This page updates on its own.")
                    ) {
                        Button("Open…") { connection.openLoginItemsSettings() }
                    }
                }
            case .unavailable(let reason):
                Section {
                    Text(reason).foregroundStyle(.secondary)
                }
            case .on:
                browserSection
                if connection.status?.phase == .ready {
                    lookupSection
                    importSection
                }
                Section {
                    Button("Turn Off Apple Passwords", role: .destructive) {
                        Task { await connection.turnOff() }
                    }
                } footer: {
                    Text("Turning off quits the background browser and removes the agent from Login Items.")
                }
            }
        }
        .formStyle(.grouped)
        .task {
            await connection.refreshStatus()
            // Opening the pane while unpaired brings up Apple's PIN right away.
            if connection.status?.phase == .needsPairing && !pinRequested {
                askForPIN()
            }
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { Task { await connection.refreshStatus() } }
        }
        .alert(
            "Apple Passwords",
            isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(errorMessage ?? "")
        }
    }

    private var heroLine: Text {
        switch connection.agentState {
        case .off: Text("Look up and import passwords and codes saved in Apple Passwords.")
        case .requiresApproval: Text("Waiting for you to allow it in Login Items.")
        case .unavailable: Text("Not available.")
        case .on:
            switch connection.status?.phase {
            case .ready: Text("Connected and paired.")
            case .needsPairing: Text("Connected. Pair with the PIN Apple shows you.")
            case .starting: Text("Starting…")
            case .failed: Text(connection.status?.message ?? "Couldn't connect.")
            case .stopped, nil: Text("Not connected.")
            }
        }
    }

    // MARK: - Sections

    private var aboutSection: some View {
        Section {
            Label("Needs Google Chrome, Microsoft Edge, Brave or Chromium with Apple's iCloud Passwords extension added.", systemImage: "puzzlepiece.extension")
            Label("Pairs with a PIN that Apple shows on this Mac, about once per login.", systemImage: "number")
            Label("Passwords are read only when you ask, and go straight into your encrypted vault.", systemImage: "lock")
        } header: {
            Text("How It Works")
        } footer: {
            Text("Vaultwarden runs that browser hidden in the background, because macOS only lets browsers talk to Apple Passwords.")
        }
    }

    @ViewBuilder
    private var browserSection: some View {
        let browsers = connection.status?.browsers ?? []
        let usable = browsers.filter(\.hasExtension)
        Section {
            if browsers.isEmpty {
                Text("No supported browser found. Install Google Chrome, Microsoft Edge, Brave or Chromium.")
                    .foregroundStyle(.secondary)
            } else if usable.isEmpty {
                SettingsDetailRow(
                    title: Text("Add the iCloud Passwords Extension"),
                    detail: Text("Add it to \(browsers.map(\.name).formatted(.list(type: .or))) and sign in once, then come back.")
                ) {
                    Link("Get Extension…", destination: Self.extensionURL)
                }
            } else {
                Picker("Browser", selection: browserBinding(usable)) {
                    ForEach(usable) { browser in
                        Text(browser.name).tag(browser.id)
                    }
                }
                connectionRow
                if connection.status?.phase == .needsPairing {
                    pairingRows
                }
            }
        } header: {
            Text("Connection")
        } footer: {
            Text("The browser keeps running hidden until you log out, so you pair about once per login. You'll pair again after a restart, a logout, or if the browser quits.")
        }
    }

    private var connectionRow: some View {
        let phase = connection.status?.phase ?? .stopped
        return LabeledContent {
            if connection.isWorking {
                ProgressView().controlSize(.small)
            } else if phase == .stopped || phase == .failed {
                Button("Connect", action: connectAndPair)
            } else {
                Button("Disconnect") {
                    Task {
                        await connection.disconnectBrowser()
                        pinRequested = false
                    }
                }
            }
        } label: {
            Text("Status")
            Text(statusText(phase))
        }
    }

    @ViewBuilder
    private var pairingRows: some View {
        SettingsDetailRow(
            title: Text("Pair"),
            detail: pinRequested
                ? Text("Enter the PIN from the Apple Passwords notification.")
                : Text("Apple shows a PIN on this Mac. Enter it here to finish.")
        ) {
            Button(pinRequested ? "Show New PIN" : "Show PIN", action: askForPIN)
        }
        if pinRequested {
            HStack {
                TextField("PIN", text: $pin)
                    .textContentType(.oneTimeCode)
                    .onSubmit(submitPIN)
                Button("Pair", action: submitPIN)
                    .disabled(pin.filter(\.isNumber).count < 4 || connection.isWorking)
            }
        }
    }

    private var lookupSection: some View {
        Section {
            HStack {
                TextField("Website", text: $site, prompt: Text("example.com"))
                    .onSubmit(search)
                Button("Look Up", action: search)
                    .disabled(site.trimmingCharacters(in: .whitespaces).isEmpty || isSearching)
            }
            if isSearching {
                ProgressView().frame(maxWidth: .infinity)
            } else if let lookup {
                if lookup.accounts.isEmpty && lookup.codes.isEmpty {
                    Text("Nothing saved in Apple Passwords for \(lookup.site).")
                        .foregroundStyle(.secondary)
                }
                ForEach(lookup.accounts) { account in
                    accountRow(account)
                }
                ForEach(lookup.codes) { code in
                    LabeledContent {
                        if let value = code.code {
                            Button(value) { Clipboard.copy(value) }
                                .monospacedDigit()
                                .help("Copy Code")
                        }
                    } label: {
                        Label(code.username.isEmpty ? code.domain : code.username, systemImage: "lock.rotation")
                    }
                }
            }
        } header: {
            Text("Look Up")
        } footer: {
            Text("Apple may ask you to authenticate before it shares a password.")
        }
    }

    private func accountRow(_ account: ApplePasswordsAccount) -> some View {
        let inVault = ApplePasswordsImport.isInVault(account, items: store.items)
        return LabeledContent {
            HStack {
                Button("Copy Password") {
                    run {
                        let password = try await connection.password(for: account.primarySite, username: account.username)
                        Clipboard.copy(password)
                    }
                }
                if canManageVault {
                    Button(inVault ? "In Vault" : "Add to Vault") {
                        run { try await add([account]) }
                    }
                    .disabled(inVault)
                }
            }
        } label: {
            Label {
                Text(account.username.isEmpty ? String(localized: "No User Name") : account.username)
                Text(account.primarySite)
            } icon: {
                Image(systemName: "person.crop.circle")
            }
        }
    }

    @ViewBuilder
    private var importSection: some View {
        Section {
            if !canManageVault {
                Text("Unlock your vault to import.").foregroundStyle(.secondary)
            } else if scan.isRunning {
                ProgressView(value: Double(scan.checked), total: Double(max(scan.total, 1))) {
                    Text("Checking \(scan.checked) of \(scan.total) websites…")
                }
            } else if let found = scan.found {
                if found.isEmpty {
                    Text("Every Apple Passwords login for these websites is already in your vault.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(found) { account in
                        Toggle(isOn: selectionBinding(account)) {
                            Text(account.username.isEmpty ? String(localized: "No User Name") : account.username)
                            Text(account.primarySite)
                        }
                    }
                    Button("Add \(scan.selected.count) to Vault") {
                        let chosen = found.filter { scan.selected.contains($0.id) }
                        run {
                            try await add(chosen)
                            scan.found = ApplePasswordsImport.missing(found, items: store.items)
                            scan.selected = []
                        }
                    }
                    .disabled(scan.selected.isEmpty || connection.isWorking)
                }
                Button("Check Again", action: startScan)
            } else {
                SettingsDetailRow(
                    title: Text("Find Missing Logins"),
                    detail: Text("Checks Apple Passwords for each website in your vault and lists accounts you haven't saved here.")
                ) {
                    Button("Check…", action: startScan)
                }
            }
        } header: {
            Text("Import")
        }
    }

    // MARK: - Actions

    /// Starts the browser if needed and, when it isn't paired yet, asks Apple for the
    /// PIN in the same step.
    private func connectAndPair() {
        run {
            try await connection.connect()
            if connection.status?.phase == .needsPairing {
                try await connection.requestPIN()
                pinRequested = true
            }
        }
    }

    private func askForPIN() {
        run {
            try await connection.requestPIN()
            pinRequested = true
        }
    }

    private func submitPIN() {
        let value = pin
        run {
            if try await connection.submitPIN(value) {
                pin = ""
                pinRequested = false
            } else {
                throw ApplePasswordsError(.invalidSession, String(localized: "That PIN didn't work. Show a new PIN and try again."))
            }
        }
    }

    private func search() {
        let query = site
        guard let host = ApplePasswordsSite.host(query) else {
            errorMessage = String(localized: "Enter a website, like example.com.")
            return
        }
        isSearching = true
        Task {
            defer { isSearching = false }
            do {
                async let accounts = connection.accounts(for: host)
                async let codes = connection.oneTimeCodes(for: host)
                lookup = Lookup(site: host, accounts: try await accounts, codes: (try? await codes) ?? [])
            } catch {
                errorMessage = error.localizedDescription
                await connection.refreshStatus()
            }
        }
    }

    private func startScan() {
        let sites = ApplePasswordsImport.sites(in: store.items)
        scan = ImportScan(isRunning: true, total: sites.count)
        Task {
            var accounts: [ApplePasswordsAccount] = []
            for site in sites {
                if let found = try? await connection.accounts(for: site) {
                    accounts.append(contentsOf: found)
                }
                scan.checked += 1
            }
            let missing = ApplePasswordsImport.missing(accounts, items: store.items)
            scan = ImportScan(found: missing, selected: Set(missing.map(\.id)))
        }
    }

    /// Fetches each password from Apple Passwords and saves a new vault login.
    private func add(_ accounts: [ApplePasswordsAccount]) async throws {
        guard canManageVault else { return }
        var failures = 0
        for account in accounts where !ApplePasswordsImport.isInVault(account, items: store.items) {
            do {
                let password = try await connection.password(for: account.primarySite, username: account.username)
                let item = ApplePasswordsImport.vaultItem(for: account, password: password)
                if await store.save(item) == false { failures += 1 }
            } catch {
                failures += 1
            }
        }
        if failures > 0 {
            throw ApplePasswordsError(.genericError, String(localized: "\(failures) logins couldn't be added."))
        }
    }

    private func run(_ body: @escaping () async throws -> Void) {
        Task {
            do {
                try await body()
            } catch {
                errorMessage = error.localizedDescription
                await connection.refreshStatus()
            }
        }
    }

    // MARK: - Helpers

    private func statusText(_ phase: ApplePasswordsBridgeStatus.Phase) -> String {
        switch phase {
        case .stopped: String(localized: "Not connected")
        case .starting: String(localized: "Starting…")
        case .needsPairing: String(localized: "Needs pairing")
        case .ready: String(localized: "Paired")
        case .failed: connection.status?.message ?? String(localized: "Couldn't connect")
        }
    }

    private func browserBinding(_ usable: [ApplePasswordsBrowser]) -> Binding<String> {
        Binding(
            get: {
                connection.status?.activeBrowserID
                    ?? connection.preferredBrowserID.flatMap { id in usable.first { $0.id == id }?.id }
                    ?? usable.first?.id ?? ""
            },
            set: { newValue in
                guard newValue != connection.status?.activeBrowserID else { return }
                connection.preferredBrowserID = newValue
                pinRequested = false
                if connection.status?.activeBrowserID != nil {
                    connectAndPair()
                }
            }
        )
    }

    private func selectionBinding(_ account: ApplePasswordsAccount) -> Binding<Bool> {
        Binding(
            get: { scan.selected.contains(account.id) },
            set: { isOn in
                if isOn { scan.selected.insert(account.id) } else { scan.selected.remove(account.id) }
            }
        )
    }

    private struct Lookup {
        var site: String
        var accounts: [ApplePasswordsAccount]
        var codes: [ApplePasswordsCode]
    }

    private struct ImportScan {
        var isRunning = false
        var total = 0
        var checked = 0
        var found: [ApplePasswordsAccount]?
        var selected: Set<String> = []
    }
}
#endif
