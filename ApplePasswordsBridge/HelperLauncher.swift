import Darwin
import Foundation

/// Starts Apple's Passwords helper with an allowlisted browser as its parent.
///
/// 1. The agent opens a private Unix socket and two pipes, then starts the browser
///    headless with a throwaway profile and `--browser-subprocess-path` set to the
///    agent's own executable.
/// 2. The first subprocess the browser launches is this executable again, run with
///    `--type=…` and the socket path in its environment. The agent checks that the
///    peer really is its own executable and a child of that browser, then passes it the
///    pipe ends with SCM_RIGHTS.
/// 3. The subprocess leaves the browser's process group, moves the pipes onto stdin
///    and stdout, and execs Apple's helper, whose parent is now the browser.
/// 4. The agent quits the browser. The helper keeps running and speaks native
///    messaging on the pipes until the agent closes them.
nonisolated enum HelperLauncher {
    static let handoffVariable = "VAULTWARDEN_APPLE_PASSWORDS_HANDOFF"
    static let appleManifest = "/Library/Google/Chrome/NativeMessagingHosts/com.apple.passwordmanager.json"
    private static let startupTimeout: TimeInterval = 20
    private static let maxHandoffBytes = 1 << 20

    struct Helper: Sendable {
        let pid: pid_t
        /// The helper's stdin.
        let writeFD: Int32
        /// The helper's stdout.
        let readFD: Int32
    }

    // MARK: - Agent side

    /// Blocks for up to 20 seconds; call it off the main thread.
    static func launch(through browser: ChromiumBrowser) throws -> Helper {
        guard let helper = appleHelperPath() else {
            throw ApplePasswordsError(.genericError, "Apple's Passwords helper wasn't found. It ships with macOS 14 and later.")
        }
        guard let ownPath = processPath(getpid()) else {
            throw ApplePasswordsError(.genericError, "The Apple Passwords agent couldn't find itself.")
        }

        let directory = try makePrivateDirectory()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let socketPath = directory + "/h.sock"
        let listener = try listenSocket(at: socketPath)
        defer { close(listener) }

        var toHelper: [Int32] = [-1, -1]
        var fromHelper: [Int32] = [-1, -1]
        guard pipe(&toHelper) == 0 else { throw posixError("create a pipe") }
        guard pipe(&fromHelper) == 0 else {
            close(toHelper[0]); close(toHelper[1])
            throw posixError("create a pipe")
        }
        let devNull = open("/dev/null", O_RDWR)
        var handedOver = false
        defer {
            close(toHelper[0]); close(fromHelper[1]); close(devNull)
            if !handedOver { close(toHelper[1]); close(fromHelper[0]) }
        }
        _ = fcntl(toHelper[1], F_SETFD, FD_CLOEXEC)
        _ = fcntl(fromHelper[0], F_SETFD, FD_CLOEXEC)

        let environment = ProcessInfo.processInfo.environment
            .filter { $0.key != handoffVariable && $0.key != "CFFIXED_USER_HOME" }
            .map { "\($0.key)=\($0.value)" }

        let browserPID = try spawnBrowser(browser, directory: directory, socketPath: socketPath, subprocessPath: ownPath)
        defer { stopProcessGroup(browserPID) }

        let (client, peer) = try acceptSubprocess(listener, browserPID: browserPID, ownPath: ownPath, browserName: browser.name)
        defer { close(client) }
        try sendHandoff(client, fds: [toHelper[0], fromHelper[1], devNull], environment: environment)
        guard waitForExec(client, peer: peer, helperPath: helper) else {
            throw ApplePasswordsError(.genericError, "\(browser.name) didn't start Apple's Passwords helper. Try another browser.")
        }

        handedOver = true
        return Helper(pid: peer, writeFD: toHelper[1], readFD: fromHelper[0])
    }

    static func appleHelperPath() -> String? {
        guard let data = FileManager.default.contents(atPath: appleManifest),
              let manifest = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let path = manifest["path"] as? String, path.hasPrefix("/") else { return nil }
        let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        // Only ever exec Apple's own binary from the system volume.
        guard resolved.hasPrefix("/System/"), FileManager.default.isExecutableFile(atPath: resolved) else { return nil }
        return resolved
    }

    private static func spawnBrowser(_ browser: ChromiumBrowser, directory: String, socketPath: String, subprocessPath: String) throws -> pid_t {
        let arguments = [
            browser.executable.path,
            "--user-data-dir=\(directory)/profile",
            "--browser-subprocess-path=\(subprocessPath)",
            "--headless=new",
            "--no-first-run",
            "--no-default-browser-check",
            "--use-mock-keychain",
            "--mute-audio",
        ]
        var environment = ProcessInfo.processInfo.environment
        environment[handoffVariable] = socketPath
        // Keeps the browser away from the real home folder and Keychain.
        environment["CFFIXED_USER_HOME"] = directory

        var argv: [UnsafeMutablePointer<CChar>?] = arguments.map { strdup($0) } + [nil]
        var envp: [UnsafeMutablePointer<CChar>?] = environment.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer {
            argv.forEach { free($0) }
            envp.forEach { free($0) }
        }

        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0)
        posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0)

        var attributes: posix_spawnattr_t?
        posix_spawnattr_init(&attributes)
        defer { posix_spawnattr_destroy(&attributes) }
        // Close everything else in the child, and give the browser its own process
        // group so all of it can be stopped at once.
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP))
        posix_spawnattr_setpgroup(&attributes, 0)

        var pid: pid_t = 0
        let result = posix_spawn(&pid, browser.executable.path, &actions, &attributes, &argv, &envp)
        guard result == 0 else {
            throw ApplePasswordsError(.genericError, "\(browser.name) couldn't be started (error \(result)).")
        }
        return pid
    }

    private static func acceptSubprocess(_ listener: Int32, browserPID: pid_t, ownPath: String, browserName: String) throws -> (Int32, pid_t) {
        let deadline = Date().addingTimeInterval(startupTimeout)
        while Date() < deadline {
            var ready = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
            let status = poll(&ready, 1, 100)
            if status < 0 && errno != EINTR { throw posixError("wait for \(browserName)") }
            if status <= 0 {
                if waitpid(browserPID, nil, WNOHANG) == browserPID {
                    throw ApplePasswordsError(.genericError, "\(browserName) quit before starting Apple's Passwords helper.")
                }
                continue
            }
            let client = accept(listener, nil, nil)
            guard client >= 0 else { continue }
            var peer: pid_t = 0
            var length = socklen_t(MemoryLayout<pid_t>.size)
            if getsockopt(client, SOL_LOCAL, LOCAL_PEERPID, &peer, &length) == 0,
               parentPID(peer) == browserPID,
               processPath(peer) == ownPath {
                return (client, peer)
            }
            close(client)
        }
        throw ApplePasswordsError(.genericError, "\(browserName) didn't start in time.")
    }

    private static func sendHandoff(_ socket: Int32, fds: [Int32], environment: [String]) throws {
        let payload = try JSONSerialization.data(withJSONObject: [
            "arguments": [ApplePasswordsBridgeIdentity.helperOrigin],
            "environment": environment,
        ])
        var length = UInt32(payload.count)
        var control = [UInt8](repeating: 0, count: ControlMessage.space(fdCount: fds.count))
        ControlMessage.write(fds, into: &control)

        let sent: Int = withUnsafeMutablePointer(to: &length) { lengthPointer in
            control.withUnsafeMutableBytes { controlBytes in
                var vector = iovec(iov_base: UnsafeMutableRawPointer(lengthPointer), iov_len: MemoryLayout<UInt32>.size)
                return withUnsafeMutablePointer(to: &vector) { vectorPointer in
                    var message = msghdr(
                        msg_name: nil, msg_namelen: 0,
                        msg_iov: vectorPointer, msg_iovlen: 1,
                        msg_control: controlBytes.baseAddress, msg_controllen: socklen_t(controlBytes.count),
                        msg_flags: 0
                    )
                    return sendmsg(socket, &message, 0)
                }
            }
        }
        guard sent == MemoryLayout<UInt32>.size else { throw posixError("hand over to the browser") }
        guard writeAll(socket, [UInt8](payload)) else { throw posixError("hand over to the browser") }
    }

    /// The subprocess closes the socket as it execs; then its path becomes Apple's helper.
    private static func waitForExec(_ socket: Int32, peer: pid_t, helperPath: String) -> Bool {
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var byte: UInt8 = 0
        while read(socket, &byte, 1) > 0 {}
        for _ in 0..<100 {
            if processPath(peer) == helperPath { return true }
            usleep(10_000)
        }
        return false
    }

    private static func stopProcessGroup(_ pid: pid_t) {
        kill(-pid, SIGTERM)
        usleep(150_000)
        kill(-pid, SIGKILL)
        var status: Int32 = 0
        while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
    }

    // MARK: - Subprocess side

    /// Runs first in `main`. When the browser starts this executable as its subprocess,
    /// this becomes Apple's helper and never returns.
    static func runHandoffIfRequested() {
        guard let value = getenv(handoffVariable) else { return }
        let arguments = CommandLine.arguments
        guard arguments.count > 1, arguments[1].hasPrefix("--type=") else { return }
        exit(runHandoff(socketPath: String(cString: value)))
    }

    private static func runHandoff(socketPath: String) -> Int32 {
        // Leave the browser's process group so stopping the browser spares the helper.
        guard setpgid(0, 0) == 0 else { return 1 }
        let socket = connectSocket(at: socketPath)
        guard socket >= 0 else { return 1 }

        var length: UInt32 = 0
        var control = [UInt8](repeating: 0, count: ControlMessage.space(fdCount: 3))
        let received: Int = withUnsafeMutablePointer(to: &length) { lengthPointer in
            control.withUnsafeMutableBytes { controlBytes in
                var vector = iovec(iov_base: UnsafeMutableRawPointer(lengthPointer), iov_len: MemoryLayout<UInt32>.size)
                return withUnsafeMutablePointer(to: &vector) { vectorPointer in
                    var message = msghdr(
                        msg_name: nil, msg_namelen: 0,
                        msg_iov: vectorPointer, msg_iovlen: 1,
                        msg_control: controlBytes.baseAddress, msg_controllen: socklen_t(controlBytes.count),
                        msg_flags: 0
                    )
                    return recvmsg(socket, &message, 0)
                }
            }
        }
        guard received == MemoryLayout<UInt32>.size, let fds = ControlMessage.read(control, fdCount: 3) else {
            close(socket)
            return 1
        }
        let closeFDs = { fds.forEach { close($0) } }
        guard Int(length) <= maxHandoffBytes, let payload = readExactly(socket, count: Int(length)) else {
            close(socket); closeFDs()
            return 1
        }
        close(socket)

        guard let handoff = (try? JSONSerialization.jsonObject(with: Data(payload))) as? [String: Any],
              let helperArguments = handoff["arguments"] as? [String],
              helperArguments.first == ApplePasswordsBridgeIdentity.helperOrigin,
              let environment = handoff["environment"] as? [String],
              let helper = appleHelperPath() else {
            closeFDs()
            return 1
        }
        for (target, fd) in fds.enumerated() {
            guard dup2(fd, Int32(target)) >= 0 else { closeFDs(); return 1 }
            if fd > 2 { close(fd) }
        }

        var argv: [UnsafeMutablePointer<CChar>?] = ([helper] + helperArguments).map { strdup($0) } + [nil]
        var envp: [UnsafeMutablePointer<CChar>?] = environment.map { strdup($0) } + [nil]
        execve(helper, &argv, &envp)
        return 1
    }

    // MARK: - Sockets and processes

    static func processPath(_ pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
        return URL(fileURLWithPath: String(cString: buffer)).resolvingSymlinksInPath().path
    }

    private static func parentPID(_ pid: pid_t) -> pid_t {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return 0 }
        return pid_t(info.pbi_ppid)
    }

    private static func makePrivateDirectory() throws -> String {
        var template = Array("/tmp/vaultwarden-applepw.XXXXXX".utf8CString)
        let path: String? = template.withUnsafeMutableBufferPointer { buffer in
            mkdtemp(buffer.baseAddress!).map { String(cString: $0) }
        }
        guard let path else { throw posixError("create a private folder") }
        chmod(path, 0o700)
        return path
    }

    private static func socketAddress(_ path: String) -> sockaddr_un? {
        var address = sockaddr_un()
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: address.sun_path) else { return nil }
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        return address
    }

    private static func listenSocket(at path: String) throws -> Int32 {
        guard var address = socketAddress(path) else { throw ApplePasswordsError(.genericError, "The socket path is too long.") }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw posixError("open a socket") }
        unlink(path)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard bound == 0, chmod(path, 0o600) == 0, Darwin.listen(fd, 4) == 0 else {
            close(fd)
            throw posixError("open a socket")
        }
        return fd
    }

    private static func connectSocket(at path: String) -> Int32 {
        guard var address = socketAddress(path) else { return -1 }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return -1 }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard connected == 0 else { close(fd); return -1 }
        return fd
    }

    static func writeAll(_ fd: Int32, _ bytes: [UInt8]) -> Bool {
        var offset = 0
        while offset < bytes.count {
            let written = bytes[offset...].withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
            if written < 0 && errno == EINTR { continue }
            guard written > 0 else { return false }
            offset += written
        }
        return true
    }

    private static func readExactly(_ fd: Int32, count: Int) -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            let got = buffer[offset...].withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            if got < 0 && errno == EINTR { continue }
            guard got > 0 else { return nil }
            offset += got
        }
        return buffer
    }

    private static func posixError(_ action: String) -> ApplePasswordsError {
        ApplePasswordsError(.genericError, "Couldn't \(action): \(String(cString: strerror(errno))).")
    }
}

/// SCM_RIGHTS control messages, laid out by hand because Swift doesn't import the CMSG macros.
nonisolated enum ControlMessage {
    private static let alignment = MemoryLayout<UInt32>.size
    private static var headerSize: Int { align(MemoryLayout<cmsghdr>.size) }

    private static func align(_ value: Int) -> Int { (value + alignment - 1) & ~(alignment - 1) }

    static func space(fdCount: Int) -> Int { headerSize + align(fdCount * MemoryLayout<Int32>.size) }
    private static func length(fdCount: Int) -> Int { headerSize + fdCount * MemoryLayout<Int32>.size }

    static func write(_ fds: [Int32], into buffer: inout [UInt8]) {
        var header = cmsghdr()
        header.cmsg_len = socklen_t(length(fdCount: fds.count))
        header.cmsg_level = SOL_SOCKET
        header.cmsg_type = SCM_RIGHTS
        buffer.withUnsafeMutableBytes { raw in
            raw.storeBytes(of: header, toByteOffset: 0, as: cmsghdr.self)
            for (index, fd) in fds.enumerated() {
                raw.storeBytes(of: fd, toByteOffset: headerSize + index * MemoryLayout<Int32>.size, as: Int32.self)
            }
        }
    }

    static func read(_ buffer: [UInt8], fdCount: Int) -> [Int32]? {
        guard buffer.count >= space(fdCount: fdCount) else { return nil }
        return buffer.withUnsafeBytes { raw -> [Int32]? in
            let header = raw.loadUnaligned(fromByteOffset: 0, as: cmsghdr.self)
            guard header.cmsg_level == SOL_SOCKET, header.cmsg_type == SCM_RIGHTS,
                  Int(header.cmsg_len) >= length(fdCount: fdCount) else { return nil }
            return (0..<fdCount).map {
                raw.loadUnaligned(fromByteOffset: headerSize + $0 * MemoryLayout<Int32>.size, as: Int32.self)
            }
        }
    }
}
