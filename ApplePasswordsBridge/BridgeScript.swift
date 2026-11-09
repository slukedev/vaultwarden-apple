import Foundation

/// Appended to the private copy of the iCloud Passwords extension's background worker,
/// so it shares that worker's scope: `g_theState`, `g_secretSession`, `g_nativeAppPort`,
/// `ChallengePIN`, `PINSet` and `connectToBackgroundNativeAppAndSetUpListeners` are the
/// extension's own. The script never sees a key; the extension encrypts and decrypts.
nonisolated enum BridgeScript {
    static func source(port: UInt16, token: String) throws -> String {
        let config = try JSONSerialization.data(withJSONObject: ["port": Int(port), "token": token])
        return """

        self.VAULTWARDEN_BRIDGE = \(String(decoding: config, as: UTF8.self));
        \(body)
        """
    }

    private static let body = #"""
    (function vaultwardenBridge() {
      const { port, token } = self.VAULTWARDEN_BRIDGE;
      const OK = 0, INVALID_SESSION = 9, SERVER_ERROR = 100;
      const SET_PASSWORD = 6, GET_LOGIN_NAMES = 4;
      let socket = null;
      let pending = null;

      const send = (message) => {
        if (socket && socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(message));
      };
      const fail = (id, status, error) => send({ id, status, error: String(error) });
      const isPaired = () => typeof g_theState !== "undefined" && g_theState === "SessionKeySet";

      // The extension replaces its native port when the helper restarts; listen on each one.
      function nativePort() {
        if (typeof g_nativeAppPort === "undefined" || !g_nativeAppPort) {
          connectToBackgroundNativeAppAndSetUpListeners();
        }
        if (g_nativeAppPort && !g_nativeAppPort.__vaultwarden) {
          g_nativeAppPort.onMessage.addListener(reply);
          g_nativeAppPort.__vaultwarden = true;
        }
        return g_nativeAppPort;
      }

      function handle(message) {
        const { id } = message;
        try {
          switch (message.kind) {
            case "handshake":
              nativePort();
              if (message.pin == null) ChallengePIN(); else PINSet(String(message.pin));
              return send({ id, status: OK });
            case "state":
              return send({ id, data: { STATUS: OK, paired: isPaired(), state: String(typeof g_theState === "undefined" ? "" : g_theState) } });
            case "request": {
              if (!isPaired()) return fail(id, INVALID_SESSION, "Not paired");
              const port = nativePort();
              if (!port) return fail(id, SERVER_ERROR, "The Apple Passwords helper isn't running");
              pending = { id, cmd: message.cmd };
              const SMSG = g_secretSession.createSMSG(JSON.stringify(message.body));
              const outgoing = { cmd: message.cmd, tabId: message.tabId, frameId: message.frameId, payload: JSON.stringify({ QID: message.qid, SMSG }) };
              if (message.url != null) outgoing.url = message.url;
              return port.postMessage(outgoing);
            }
            default:
              return fail(id, SERVER_ERROR, "Unknown request");
          }
        } catch (error) {
          pending = null;
          fail(id, SERVER_ERROR, error);
        }
      }

      function reply(message) {
        if (!pending) return;
        const matches = message.cmd === pending.cmd || (pending.cmd === SET_PASSWORD && message.cmd === GET_LOGIN_NAMES);
        if (!matches) return;
        const { id } = pending;
        pending = null;
        try {
          let payload = message.payload;
          if (typeof payload === "string") payload = JSON.parse(payload);
          const data = payload && payload.SMSG
            ? JSON.parse(g_secretSession.parseSMSG(payload.SMSG))
            : { STATUS: message.STATUS ?? OK };
          send({ id, data });
        } catch (error) {
          fail(id, SERVER_ERROR, error);
        }
      }

      function connect() {
        const current = new WebSocket(`ws://127.0.0.1:${port}`);
        socket = current;
        current.onopen = () => send({ token });
        // A failed socket always closes next; reconnecting there keeps one timer per socket.
        current.onclose = () => {
          if (socket !== current) return;
          socket = null;
          pending = null;
          setTimeout(connect, 2000);
        };
        socket.onmessage = (event) => {
          try { handle(JSON.parse(event.data)); } catch (_) { /* malformed; ignore */ }
        };
      }

      // Chrome suspends an idle extension worker after 30 seconds, and the pairing key only
      // lives in that worker's memory. Traffic on the socket keeps it awake.
      setInterval(() => send({ heartbeat: Date.now() }), 20000);

      nativePort();
      connect();
    })();
    """#
}
