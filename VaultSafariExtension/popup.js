"use strict";

const site = document.getElementById("site");
const status = document.getElementById("status");

function row(action) {
    return document.querySelector(`[data-action="${action}"]`);
}

function native(message) {
    return browser.runtime.sendNativeMessage("application.id", message).catch(() => ({}));
}

function displayHost(url) {
    try {
        const parsed = new URL(url);
        if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
            return null;
        }
        return parsed.hostname.replace(/^www\./, "");
    } catch {
        return null;
    }
}

function savedLine(count) {
    if (count === 0) {
        return "No saved passwords";
    }
    return count === 1 ? "1 saved password" : `${count.toLocaleString()} saved passwords`;
}

function bind(action, handler) {
    const item = row(action);
    item.hidden = false;
    item.querySelector("button").addEventListener("click", handler);
}

async function start() {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    const page = tab && tab.url ? tab.url : "";
    const host = displayHost(page);
    const config = await native({ type: "config" });

    if (!host) {
        status.textContent = "";
        if (config.canOpenApp) {
            bind("search", () => native({ type: "open", action: "search", page: "" }).then(() => window.close()));
        }
        return;
    }

    site.textContent = host;
    const [state, probe] = await Promise.all([
        native({ type: "status", page }),
        browser.tabs.sendMessage(tab.id, { type: "probe" }, { frameId: 0 }).catch(() => ({}))
    ]);

    status.textContent = state.ready === false ? "Open Vaultwarden to turn on AutoFill" : savedLine(state.count || 0);

    if (probe && probe.hasLoginField && (state.count || 0) > 0) {
        bind("fill", async () => {
            await browser.tabs.sendMessage(tab.id, { type: "focusLogin" }, { frameId: 0 }).catch(() => {});
            window.close();
        });
    }
    if (config.canOpenApp) {
        bind("new", () => native({ type: "open", action: "new", page }).then(() => window.close()));
        if ((state.count || 0) > 0) {
            bind("search", () => native({ type: "open", action: "search", page }).then(() => window.close()));
        }
    }
}

start().catch(() => {
    status.textContent = "";
});
