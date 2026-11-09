"use strict";

// Safari only lets the background page and popup talk to the app, so content
// scripts send their questions through here. Only known message types pass.
const NATIVE_TYPES = new Set(["config", "status", "capture", "pending", "dismiss", "save"]);

function native(message) {
    return browser.runtime.sendNativeMessage("application.id", message).catch(() => ({}));
}

browser.runtime.onMessage.addListener((message, sender) => {
    if (!message || !NATIVE_TYPES.has(message.type) || !sender || !sender.tab) {
        return undefined;
    }
    // A page only ever asks about itself.
    const request = { ...message, page: sender.url || "" };
    if (message.type !== "capture") {
        return native(request);
    }
    return native(request).then((reply) => {
        // A login in a frame, or one that never leaves the page, still gets its
        // prompt in the page people are looking at.
        if (reply && reply.id && (reply.action === "save" || reply.action === "update")) {
            setTimeout(() => {
                browser.tabs.sendMessage(sender.tab.id, { type: "showPending", id: reply.id }, { frameId: 0 })
                    .catch(() => {});
            }, 900);
        }
        return reply;
    });
});
