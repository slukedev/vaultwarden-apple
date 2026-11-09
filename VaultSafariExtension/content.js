"use strict";

(() => {
    if (window.__vaultwardenContentScript) {
        return;
    }
    window.__vaultwardenContentScript = true;

    const isTopFrame = window === window.top;

    // MARK: - Field hints

    // Tokens Safari already understands. A field that carries one is left alone.
    const KNOWN_TOKEN = /\b(username|email|current-password|new-password|one-time-code|webauthn|tel|name|given-name|family-name|additional-name|nickname|organization|street-address|address-line\d|address-level\d|postal-code|country|cc-[a-z-]+|bday[a-z-]*|sex|url|photo|language|transaction-[a-z]+)\b/i;
    const USERNAME_HINT = /user|login|e-?mail|account|identifier|member|customer|phone|mobile|handle|nickname/i;
    const NEW_PASSWORD_HINT = /new|create|confirm|repeat|retype|re-?enter|again|verify|choose|set[-_ ]?pass|register|signup|sign[-_ ]up/i;
    const CURRENT_PASSWORD_HINT = /current|old|existing|previous/i;
    const SIGNUP_TEXT = /sign\s?up|create (an |your )?account|register|join now|get started|new account/i;
    const OTP_HINT = /one[-_ ]?time|otp|totp|2fa|two[-_ ]?factor|mfa|multi[-_ ]?factor|verification[-_ ]?code|security[-_ ]?code|auth(entication|enticator)?[-_ ]?code|passcode|sms[-_ ]?code|confirmation[-_ ]?code|login[-_ ]?code|access[-_ ]?code|\bcode\b|\btoken\b/i;
    const NOT_OTP_HINT = /zip|postal|post[-_ ]?code|phone|tel\b|card|cvv|cvc|csc|promo|coupon|voucher|discount|gift|referral|captcha|search|country|area[-_ ]?code|invite/i;
    const TEXTUAL_TYPES = new Set(["", "text", "email", "tel", "number", "url"]);

    function attributeText(input) {
        const parts = [
            input.name,
            input.id,
            input.placeholder,
            input.getAttribute("aria-label"),
            input.getAttribute("data-testid"),
            input.className && typeof input.className === "string" ? input.className : ""
        ];
        if (input.labels) {
            for (const label of input.labels) {
                parts.push(label.textContent);
            }
        }
        const labelledBy = input.getAttribute("aria-labelledby");
        if (labelledBy) {
            for (const id of labelledBy.split(/\s+/)) {
                const element = document.getElementById(id);
                if (element) {
                    parts.push(element.textContent);
                }
            }
        }
        return parts.filter(Boolean).join(" ").slice(0, 600);
    }

    function isVisible(input) {
        if (input.disabled || input.type === "hidden") {
            return false;
        }
        const rect = input.getBoundingClientRect();
        if (rect.width < 2 || rect.height < 2) {
            return false;
        }
        const style = window.getComputedStyle(input);
        return style.visibility !== "hidden" && style.display !== "none" && Number(style.opacity) > 0.01;
    }

    function hasKnownToken(input) {
        const value = (input.getAttribute("autocomplete") || "").trim();
        return value !== "" && KNOWN_TOKEN.test(value);
    }

    function hint(input, token) {
        if (hasKnownToken(input)) {
            return;
        }
        input.setAttribute("autocomplete", token);
    }

    function isTextual(input) {
        return TEXTUAL_TYPES.has((input.getAttribute("type") || "").toLowerCase());
    }

    function scopeOf(input) {
        return input.form || input.closest("[role=form], dialog, [role=dialog]") || document.body;
    }

    function scopeText(scope) {
        const pieces = [];
        for (const element of scope.querySelectorAll("button, input[type=submit], h1, h2, h3, legend, a[role=button]")) {
            pieces.push(element.textContent || element.value || "");
            if (pieces.length > 20) {
                break;
            }
        }
        return pieces.join(" ").slice(0, 2000);
    }

    /// The visible text field just before the first password field.
    function usernameFieldBefore(password, scope) {
        let candidate = null;
        for (const input of scope.querySelectorAll("input")) {
            if (input === password) {
                break;
            }
            if (!isTextual(input) || !isVisible(input)) {
                continue;
            }
            const text = attributeText(input);
            if (OTP_HINT.test(text) && !USERNAME_HINT.test(text)) {
                continue;
            }
            if (/search/i.test(text)) {
                continue;
            }
            candidate = input;
        }
        return candidate;
    }

    function classify(scope) {
        const passwords = Array.from(scope.querySelectorAll("input[type=password]")).filter(isVisible);
        if (passwords.length === 0) {
            return null;
        }
        const texts = passwords.map(attributeText);
        let current = [];
        let fresh = [];
        if (passwords.length >= 3) {
            current = [passwords[0]];
            fresh = passwords.slice(1);
        } else if (passwords.length === 2) {
            if (CURRENT_PASSWORD_HINT.test(texts[0]) || (NEW_PASSWORD_HINT.test(texts[1]) && !NEW_PASSWORD_HINT.test(texts[0]))) {
                const firstIsCurrent = CURRENT_PASSWORD_HINT.test(texts[0]);
                current = firstIsCurrent ? [passwords[0]] : [];
                fresh = firstIsCurrent ? [passwords[1]] : passwords;
            } else {
                fresh = passwords;
            }
        } else if (NEW_PASSWORD_HINT.test(texts[0]) || SIGNUP_TEXT.test(scopeText(scope))) {
            fresh = passwords;
        } else {
            current = passwords;
        }
        return {
            current,
            fresh,
            username: usernameFieldBefore(passwords[0], scope),
            isPasswordChange: current.length > 0 && fresh.length > 0
        };
    }

    function annotate() {
        const scopes = new Set();
        for (const password of document.querySelectorAll("input[type=password]")) {
            scopes.add(scopeOf(password));
        }
        for (const scope of scopes) {
            const form = classify(scope);
            if (!form) {
                continue;
            }
            form.current.forEach((input) => hint(input, "current-password"));
            form.fresh.forEach((input) => hint(input, "new-password"));
            if (form.username) {
                hint(form.username, "username");
            }
        }

        // Identifier-first sign-in, such as an email page before the password page.
        for (const input of document.querySelectorAll("input")) {
            if (!isTextual(input) || hasKnownToken(input) || !isVisible(input)) {
                continue;
            }
            const scope = scopeOf(input);
            if (scope.querySelector("input[type=password]")) {
                continue;
            }
            const text = attributeText(input);
            const type = (input.getAttribute("type") || "").toLowerCase();
            if (OTP_HINT.test(text) && !NOT_OTP_HINT.test(text)) {
                const maxLength = Number(input.getAttribute("maxlength") || 0);
                if (maxLength === 0 || (maxLength >= 4 && maxLength <= 10) || maxLength === 1) {
                    if (maxLength === 1) {
                        // One box per digit: hint the first, the rest follow it.
                        const boxes = Array.from(scope.querySelectorAll("input[maxlength='1']")).filter(isVisible);
                        if (boxes.length >= 4 && boxes[0] === input) {
                            hint(input, "one-time-code");
                        }
                    } else {
                        hint(input, "one-time-code");
                    }
                }
                continue;
            }
            const textCount = Array.from(scope.querySelectorAll("input")).filter((other) => isTextual(other) && isVisible(other)).length;
            if (textCount === 1 && (type === "email" || USERNAME_HINT.test(text)) && !/search|subscribe|newsletter/i.test(text + " " + scopeText(scope))) {
                hint(input, "username");
            }
        }
    }

    let annotateTimer = null;
    function scheduleAnnotate() {
        if (annotateTimer !== null) {
            return;
        }
        annotateTimer = setTimeout(() => {
            annotateTimer = null;
            annotate();
        }, 250);
    }

    // MARK: - Saving new passwords (Mac)

    let capturesLogins = false;
    let lastCapture = "";

    function credentialFrom(scope) {
        const form = classify(scope);
        if (!form) {
            return null;
        }
        const field = form.fresh.find((input) => input.value) || form.current.find((input) => input.value);
        if (!field || !field.value) {
            return null;
        }
        let username = form.username ? form.username.value : "";
        if (!username) {
            // Sign-in pages often keep the identifier from the previous step in a hidden field.
            const remembered = scope.querySelector("input[autocomplete~=username], input[autocomplete~=email], input[type=email]");
            username = remembered ? remembered.value : "";
        }
        return {
            username: username.trim(),
            password: field.value,
            isPasswordChange: form.isPasswordChange
        };
    }

    function capture(scope) {
        if (!capturesLogins || !scope) {
            return;
        }
        const credential = credentialFrom(scope);
        if (!credential) {
            return;
        }
        const signature = `${credential.username}\u0000${credential.password}`;
        if (signature === lastCapture) {
            return;
        }
        lastCapture = signature;
        browser.runtime.sendMessage({ type: "capture", ...credential }).catch(() => {});
    }

    function scopeForEvent(target) {
        if (!(target instanceof Element)) {
            return null;
        }
        if (target.form) {
            return target.form;
        }
        const scope = target.closest("form, [role=form], dialog, [role=dialog]");
        if (scope && scope.querySelector("input[type=password]")) {
            return scope;
        }
        return document.querySelector("input[type=password]") ? document.body : null;
    }

    function listenForLogins() {
        document.addEventListener("submit", (event) => capture(scopeForEvent(event.target)), true);
        document.addEventListener("click", (event) => {
            const button = event.target instanceof Element
                ? event.target.closest("button, input[type=submit], input[type=button], [role=button]")
                : null;
            if (button) {
                capture(scopeForEvent(button));
            }
        }, true);
        document.addEventListener("keydown", (event) => {
            if (event.key === "Enter" && event.target instanceof HTMLInputElement) {
                capture(scopeForEvent(event.target));
            }
        }, true);
    }

    // MARK: - Save prompt (top frame)

    let banner = null;

    const ICON = `<svg viewBox="0 0 36 36" width="36" height="36" aria-hidden="true">
        <rect width="36" height="36" rx="8" fill="#1F5CE0"/>
        <path d="M18 6.5l9 3.4v6.7c0 5.9-3.8 10.6-9 12.6-5.2-2-9-6.7-9-12.6V9.9z" fill="none" stroke="#fff" stroke-width="1.9" stroke-linejoin="round"/>
        <circle cx="18" cy="15" r="3.4" fill="#fff"/>
        <path d="M16.9 17.6h2.2v6.8l-1.1 1.1-1.1-1.1v-1.2l.9-.8-.9-.8z" fill="#fff"/>
        <circle cx="18" cy="14.4" r="0.9" fill="#1F5CE0"/>
    </svg>`;

    const STYLE = `
        :host { all: initial; }
        .card {
            position: fixed; top: 12px; right: 12px; z-index: 2147483647;
            box-sizing: border-box; width: 340px; max-width: calc(100vw - 24px);
            display: grid; grid-template-columns: 36px 1fr; column-gap: 12px; row-gap: 12px;
            padding: 14px; border-radius: 16px;
            font: 13px/1.35 -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
            color: #1d1d1f; background: rgba(250, 250, 250, 0.82);
            -webkit-backdrop-filter: saturate(180%) blur(24px); backdrop-filter: saturate(180%) blur(24px);
            box-shadow: 0 0 0 0.5px rgba(0, 0, 0, 0.14), 0 12px 32px rgba(0, 0, 0, 0.18);
            animation: arrive 220ms cubic-bezier(0.2, 0.9, 0.3, 1);
        }
        .icon { width: 36px; height: 36px; align-self: start; }
        .icon svg { display: block; }
        .text { min-width: 0; align-self: center; }
        .title { font-weight: 600; }
        .detail { color: rgba(60, 60, 67, 0.72); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .actions { grid-column: 1 / -1; display: flex; justify-content: flex-end; gap: 8px; }
        button {
            font: inherit; font-weight: 500; border: 0; border-radius: 8px; padding: 5px 12px; cursor: default;
            color: #1d1d1f; background: rgba(0, 0, 0, 0.06);
        }
        button.primary { color: #fff; background: #0a7aff; }
        button:focus-visible { outline: 3px solid rgba(10, 122, 255, 0.5); outline-offset: 1px; }
        button:active { filter: brightness(0.92); }
        @media (prefers-color-scheme: dark) {
            .card { color: #f5f5f7; background: rgba(40, 40, 42, 0.82); box-shadow: 0 0 0 0.5px rgba(255, 255, 255, 0.16), 0 12px 32px rgba(0, 0, 0, 0.45); }
            .detail { color: rgba(235, 235, 245, 0.62); }
            button { color: #f5f5f7; background: rgba(255, 255, 255, 0.12); }
        }
        @media (prefers-reduced-motion: reduce) { .card { animation: fade 160ms ease-out; } }
        @keyframes arrive { from { opacity: 0; transform: translateY(-8px) scale(0.98); } to { opacity: 1; transform: none; } }
        @keyframes fade { from { opacity: 0; } to { opacity: 1; } }
    `;

    function removeBanner() {
        if (banner) {
            banner.host.remove();
            banner = null;
        }
    }

    function showBanner(pending) {
        if (!pending || !pending.id || (banner && banner.id === pending.id)) {
            return;
        }
        removeBanner();
        const host = document.createElement("vaultwarden-save-prompt");
        const root = host.attachShadow({ mode: "closed" });
        const isUpdate = pending.action === "update";

        const style = document.createElement("style");
        style.textContent = STYLE;
        const card = document.createElement("div");
        card.className = "card";
        card.setAttribute("role", "alertdialog");
        card.setAttribute("aria-labelledby", "title");

        const icon = document.createElement("div");
        icon.className = "icon";
        icon.innerHTML = ICON;
        const text = document.createElement("div");
        text.className = "text";
        const title = document.createElement("div");
        title.className = "title";
        title.id = "title";
        title.textContent = isUpdate
            ? `Update password for ${pending.host}?`
            : `Save password for ${pending.host}?`;
        text.append(title);
        if (pending.username) {
            const detail = document.createElement("div");
            detail.className = "detail";
            detail.textContent = pending.username;
            text.append(detail);
        }

        const actions = document.createElement("div");
        actions.className = "actions";
        const notNow = document.createElement("button");
        notNow.textContent = "Not Now";
        const save = document.createElement("button");
        save.className = "primary";
        save.textContent = isUpdate ? "Update Password" : "Save Password";
        actions.append(notNow, save);

        notNow.addEventListener("click", () => {
            browser.runtime.sendMessage({ type: "dismiss", id: pending.id }).catch(() => {});
            removeBanner();
        });
        save.addEventListener("click", () => {
            browser.runtime.sendMessage({ type: "save", id: pending.id }).catch(() => {});
            removeBanner();
        });
        card.addEventListener("keydown", (event) => {
            if (event.key === "Escape") {
                notNow.click();
            }
        });

        card.append(icon, text, actions);
        root.append(style, card);
        (document.body || document.documentElement).append(host);
        banner = { id: pending.id, host };
    }

    function askForPending(id) {
        browser.runtime.sendMessage(id ? { type: "pending", id } : { type: "pending" })
            .then((pending) => showBanner(pending))
            .catch(() => {});
    }

    // MARK: - Popup requests

    function loginField() {
        for (const password of document.querySelectorAll("input[type=password]")) {
            if (!isVisible(password)) {
                continue;
            }
            const form = classify(scopeOf(password));
            if (form && form.username && !form.username.value) {
                return form.username;
            }
            return password;
        }
        for (const input of document.querySelectorAll("input[autocomplete~=username]")) {
            if (isVisible(input)) {
                return input;
            }
        }
        return null;
    }

    browser.runtime.onMessage.addListener((message) => {
        if (!message) {
            return undefined;
        }
        if (message.type === "showPending" && isTopFrame) {
            askForPending(message.id);
            return undefined;
        }
        if (!isTopFrame) {
            return undefined;
        }
        if (message.type === "probe") {
            return Promise.resolve({ hasLoginField: loginField() !== null });
        }
        if (message.type === "focusLogin") {
            const field = loginField();
            if (field) {
                field.scrollIntoView({ block: "center", behavior: "smooth" });
                field.focus({ preventScroll: true });
            }
            return Promise.resolve({ focused: field !== null });
        }
        return undefined;
    });

    // MARK: - Start

    annotate();
    new MutationObserver(scheduleAnnotate).observe(document.documentElement, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["type", "hidden"]
    });
    // Fields revealed by a class or style change are caught when they're first used.
    document.addEventListener("focusin", (event) => {
        if (event.target instanceof HTMLInputElement) {
            scheduleAnnotate();
        }
    }, true);

    browser.runtime.sendMessage({ type: "config" }).then((config) => {
        capturesLogins = Boolean(config && config.capturesLogins);
        if (capturesLogins) {
            listenForLogins();
            if (isTopFrame) {
                askForPending();
            }
        }
    }).catch(() => {});
})();
