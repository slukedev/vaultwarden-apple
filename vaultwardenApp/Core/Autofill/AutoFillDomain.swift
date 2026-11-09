import Foundation

/// Website and app identity rules shared by the app, the AutoFill extension and the
/// Safari extension. Has no SDK dependency so every target can compile it.
nonisolated enum AutoFillDomain {
    /// Schemes Bitwarden clients use for native apps instead of websites.
    static let appSchemes: Set<String> = ["iosapp", "androidapp", "macapp"]

    /// The lowercased host of a URI, with or without a scheme. Nil for app URIs.
    static func host(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, appIdentifier(trimmed) == nil else { return nil }
        let candidate = trimmed.contains("://") ? trimmed : "https://\(trimmed)"
        guard let host = URLComponents(string: candidate)?.host?.lowercased()
            .trimmingCharacters(in: CharacterSet(charactersIn: ".")),
              !host.isEmpty else { return nil }
        return host
    }

    /// The bundle identifier in an `iosapp://`, `androidapp://` or `macapp://` URI.
    static func appIdentifier(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let range = trimmed.range(of: "://") else { return nil }
        let scheme = trimmed[..<range.lowerBound].lowercased()
        guard appSchemes.contains(scheme) else { return nil }
        let identifier = trimmed[range.upperBound...]
            .split(separator: "/", maxSplits: 1, omittingEmptySubsequences: true)
            .first.map(String.init)?
            .lowercased()
        return identifier?.isEmpty == false ? identifier : nil
    }

    /// Turns a system App ID ("TEAMID1234.com.example.app") into the URI the vault
    /// stores for it ("iosapp://com.example.app").
    static func appURI(fromAppID appID: String) -> String? {
        let trimmed = appID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let parts = trimmed.split(separator: ".", maxSplits: 1)
        var bundle = trimmed
        if parts.count == 2, isTeamIdentifier(parts[0]) {
            bundle = String(parts[1])
        }
        return "iosapp://\(bundle.lowercased())"
    }

    private static func isTeamIdentifier(_ value: Substring) -> Bool {
        value.count == 10 && value.allSatisfy { $0.isASCII && ($0.isUppercase || $0.isNumber) }
    }

    static func isIPAddress(_ host: String) -> Bool {
        if host.contains(":") { return true }
        let components = host.split(separator: ".", omittingEmptySubsequences: false)
        return components.count == 4 && components.allSatisfy {
            guard let number = Int($0) else { return false }
            return (0...255).contains(number)
        }
    }

    /// The part of a host one owner controls, the way browsers scope cookies:
    /// "accounts.google.com" is "google.com", "alice.github.io" stays "alice.github.io".
    static func registrableDomain(_ host: String) -> String {
        let host = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        if isIPAddress(host) { return host }
        let labels = host.split(separator: ".").map(String.init)
        guard labels.count > 1 else { return host }
        // Longest public suffix first, so "co.uk" wins over "uk".
        for length in stride(from: min(labels.count, 4), through: 2, by: -1) {
            let suffix = labels.suffix(length).joined(separator: ".")
            if publicSuffixes.contains(suffix) {
                return labels.count > length
                    ? labels.suffix(length + 1).joined(separator: ".")
                    : host
            }
        }
        return labels.suffix(2).joined(separator: ".")
    }

    /// Multi-label suffixes under which unrelated people register names. Single-label
    /// TLDs need no entry. Includes hosting platforms, so one person's site never
    /// offers another person's password.
    static let publicSuffixes: Set<String> = [
        // Country second levels
        "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "nhs.uk", "org.uk", "plc.uk", "sch.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "asn.au",
        "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ed.jp", "gr.jp", "lg.jp",
        "co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr", "re.kr",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
        "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk",
        "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw", "idv.tw",
        "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
        "com.my", "net.my", "org.my", "edu.my", "gov.my",
        "co.id", "ac.id", "go.id", "or.id", "sch.id", "web.id", "my.id", "net.id", "biz.id",
        "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in", "ac.in", "edu.in", "gov.in", "res.in",
        "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
        "co.th", "in.th", "ac.th", "go.th", "or.th",
        "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn",
        "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk",
        "com.bd", "net.bd", "org.bd",
        "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br", "blog.br",
        "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx",
        "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
        "com.co", "net.co", "org.co", "gov.co", "edu.co",
        "com.pe", "net.pe", "org.pe", "gob.pe",
        "com.uy", "com.ve", "com.ec", "com.bo", "com.py", "cl.cl",
        "co.za", "org.za", "net.za", "gov.za", "ac.za", "web.za",
        "com.ng", "org.ng", "gov.ng", "edu.ng",
        "co.ke", "or.ke", "ac.ke", "go.ke",
        "com.eg", "gov.eg", "edu.eg",
        "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "gen.tr", "web.tr",
        "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa",
        "co.il", "org.il", "net.il", "ac.il", "gov.il",
        "com.ua", "net.ua", "org.ua", "kiev.ua", "in.ua",
        "com.ru", "net.ru", "org.ru", "msk.ru", "spb.ru",
        "com.pl", "net.pl", "org.pl", "waw.pl", "gov.pl",
        "co.at", "or.at", "gv.at", "ac.at",
        "com.es", "nom.es", "org.es", "gob.es", "edu.es",
        "com.pt", "org.pt", "gov.pt", "edu.pt",
        "com.gr", "org.gr", "gov.gr", "edu.gr",
        "com.cy", "com.mt", "co.hu", "co.rs", "co.me", "com.de",
        "gouv.fr", "asso.fr", "nom.fr", "com.fr",
        "co.it", "gov.it", "edu.it",
        "co.ve", "com.ge", "com.kz", "com.az", "com.lb", "com.jo", "com.kw", "com.qa", "com.om", "com.bh",
        "co.ae", "ae.org", "com.ae", "net.ae", "gov.ae",
        "us.com", "uk.com", "eu.com", "de.com", "br.com", "cn.com", "jpn.com", "co.com",
        "us.org", "uk.net", "gb.net", "se.net",
        // Hosting and developer platforms
        "github.io", "githubusercontent.com", "gitlab.io", "bitbucket.io", "codeberg.page",
        "pages.dev", "workers.dev", "r2.dev", "netlify.app", "netlify.com", "vercel.app", "now.sh",
        "herokuapp.com", "herokussl.com", "fly.dev", "onrender.com", "railway.app", "up.railway.app",
        "web.app", "firebaseapp.com", "appspot.com", "cloudfunctions.net", "run.app",
        "azurewebsites.net", "azurestaticapps.net", "cloudapp.net", "trafficmanager.net", "blob.core.windows.net",
        "cloudfront.net", "amazonaws.com", "elasticbeanstalk.com", "s3.amazonaws.com", "awsapprunner.com",
        "blogspot.com", "wordpress.com", "tumblr.com", "wixsite.com", "weebly.com", "squarespace.com",
        "myshopify.com", "webflow.io", "framer.app", "framer.website", "notion.site", "carrd.co",
        "glitch.me", "repl.co", "replit.dev", "replit.app", "surge.sh", "deno.dev", "ngrok.io", "ngrok-free.app",
        "ngrok.app", "loca.lt", "trycloudflare.com", "duckdns.org", "dyndns.org", "no-ip.org", "ddns.net",
        "synology.me", "myqnapcloud.com", "tailscale.net", "ts.net", "plex.direct", "home-assistant.io",
        "ui.nabu.casa", "readthedocs.io", "gitbook.io", "hf.space", "streamlit.app", "dev.to",
        "azure-api.net", "digitaloceanspaces.com", "ondigitalocean.app", "pythonanywhere.com", "fastly.net"
    ]
}
