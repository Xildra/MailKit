//
//  SASLMechanism.swift
//  PerfectSMTP
//
//  AUTH abstraction (plan §4.5). `SASLPlain`/`SASLLogin` are the workhorses
//  (SendGrid/Postmark/SES issue API keys as SMTP passwords); `XOAuth2` is
//  first-class and mandatory-in-practice for Gmail/Workspace (legacy SMTP
//  password auth disabled since March 2025) and Microsoft 365 (Basic-auth
//  SMTP being phased out through 2027). `SASLScramSHA256` is deliberately
//  not implemented — deferred per plan §4.5/§10.
//
//  Fork: `SASLCramMD5` and `SASLPasswordNegotiation` restore what Swift-SMTP
//  did out of the box — pick the password mechanism from the server's own
//  `AUTH` list — for servers that only offer LOGIN or CRAM-MD5 (Exchange
//  on-premises advertises `AUTH NTLM LOGIN`, no PLAIN).
//

import Crypto
import Foundation

/// A SASL mechanism's message-exchange state machine, driven by
/// `SMTPConnection.authenticate(_:)` during `AUTH`. Implement this to add a
/// mechanism beyond the three built-in ones (`SASLPlain`/`SASLLogin`/
/// `XOAuth2`); `SMTPConnection` calls these methods in a fixed order and
/// doesn't need to know which concrete mechanism it's driving.
///
/// Exchange shape: `initialResponse()` is called exactly once, before the
/// first `AUTH <name>` command is even sent -- returning non-`nil` sends it
/// as the (optional, RFC 4954) inline initial-response argument on that same
/// command line; returning `nil` (as `SASLLogin` does) sends a bare
/// `AUTH <name>` with no inline argument, and the server's first `334`
/// challenge is handled by `respond(to:)` instead. After that,
/// `SMTPConnection.authenticate(_:)`'s exchange loop calls `respond(to:)`
/// once per `334` continuation reply the server sends, purely driven by the
/// server's own reply codes -- it stops once the server issues a final,
/// non-`334` reply (`235` success or a `5xx`/`4xx` failure), not by
/// consulting `isComplete`.
public protocol SASLMechanism: Sendable {
    /// The `AUTH` command's mechanism name (e.g. `"PLAIN"`, `"LOGIN"`,
    /// `"XOAUTH2"`), sent verbatim as `AUTH <name>`.
    var name: String { get }
    /// The RFC 4954 inline initial response, sent base64-encoded on the same
    /// line as `AUTH <name>` when non-`nil`. Return `nil` for a mechanism
    /// that has nothing to say before seeing the server's first challenge
    /// (e.g. `SASLLogin`).
    mutating func initialResponse() async throws -> [UInt8]?
    /// Computes this mechanism's response to one base64-decoded `334`
    /// challenge from the server. May be `async`-suspending (`XOAuth2` uses
    /// this to `await` its `tokenProvider` closure).
    mutating func respond(to challenge: [UInt8]) async throws -> [UInt8]
    /// Whether this mechanism considers its own step sequence finished.
    /// Exposed for the mechanism's own bookkeeping/introspection --
    /// `SMTPConnection.authenticate(_:)`'s exchange loop does not currently
    /// consult this property itself; it terminates purely on the server's
    /// reply code (see this protocol's own doc comment).
    var isComplete: Bool { get }
}

/// RFC 4616. `authzid` is almost always empty for SMTP AUTH (the
/// authentication identity and authorization identity are the same
/// mailbox); exposed for completeness.
public struct SASLPlain: SASLMechanism {
    public let name = "PLAIN"
    public let authzid: String
    public let username: String
    public let password: String
    private var sentInitial = false

    public init(authzid: String = "", username: String, password: String) {
        self.authzid = authzid
        self.username = username
        self.password = password
    }

    public mutating func initialResponse() async throws -> [UInt8]? {
        sentInitial = true
        var bytes: [UInt8] = []
        bytes.append(contentsOf: Array(authzid.utf8))
        bytes.append(0)
        bytes.append(contentsOf: Array(username.utf8))
        bytes.append(0)
        bytes.append(contentsOf: Array(password.utf8))
        return bytes
    }

    public mutating func respond(to challenge: [UInt8]) async throws -> [UInt8] {
        // PLAIN's whole exchange is the initial response; a server that
        // still issues a mid-exchange continuation gets an empty reply.
        []
    }

    public var isComplete: Bool { sentInitial }
}

/// RFC 4954's `AUTH LOGIN` (a de facto standard, not itself an RFC-defined
/// SASL mechanism, but universally supported). No initial response; the
/// server issues two base64 `334` challenges ("Username:" then
/// "Password:") in order.
public struct SASLLogin: SASLMechanism {
    public let name = "LOGIN"
    public let username: String
    public let password: String
    private var step = 0

    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }

    public mutating func initialResponse() async throws -> [UInt8]? { nil }

    public mutating func respond(to challenge: [UInt8]) async throws -> [UInt8] {
        step += 1
        return step == 1 ? Array(username.utf8) : Array(password.utf8)
    }

    public var isComplete: Bool { step >= 2 }
}

/// RFC 7628 XOAUTH2/OAUTHBEARER framing:
/// `user=<username>\x01auth=Bearer <token>\x01\x01`. The library only
/// formats this framing and invokes the caller-supplied `tokenProvider` —
/// it does not itself run an OAuth2 authorization flow. On a `535`, the
/// connection-level `authenticate(_:)` calls `tokenProvider()` again and
/// retries the whole exchange once (plan §4.5) before surfacing
/// `SMTPError.authenticationFailed`.
public struct XOAuth2: SASLMechanism {
    public let name = "XOAUTH2"
    public let username: String
    public let tokenProvider: @Sendable () async throws -> String
    private var sentInitial = false

    public init(username: String, tokenProvider: @escaping @Sendable () async throws -> String) {
        self.username = username
        self.tokenProvider = tokenProvider
    }

    public mutating func initialResponse() async throws -> [UInt8]? {
        sentInitial = true
        let token = try await tokenProvider()
        let framed = "user=\(username)\u{1}auth=Bearer \(token)\u{1}\u{1}"
        return Array(framed.utf8)
    }

    public mutating func respond(to challenge: [UInt8]) async throws -> [UInt8] {
        // A `334` here is Google's XOAUTH2 error-detail continuation (a
        // base64 JSON error object); RFC 7628 §3.2.3 requires responding
        // with an empty message so the server then returns its real 5xx,
        // which `authenticate(_:)`'s exchange loop classifies normally.
        []
    }

    public var isComplete: Bool { sentInitial }
}

/// RFC 2195 CRAM-MD5. No initial response; the server's single `334`
/// challenge is answered with `username SP hex(HMAC-MD5(password, challenge))`.
///
/// Fork addition, for parity with Swift-SMTP. MD5 is weak and the server
/// must keep a plaintext-equivalent secret, so prefer PLAIN or LOGIN over
/// TLS; this exists for servers that offer nothing else, and is only ever
/// chosen by `SASLPasswordNegotiation` when the server lists it first.
public struct SASLCramMD5: SASLMechanism {
    public let name = "CRAM-MD5"
    public let username: String
    public let password: String
    private var answered = false

    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }

    public mutating func initialResponse() async throws -> [UInt8]? { nil }

    public mutating func respond(to challenge: [UInt8]) async throws -> [UInt8] {
        answered = true
        let key = SymmetricKey(data: Array(password.utf8))
        let digest = HMAC<Insecure.MD5>.authenticationCode(for: challenge, using: key)
        let hex = digest.map { byte in
            let value = String(byte, radix: 16)
            return value.count == 1 ? "0" + value : value
        }.joined()
        return Array("\(username) \(hex)".utf8)
    }

    public var isComplete: Bool { answered }
}

/// Picks a password mechanism from the `AUTH` mechanisms a server advertised,
/// the way Swift-SMTP did: the **first** one, in the server's own order, that
/// this library can drive. Used by `RelayConfig.Auth.automatic`.
///
/// Fork addition. Deliberately:
/// - token mechanisms (`XOAUTH2`, `OAUTHBEARER`) are never picked — a password
///   is not a bearer token, and Swift-SMTP's default list did send it as one
///   when a server happened to advertise `XOAUTH2` first;
/// - there is no fallback to the next mechanism after a rejection: every
///   failed attempt counts against directory lockout policies (Active
///   Directory locks accounts after a few), so one attempt per connection;
/// - nothing about the credentials is validated or rejected. The only
///   adjustment is skipping `PLAIN` when either value contains a NUL byte,
///   which PLAIN's NUL-separated framing cannot carry — LOGIN and CRAM-MD5
///   can.
public enum SASLPasswordNegotiation {
    public static func mechanism(
        username: String,
        password: String,
        advertised: [String]
    ) throws -> any SASLMechanism {
        for name in advertised {
            switch name.uppercased() {
            case "PLAIN":
                if username.utf8.contains(0) || password.utf8.contains(0) { continue }
                return SASLPlain(username: username, password: password)
            case "LOGIN":
                return SASLLogin(username: username, password: password)
            case "CRAM-MD5":
                return SASLCramMD5(username: username, password: password)
            default:
                continue
            }
        }
        let offered = advertised.isEmpty ? "no AUTH extension" : advertised.joined(separator: " ")
        throw SMTPError.authenticationFailed(
            SMTPReply(code: 504, lines: ["No supported password AUTH mechanism (server offers: \(offered))"])
        )
    }
}
