//
//  ErrorDescriptions.swift
//  PerfectSMTPCore
//
//  Fork addition: human-readable `LocalizedError` descriptions. Upstream
//  errors had none, so an app surfacing `error.localizedDescription` — as a
//  send-failure alert does — showed "The operation couldn't be completed.
//  (PerfectSMTPCore.SMTPError error 5.)". Descriptions carry the server's
//  reply, never anything the client sent (no credentials, no AUTH lines).
//

import Foundation

extension SMTPReply {
    /// `535 5.7.8 Authentication credentials invalid` — the reply as the
    /// server sent it, multiline replies joined on one line.
    var descriptionForError: String {
        lines.isEmpty ? "\(code)" : "\(code) \(lines.joined(separator: " "))"
    }
}

func describeUnderlying(_ error: any Error) -> String {
    (error as? LocalizedError)?.errorDescription ?? String(describing: error)
}

extension SMTPError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .transientFailure(let reply):
            return "The SMTP server temporarily refused the request: \(reply.descriptionForError)"
        case .serviceUnavailable(let reply):
            return "The SMTP server is unavailable and closed the connection: \(reply.descriptionForError)"
        case .permanentFailure(let reply):
            return "The SMTP server refused the request: \(reply.descriptionForError)"
        case .greylisted(let reply):
            return "The SMTP server deferred the message, try again later: \(reply.descriptionForError)"
        case .sizeExceeded(let limit):
            return limit > 0
                ? "The message exceeds the server's size limit of \(limit) bytes."
                : "The message exceeds the server's size limit."
        case .authenticationFailed(let reply):
            return "SMTP authentication failed: \(reply.descriptionForError)"
        case .starttlsRequired:
            return "The SMTP server does not offer STARTTLS, and an encrypted connection is required."
        case .starttlsInjection(let underlying):
            if let underlying {
                return "The TLS handshake with the SMTP server failed: \(describeUnderlying(underlying))"
            }
            return "The SMTP server sent unexpected data during the STARTTLS upgrade; the connection was closed."
        case .tlsPolicyViolation(let detail):
            return "The destination's TLS policy was not satisfied: \(detail)"
        case .circuitOpen:
            return "Too many consecutive failures with this SMTP server; sending is paused briefly."
        case .connectionFailed(let underlying):
            return "The connection to the SMTP server failed: \(describeUnderlying(underlying))"
        case .ambiguousDelivery(let reply):
            let detail = reply.map { ": \($0.descriptionForError)" } ?? "."
            return "The connection was lost after the message was sent; it may or may not have been delivered\(detail)"
        }
    }
}

extension HeaderEncoder.HeaderInjectionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .controlCharacterInField(let field):
            return "The \(field) contains a control character (such as a line break)."
        case .leadingHyphenInField(let field):
            return "The \(field) must not start with a hyphen."
        }
    }
}

extension MIMEComposer.ComposerError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .missingBody:
            return "The message has no text or HTML body."
        case .forbiddenHeader(let name):
            return "The header \(name) is managed by the library and cannot be set as an extra header."
        case .invalidHeaderValue(let field):
            return "The value of \(field) contains a control character (such as a line break)."
        case .postOneClickRequiresURL:
            return "One-click unsubscribe requires an HTTPS unsubscribe URL."
        case .listUnsubscribeURLMustBeHTTPS:
            return "The unsubscribe URL must use HTTPS."
        case .listUnsubscribeValueContainsDelimiterCharacter(let value):
            return "The unsubscribe value contains a forbidden delimiter character: \(value)"
        case .bodyOverrideRequiresSingleBodyPart:
            return "A body content-type or transfer-encoding override requires exactly one of the text or HTML bodies."
        case .sevenBitOverrideRequiresValidSevenBitBody:
            return "The body is not valid 7-bit text, so it cannot be sent with a 7bit transfer encoding."
        case .bodyContentTypeOverrideCharsetMustBeUTF8:
            return "A body content-type override must declare the UTF-8 charset."
        }
    }
}
