//
//  ErrorDescriptions.swift
//  PerfectSMTP
//
//  Fork addition: `LocalizedError` descriptions for the transport layer's
//  own error types — see the matching file in PerfectSMTPCore.
//

import Foundation

extension SMTPConnectionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .channelClosedByPeer:
            return "The SMTP server closed the connection unexpectedly."
        case .malformedSASLChallenge:
            return "The SMTP server sent an invalid authentication challenge."
        case .replyTimedOut:
            return "The SMTP server did not respond in time."
        }
    }
}

extension SMTPConnectionPool.PoolError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .shutdown:
            return "The mail transport has been shut down."
        }
    }
}

extension SMTPResponseDecoder.DecoderError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .malformedReplyLine:
            return "The SMTP server sent a malformed reply."
        case .codeMismatchInMultiline(let expected, let got):
            return "The SMTP server sent an inconsistent multiline reply (\(expected) then \(got))."
        case .residualBytesOnRemoval:
            return "The SMTP server sent unexpected data during the STARTTLS upgrade; the connection was closed."
        case .tooManyContinuationLines(let limit):
            return "The SMTP server sent a reply longer than \(limit) lines."
        }
    }
}

extension MTASTSPolicyBodyTooLarge: LocalizedError {
    public var errorDescription: String? {
        "The MTA-STS policy is larger than \(limit) bytes."
    }
}
