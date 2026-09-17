//
//  ForkFilenameEncodingTests.swift
//  PerfectSMTPCoreTests
//
//  Fork: non-ASCII attachment names used to go into the headers as raw
//  UTF-8. They are now RFC 2047-encoded in `name`/`filename` (what Swift-SMTP
//  sent) plus RFC 2231 `filename*`; ASCII names are unchanged.
//

import Foundation
import Testing
@testable import PerfectSMTPCore

struct ForkFilenameEncodingTests {

    private func composedBody(attachmentNamed filename: String) throws -> String {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hi"
        message.attachments = [Attachment(filename: filename, contentType: "application/pdf", data: Data("pdf".utf8))]
        return String(decoding: try MIMEComposer(message).compose().body, as: UTF8.self)
    }

    @Test func asciiNamesAreEmittedExactlyAsBefore() throws {
        let body = try composedBody(attachmentNamed: "report 2026.pdf")
        #expect(body.contains("Content-Type: application/pdf; name=\"report 2026.pdf\"\r\n"))
        #expect(body.contains("Content-Disposition: attachment; filename=\"report 2026.pdf\"\r\n"))
        #expect(!body.contains("filename*"))
    }

    @Test func accentedNamesAreEncodedInsteadOfSentAsRawUTF8() throws {
        let name = "Compte-rendu d'activité.pdf"
        let body = try composedBody(attachmentNamed: name)
        let encodedWord = "=?utf-8?B?\(Data(name.utf8).base64EncodedString())?="

        #expect(body.contains("Content-Type: application/pdf; name=\"\(encodedWord)\"\r\n"))
        #expect(body.contains(
            "Content-Disposition: attachment; filename=\"\(encodedWord)\"; filename*=utf-8''Compte-rendu%20d%27activit%C3%A9.pdf\r\n"
        ))
        // Every header line is 7-bit clean.
        let headerBytes = body.split(separator: "\r\n", omittingEmptySubsequences: false)
            .filter { $0.hasPrefix("Content-") }
            .flatMap { $0.utf8 }
        #expect(headerBytes.allSatisfy { $0 < 0x80 })
    }

    @Test func encodedNamesDecodeBackToTheOriginal() throws {
        let name = "Déclaration de frais — mission n°12 🛩.pdf"
        let body = try composedBody(attachmentNamed: name)
        let base64 = try #require(body.firstMatch(of: /filename="=\?utf-8\?B\?([A-Za-z0-9+\/=]+)\?="/)?.1)
        #expect(Data(base64Encoded: String(base64)).map { String(decoding: $0, as: UTF8.self) } == name)
    }

    @Test func coreErrorsHaveReadableDescriptions() {
        #expect(MIMEComposer.ComposerError.missingBody.localizedDescription == "The message has no text or HTML body.")
        #expect(
            HeaderEncoder.HeaderInjectionError.controlCharacterInField("RCPT TO address").localizedDescription
                == "The RCPT TO address contains a control character (such as a line break)."
        )
    }
}
