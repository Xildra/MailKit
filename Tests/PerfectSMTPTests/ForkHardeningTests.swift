//
//  ForkHardeningTests.swift
//  PerfectSMTPTests
//
//  Regression tests for the fork's changes to the transport layer:
//  password-mechanism negotiation (and the promise not to reject any
//  credential), CRAM-MD5, the SASL round bound, resetting abandoned
//  transactions before a connection is pooled again, the TLS 1.2 floor,
//  the MTA-STS body cap, and readable error descriptions.
//

import Foundation
import NIOCore
import NIOEmbedded
import NIOPosix
import NIOSSL
import Testing
@testable import PerfectSMTP

struct PasswordNegotiationTests {

    @Test func picksTheFirstSupportedMechanismInTheServersOrder() throws {
        let exchange = try SASLPasswordNegotiation.mechanism(username: "u", password: "p", advertised: ["NTLM", "LOGIN"])
        #expect(exchange is SASLLogin)

        let cram = try SASLPasswordNegotiation.mechanism(username: "u", password: "p", advertised: ["CRAM-MD5", "LOGIN", "PLAIN"])
        #expect(cram is SASLCramMD5)

        let plain = try SASLPasswordNegotiation.mechanism(username: "u", password: "p", advertised: ["PLAIN", "LOGIN"])
        #expect(plain is SASLPlain)
    }

    /// Swift-SMTP sent the password as an XOAUTH2 bearer token when a server
    /// listed XOAUTH2 first.
    @Test func neverSendsAPasswordThroughATokenMechanism() throws {
        let mechanism = try SASLPasswordNegotiation.mechanism(
            username: "u", password: "p", advertised: ["XOAUTH2", "OAUTHBEARER", "PLAIN"]
        )
        #expect(mechanism is SASLPlain)
    }

    @Test func noUsableMechanismFailsBeforeAnythingIsSent() {
        for advertised in [[], ["GSSAPI", "NTLM"], ["XOAUTH2"]] {
            #expect(throws: SMTPError.self) {
                try SASLPasswordNegotiation.mechanism(username: "u", password: "p", advertised: advertised)
            }
        }
    }

    @Test func plainIsSkippedOnlyWhenACredentialContainsNUL() throws {
        let mechanism = try SASLPasswordNegotiation.mechanism(
            username: "user", password: "a\u{0}b", advertised: ["PLAIN", "LOGIN"]
        )
        #expect(mechanism is SASLLogin)
    }

    /// The credentials an app stores must reach the server byte for byte:
    /// domain-qualified logins, spaces, quotes, backslashes, accents, emoji.
    @Test func credentialsAreNeverRejectedOrAltered() async throws {
        let username = "CORP\\first.last@example.com"
        let password = "pâss wörd \"'\\%€;:<>🔑"

        var plain = try SASLPasswordNegotiation.mechanism(username: username, password: password, advertised: ["PLAIN"])
        let plainResponse = try await plain.initialResponse()
        #expect(plainResponse == [0] + Array(username.utf8) + [0] + Array(password.utf8))

        var login = try SASLPasswordNegotiation.mechanism(username: username, password: password, advertised: ["LOGIN"])
        #expect(try await login.respond(to: Array("Username:".utf8)) == Array(username.utf8))
        #expect(try await login.respond(to: Array("Password:".utf8)) == Array(password.utf8))
    }

    /// RFC 2195 §2's worked example.
    @Test func cramMD5MatchesTheRFC2195Example() async throws {
        var mechanism = SASLCramMD5(username: "tim", password: "tanstaaftanstaaf")
        #expect(try await mechanism.initialResponse() == nil)
        let response = try await mechanism.respond(to: Array("<1896.697170952@postoffice.reston.mci.net>".utf8))
        #expect(String(decoding: response, as: UTF8.self) == "tim b913a602c7eda7a495b4e6e7334d3890")
        #expect(mechanism.isComplete)
    }

    @Test func automaticAuthNegotiatesAgainstALoginOnlyServer() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await negotiate(connection, channel, ["250-exchange.example.com", "250 AUTH NTLM LOGIN"])

        let config = RelayConfig(host: "exchange.example.com", port: 587, tls: .startTLS,
                                 auth: .automatic(username: "user", password: "secret"))
        let mechanism = try #require(try config.mechanism(advertised: connection.capabilities.authMechanisms))

        let task = Task { try await connection.authenticate(mechanism) }
        #expect(try await expectClientLine(channel) == "AUTH LOGIN")
        try await serverSend(channel, "334 " + Data("Username:".utf8).base64EncodedString())
        #expect(Data(base64Encoded: try await expectClientLine(channel)) == Data("user".utf8))
        try await serverSend(channel, "334 " + Data("Password:".utf8).base64EncodedString())
        #expect(Data(base64Encoded: try await expectClientLine(channel)) == Data("secret".utf8))
        try await serverSend(channel, "235 2.7.0 Authentication successful")
        try await task.value
        #expect(connection.isAuthenticated)
    }

    @Test func explicitMechanismsKeepTheirUpstreamBehavior() throws {
        let config = RelayConfig(host: "h", port: 587, tls: .startTLS, auth: .plain(username: "u", password: "p"))
        // Not consulted for explicit cases: PLAIN is returned even though the
        // server offers only LOGIN, and `authenticate` then refuses it.
        #expect(try config.mechanism(advertised: ["LOGIN"]) is SASLPlain)
    }
}

struct SASLRoundBoundTests {

    @Test func aServerAnswering334ForeverIsCutOff() async throws {
        let (connection, channel) = try await ConnectionHarness.make(replyTimeout: 5)
        try await negotiate(connection, channel, ["250-smtp.example.com", "250 AUTH LOGIN"])

        let task = Task { try await connection.authenticate(SASLLogin(username: "u", password: "p")) }
        let challenge = "334 " + Data("Password:".utf8).base64EncodedString()
        // `AUTH LOGIN` plus one response per allowed round.
        for _ in 0...SMTPConnection.maximumSASLRounds {
            _ = try await expectClientLine(channel)
            try await serverSend(channel, challenge)
        }
        await #expect(throws: SMTPError.self) { try await task.value }
        #expect(!connection.isAuthenticated)
    }
}

struct AbandonedTransactionTests {

    private let message = SignedMessage(rfc5322: Array("Subject: hi\r\n\r\nbody".utf8))

    @Test func lockStepWithNoAcceptedRecipientResetsTheTransaction() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await connectedForLivenessChecks(channel)
        try await negotiate(connection, channel, ["250-smtp.example.com", "250 8BITMIME"])
        let envelope = try SMTPEnvelope(mailFrom: .address("from@example.com"), recipients: ["bad@example.com"])

        let task = Task { try await connection.sendMessage(envelope, message) }
        #expect(try await expectClientLine(channel) == "MAIL FROM:<from@example.com>")
        try await serverSend(channel, "250 2.1.0 OK")
        #expect(try await expectClientLine(channel) == "RCPT TO:<bad@example.com>")
        try await serverSend(channel, "550 5.1.1 User unknown")
        #expect(try await expectClientLine(channel) == "RSET")
        try await serverSend(channel, "250 2.0.0 OK")

        let results = try await task.value
        guard case .permanentlyFailed = results[0].outcome else {
            Issue.record("expected permanentlyFailed, got \(results[0].outcome)")
            return
        }
        #expect(connection.channel.isActive)
        try await channel.close()
    }

    @Test func lockStepWithDATARefusedResetsTheTransaction() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await negotiate(connection, channel, ["250-smtp.example.com", "250 8BITMIME"])
        let envelope = try SMTPEnvelope(mailFrom: .address("from@example.com"), recipients: ["a@example.com"])

        let task = Task { try await connection.sendMessage(envelope, message) }
        _ = try await expectClientLine(channel) // MAIL
        try await serverSend(channel, "250 2.1.0 OK")
        _ = try await expectClientLine(channel) // RCPT
        try await serverSend(channel, "250 2.1.5 OK")
        #expect(try await expectClientLine(channel) == "DATA")
        try await serverSend(channel, "554 5.7.1 Relay refused")
        #expect(try await expectClientLine(channel) == "RSET")
        try await serverSend(channel, "250 2.0.0 OK")

        let results = try await task.value
        guard case .permanentlyFailed = results[0].outcome else {
            Issue.record("expected permanentlyFailed, got \(results[0].outcome)")
            return
        }
    }

    /// The desync upstream left behind: DATA answered 354 with every RCPT
    /// refused, connection pooled in DATA mode.
    @Test func pipelinedDATAAcceptedWithoutRecipientsIsTerminatedThenReset() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await connectedForLivenessChecks(channel)
        try await negotiate(connection, channel, ["250-smtp.example.com", "250 PIPELINING"])
        let envelope = try SMTPEnvelope(mailFrom: .address("from@example.com"), recipients: ["bad@example.com"])
        let secret = SignedMessage(rfc5322: Array("Subject: hi\r\n\r\nSECRET BODY".utf8))

        let task = Task { try await connection.sendMessage(envelope, secret) }
        _ = try await expectClientLine(channel) // MAIL
        _ = try await expectClientLine(channel) // RCPT
        _ = try await expectClientLine(channel) // DATA
        try await serverSend(channel, "250 2.1.0 OK")
        try await serverSend(channel, "550 5.1.1 User unknown")
        try await serverSend(channel, "354 Start mail input")
        // The lone terminator, never the body.
        #expect(try await expectClientLine(channel) == ".")
        try await serverSend(channel, "554 5.5.1 No valid recipients")
        #expect(try await expectClientLine(channel) == "RSET")
        try await serverSend(channel, "250 2.0.0 OK")

        let results = try await task.value
        #expect(results.count == 1)
        guard case .permanentlyFailed = results[0].outcome else {
            Issue.record("expected permanentlyFailed, got \(results[0].outcome)")
            return
        }
        #expect(try await channel.readOutbound(as: ByteBuffer.self) == nil)
        #expect(connection.channel.isActive)
        try await channel.close()
    }

    /// A 421 announces the server is closing: no RSET that would wait up to
    /// `replyTimeout` for a reply that never comes.
    @Test func a421IsNotFollowedByRSETAndClosesTheConnection() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await connectedForLivenessChecks(channel)
        try await negotiate(connection, channel, ["250-smtp.example.com", "250 8BITMIME"])
        let envelope = try SMTPEnvelope(mailFrom: .address("from@example.com"), recipients: ["a@example.com"])

        let task = Task { try await connection.sendMessage(envelope, message) }
        _ = try await expectClientLine(channel) // MAIL
        try await serverSend(channel, "250 2.1.0 OK")
        _ = try await expectClientLine(channel) // RCPT
        try await serverSend(channel, "421 4.3.2 Service shutting down")

        let results = try await task.value
        guard case .queuedForRetry(_, _, let last) = results[0].outcome, last.code == 421 else {
            Issue.record("expected queuedForRetry carrying the 421, got \(results[0].outcome)")
            return
        }
        #expect(try await channel.readOutbound(as: ByteBuffer.self) == nil)
        #expect(!connection.channel.isActive)
    }

    @Test func aRefusedResetClosesTheConnectionSoThePoolDropsIt() async throws {
        let (connection, channel) = try await ConnectionHarness.make()
        try await connectedForLivenessChecks(channel)
        try await negotiate(connection, channel, ["250-smtp.example.com", "250 8BITMIME"])
        let envelope = try SMTPEnvelope(mailFrom: .address("from@example.com"), recipients: ["bad@example.com"])

        let task = Task { try await connection.sendMessage(envelope, message) }
        _ = try await expectClientLine(channel) // MAIL
        try await serverSend(channel, "250 2.1.0 OK")
        _ = try await expectClientLine(channel) // RCPT
        try await serverSend(channel, "550 5.1.1 User unknown")
        #expect(try await expectClientLine(channel) == "RSET")
        try await serverSend(channel, "502 5.5.2 Command not recognized")

        let results = try await task.value
        #expect(results.count == 1)
        // Was active before the refused RSET (see `connectedForLivenessChecks`).
        #expect(!connection.channel.isActive)
    }
}

struct TLSDefaultsTests {

    @Test func poolConnectionsRequireTLS12WithFullVerification() {
        let tls = SMTPConnectionPool.Configuration().tlsConfiguration
        #expect(tls.minimumTLSVersion == .tlsv12)
        #expect(tls.certificateVerification == .fullVerification)
        #expect(RelayConfig(host: "h", port: 587, tls: .startTLS).pool.tlsConfiguration.minimumTLSVersion == .tlsv12)
    }

    @Test func theTLSConfigurationCanStillBeOverridden() {
        var legacy = TLSConfiguration.makeClientConfiguration()
        legacy.minimumTLSVersion = .tlsv1
        let configuration = SMTPConnectionPool.Configuration(tlsConfiguration: legacy)
        #expect(configuration.tlsConfiguration.minimumTLSVersion == .tlsv1)
    }
}

struct ErrorDescriptionTests {

    @Test func errorsDescribeWhatHappenedInsteadOfAnErrorCode() {
        let auth = SMTPError.authenticationFailed(SMTPReply(code: 535, lines: ["5.7.8 Authentication credentials invalid"]))
        #expect(auth.localizedDescription == "SMTP authentication failed: 535 5.7.8 Authentication credentials invalid")

        let errors: [any Error] = [
            SMTPError.starttlsRequired,
            SMTPError.circuitOpen,
            SMTPError.connectionFailed(SMTPConnectionError.replyTimedOut),
            SMTPConnectionError.channelClosedByPeer,
            SMTPConnectionPool.PoolError.shutdown,
            SMTPResponseDecoder.DecoderError.tooManyContinuationLines(limit: 100),
            MTASTSPolicyBodyTooLarge(limit: 65_536),
        ]
        for error in errors {
            #expect(!error.localizedDescription.contains("The operation couldn’t be completed"))
            #expect(!error.localizedDescription.contains("The operation couldn't be completed"))
        }
    }

    @Test func aWrappedErrorIsDescribedThroughItsOwnDescription() {
        let error = SMTPError.connectionFailed(SMTPConnectionError.replyTimedOut)
        #expect(error.localizedDescription == "The connection to the SMTP server failed: The SMTP server did not respond in time.")
    }
}

struct MTASTSBodyCapTests {

    @Test func aPolicyLargerThanTheCapIsRefused() async throws {
        let oversized = URLSessionMTASTSFetcher.maximumPolicyBodySize + 1
        for declaresLength in [true, false] {
            let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
            let server = try await FixedBodyHTTPServer.start(group: group, bodySize: oversized, declaresLength: declaresLength)
            let url = URL(string: "http://127.0.0.1:\(server.port)/.well-known/mta-sts.txt")!

            await #expect(throws: MTASTSPolicyBodyTooLarge.self) {
                _ = try await URLSessionMTASTSFetcher().fetch(url: url)
            }

            try await server.channel.close()
            try await group.shutdownGracefully()
        }
    }

    @Test func aPolicyAtTheCapIsStillFetched() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let size = URLSessionMTASTSFetcher.maximumPolicyBodySize
        let server = try await FixedBodyHTTPServer.start(group: group, bodySize: size, declaresLength: false)
        let url = URL(string: "http://127.0.0.1:\(server.port)/.well-known/mta-sts.txt")!

        let response = try await URLSessionMTASTSFetcher().fetch(url: url)

        try await server.channel.close()
        try await group.shutdownGracefully()
        #expect(response.statusCode == 200)
        #expect(response.body.count == size)
    }
}

// MARK: - Helpers

/// `ConnectionHarness` channels are never connected, so `isActive` is false
/// from the start and could not tell a closed connection from a live one.
/// A test that connects must close the channel before it ends: the
/// `NIOAsyncChannel` writer traps if it is deinitialized while still open.
private func connectedForLivenessChecks(_ channel: NIOAsyncTestingChannel) async throws {
    try await channel.connect(to: try SocketAddress(ipAddress: "127.0.0.1", port: 587))
    #expect(channel.isActive)
}

private func negotiate(_ connection: SMTPConnection, _ channel: NIOAsyncTestingChannel, _ lines: [String]) async throws {
    let task = Task { try await connection.negotiateCapabilities() }
    _ = try await expectClientLine(channel)
    for line in lines { try await serverSend(channel, line) }
    _ = try await task.value
}

private enum FixedBodyHTTPServer {
    struct Running {
        let channel: Channel
        let port: Int
    }

    static func start(group: any EventLoopGroup, bodySize: Int, declaresLength: Bool) async throws -> Running {
        let bootstrap = ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(
                        FixedBodyHTTPHandler(bodySize: bodySize, declaresLength: declaresLength)
                    )
                }
            }
        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        guard let port = channel.localAddress?.port else { throw ServerError.noLocalPort }
        return Running(channel: channel, port: port)
    }

    enum ServerError: Error {
        case noLocalPort
    }
}

/// Answers the first complete request with `bodySize` bytes of policy-like
/// text, with or without `Content-Length` (without it, the body runs until
/// the connection closes — the case only a streaming limit catches).
private final class FixedBodyHTTPHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let bodySize: Int
    private let declaresLength: Bool
    private var accumulated = ByteBuffer()
    private var answered = false

    init(bodySize: Int, declaresLength: Bool) {
        self.bodySize = bodySize
        self.declaresLength = declaresLength
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = Self.unwrapInboundIn(data)
        accumulated.writeBuffer(&incoming)
        guard !answered, accumulated.readableBytesView.contains(0x0A),
              String(buffer: accumulated).contains("\r\n\r\n") else { return }
        answered = true

        var head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n"
        if declaresLength { head += "Content-Length: \(bodySize)\r\n" }
        head += "\r\n"
        var buffer = context.channel.allocator.buffer(capacity: head.utf8.count + bodySize)
        buffer.writeString(head)
        buffer.writeRepeatingByte(UInt8(ascii: "a"), count: bodySize)
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        context.writeAndFlush(Self.wrapOutboundOut(buffer)).whenComplete { _ in
            boundContext.value.close(promise: nil)
        }
    }
}
