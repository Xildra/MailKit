# Perfect - SMTP [简体中文](README.zh_CN.md)

<p align="center">
    <a href="https://www.swift.org/" target="_blank">
        <img src="https://img.shields.io/badge/Swift-6.2-orange.svg?style=flat" alt="Swift 6.2">
    </a>
    <a href="https://developer.apple.com/macos/" target="_blank">
        <img src="https://img.shields.io/badge/Platforms-macOS%2012%2B%20%7C%20iOS%2015%2B-lightgray.svg?style=flat" alt="Platforms macOS 12+ | iOS 15+">
    </a>
    <a href="LICENSE" target="_blank">
        <img src="https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg?style=flat" alt="License Apache 2.0">
    </a>
</p>

Perfect-SMTP is a from-scratch Swift 6.2 / SwiftNIO SMTP client. It is not a
wrapper around libcurl or any other mail library — it drives the SMTP wire
protocol itself, including its own STARTTLS state machine, connection
pooling, DKIM signing, and MTA-STS policy enforcement.

It ships three delivery strategies (relay through an existing SMTP host,
hand off to a local MTA like Postfix/sendmail, or resolve MX records and
deliver directly), so you can pick the one that matches how you already
operate mail, or let Perfect-SMTP be the terminal MTA itself.

> This is a complete rewrite of the pre-2026 libcurl-based Perfect-SMTP. If
> you used the old `EMail`/`SMTPClient`/`Recipient` API, see
> [Migrating from the old Perfect-SMTP](Documentation/user-guide.md#migrating-from-the-old-perfect-smtp)
> in the user guide — this is not a drop-in upgrade. The old version is
> preserved on the [`legacy`](../../tree/legacy) branch.

## About this fork

This is [Xildra/MailKit](https://github.com/Xildra/MailKit), a fork of
[PerfectlySoft/Perfect-SMTP](https://github.com/PerfectlySoft/Perfect-SMTP)
at `a33bc72`. Module and product names are unchanged (`PerfectSMTP`,
`PerfectSMTPCore`) and every public API from upstream is still there, so
code written against upstream compiles as is. Changes, all marked `Fork:` in
the source:

**Platforms and dependencies**
- Builds for **iOS** (15+). Upstream did not: `LocalMTATransport` uses
  `Foundation.Process`; it is now compiled on macOS and Linux only.
- Dependency floors raised past known advisories: swift-nio ≥ 2.101.0
  (CVE-2026-43671, CVE-2026-43678), swift-nio-ssl ≥ 2.37.2
  (CVE-2026-43820). swift-crypto moves from `exact: "4.5.1"` to
  `.upToNextMinor(from: "4.5.1")` so 4.5.x security patches can be picked up.

**Security**
- `RelayTransport` connections require **TLS 1.2** (NIOSSL's client default
  still allowed 1.0/1.1, and iOS App Transport Security does not cover raw
  sockets). `SMTPConnectionPool.Configuration.tlsConfiguration` — reachable
  through `RelayConfig.pool` — overrides it for custom trust roots, pinning,
  or a legacy server. `DirectMXTransport` is unchanged: refusing TLS 1.0 in
  opportunistic delivery would fall back to plaintext instead.
- AUTH exchanges are bounded to 8 `334` continuations (a hostile server could
  keep `SASLLogin` re-sending the password forever).
- MTA-STS policy bodies are capped at 64 KiB (upstream buffered any size from
  an attacker-controlled host).

**Correctness**
- A transaction abandoned before its final DATA reply (no recipient accepted,
  or DATA refused) is reset with `RSET` before its connection is pooled
  again; if DATA was answered `354` with no accepted recipient, the empty
  DATA phase is terminated first; after a `421` the connection is closed
  instead. Upstream pooled such connections as-is — in the `354` case still
  in DATA mode, desynchronizing every later reply.
- Non-ASCII attachment names were written into headers as raw UTF-8. They
  are now RFC 2047-encoded in `name`/`filename`, plus RFC 2231 `filename*`.
  ASCII names are emitted exactly as before.
- Every error type has a `LocalizedError` description. Upstream's
  `localizedDescription` read "The operation couldn't be completed.
  (PerfectSMTPCore.SMTPError error 5.)".

**Additions**
- `RelayConfig.Auth.automatic(username:password:)` picks PLAIN, LOGIN or
  CRAM-MD5 from the server's own `AUTH` list, in the server's order — the
  behavior Swift-SMTP had — without ever sending a password through a token
  mechanism, and without rejecting or altering any credential. Needed for
  servers without PLAIN, such as Exchange on-premises (`AUTH NTLM LOGIN`).
- `SASLCramMD5` (RFC 2195) and `SASLPasswordNegotiation`.

**Not changed, worth knowing**
- `TLSMode.none` with authentication still sends credentials in clear text;
  it exists for trusted internal relays.
- `DNSResolver.systemNameservers()` (the default for `DirectMXTransport`)
  parses `/etc/resolv.conf` and, when that yields nothing, silently queries
  Cloudflare `1.1.1.1` and Google `8.8.8.8` — which leaks recipient domains
  to third parties and fails on networks that block public DNS. Pass
  `nameservers:` explicitly, or use `RelayTransport` (no DNS of its own) on
  iOS.

This package is domain-agnostic by design — it has no Lasso-specific code
and no Lasso dependency. It is, however, a **core dependency**:
[Perfect-Lasso](https://github.com/taplin/Perfect-Lasso) — a Swift
reimplementation of the Lasso language, still in active development and
not yet production-ready, though validated against real code from
multiple production e-commerce sites — depends on this package directly
to implement its `email_send` tag, which sends real outbound email during
that validation testing. (There is a separate, unrelated
in-progress target called `LassoPerfectSMTP` being built *inside* the
Perfect-Lasso repo on another branch — that is not this package and does not
depend on it.)

## Features

- **Hand-rolled SMTP client on SwiftNIO** — its own STARTTLS upgrade
  sequence with byte-precise buffer discipline against injection/downgrade
  attacks, connection pooling with circuit breaking, and PIPELINING support.
- **DKIM signing** (RFC 6376) — RSA-SHA256 and Ed25519-SHA256 (RFC 8463),
  including dual-signing, with automatic oversigning of security-sensitive
  headers and a DMARC-alignment lint.
- **Three delivery strategies** — `RelayTransport` (an ESP or existing SMTP
  relay), `LocalMTATransport` (hand off to `sendmail`/Postfix on the same
  host), and `DirectMXTransport` (resolve MX records and deliver directly,
  with its own retry queue and circuit breaker).
- **MTA-STS** (RFC 8461) policy discovery, caching, and enforcement for
  direct-MX delivery, plus opportunistic STARTTLS by default.
- **SASL authentication** — `PLAIN`, `LOGIN`, `CRAM-MD5`, and `XOAUTH2`
  (required by Gmail/Workspace, increasingly required by Microsoft 365),
  or automatic selection from what the server offers.
- **Deliverability headers** — `List-Unsubscribe`/`List-Unsubscribe-Post`
  (RFC 8058), `Precedence`, `Auto-Submitted` — the headers Gmail and Yahoo
  have required for bulk senders since November 2025.
- **Bulk/list-server ready** — a bounded-concurrency batch `send` and an
  `AsyncSequence`-based streaming `send` for sending to millions of
  recipients without materializing them all in memory.
- **Structured delivery results** — every send returns a per-recipient
  outcome (delivered, queued for retry, permanently failed, expired,
  ambiguous, or a transport-level failure) instead of a single pass/fail.

For anything beyond the basics below, see the
**[full user guide](Documentation/user-guide.md)**.

## Requirements

- Swift 6.2 toolchain (`swift-tools-version: 6.2`, `.swiftLanguageMode(.v6)`)
- macOS 12 or later, or iOS 15 or later

## Installation

Add the package to your `Package.swift`:

```swift
.package(url: "https://github.com/Xildra/MailKit.git", from: "1.0.0")
```

and depend on the `PerfectSMTP` product (it re-exports `PerfectSMTPCore`,
which you only need directly if you want to compose/sign messages without
sending them):

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "PerfectSMTP", package: "MailKit"),
    ]
)
```

## Quick start

Send one email through an existing SMTP relay (a corporate MTA or an ESP
like SendGrid/Postmark/SES):

```swift
import PerfectSMTP
import NIOPosix

let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)

let transport = RelayTransport(
    config: RelayConfig(
        host: "smtp.example.com",
        port: 587,
        tls: .startTLS,
        auth: .plain(username: "postmaster@example.com", password: "secret")
    ),
    group: group
)
let mailer = SMTPMailer(transport: transport)

var message = EmailMessage(from: EmailAddress(displayName: "Ops", address: "ops@example.com"))
message.to = [EmailAddress(address: "user@dest.com")]
message.subject = "Hello from Perfect-SMTP"
message.textBody = "Hi there!"

let results = try await mailer.send(message, envelopeFrom: .address("ops@example.com"))
for result in results {
    print(result.recipient, result.outcome)
}

try await group.shutdownGracefully()
```

That's it for the basic case. For DKIM signing, direct-MX delivery,
authentication options, bulk sending, and deliverability headers, see the
**[user guide](Documentation/user-guide.md)**.

## Testing

```
swift test
```

372 tests (209 in `PerfectSMTPTests`, 163 in `PerfectSMTPCoreTests`) run with
no external services and no environment variables — this includes tests
that open real loopback sockets (a STARTTLS handshake and a full DirectMX
delivery each run against an in-process fake SMTP server on `127.0.0.1`),
but nothing here talks to the real network or a real mail server.

Note: the original rewrite plan (`Documentation/swift6-nio-rewrite-plan.md`
§4.1/§5) describes an additional `SMTP_TESTS=1`-gated live-integration tier
against a MailHog/smtp4dev CI service container. That tier was never built —
there is no such environment variable referenced anywhere in `Tests/`, and
this repository has no CI workflow files at all. If you need to verify
against a real SMTP server, point a `RelayTransport` or `DirectMXTransport`
at a local MailHog/smtp4dev instance yourself; see
[Testing your integration](Documentation/user-guide.md#testing-your-integration)
in the user guide.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
