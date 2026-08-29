package jinguissl.contract

import std.collection.ArrayList
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.tls.{
    TLS13_RESUMPTION_MAX_LIFETIME_SECONDS,
    TLS13_RESUMPTION_DEFAULT_LIFETIME_SECONDS,
    TLS13_RESUMPTION_DEFAULT_AGE_TOLERANCE_MILLISECONDS,
    Tls13ClientResumptionTicket,
    Tls13ValidatedResumption,
    Tls13OpaqueTicketStore,
    TlsClientHello,
    TlsExtension,
    tls13BuildClientHelloX25519WithCipherSuites,
    tlsBuildAlpnExtension,
    tlsBuildServerNameExtension,
    tls13CreateClientResumptionTicket,
    tls13BuildClientHelloFromResumptionTicket,
    tlsDecodeClientHelloHandshake,
    tlsEncodeClientHelloHandshake
}
import jinguissl_core.crypto.x25519.{x25519GeneratePrivateKey, x25519PublicFromPrivate}

public let CONTRACT_TLS13_RESUMPTION_MAX_LIFETIME_SECONDS: Int64 =
    TLS13_RESUMPTION_MAX_LIFETIME_SECONDS
public let CONTRACT_TLS13_RESUMPTION_DEFAULT_LIFETIME_SECONDS: Int64 =
    TLS13_RESUMPTION_DEFAULT_LIFETIME_SECONDS
public let CONTRACT_TLS13_RESUMPTION_DEFAULT_AGE_TOLERANCE_MILLISECONDS: Int64 =
    TLS13_RESUMPTION_DEFAULT_AGE_TOLERANCE_MILLISECONDS

/**
 * Contract-owned client state for one server-issued opaque TLS 1.3 ticket.
 * The secret-bearing PSK remains local and is never encoded into wireTicket.
 */
public class ContractTls13ClientResumptionTicket {
    internal let _inner: Tls13ClientResumptionTicket
    public let wireTicket: Array<Byte>
    public let resumptionPsk: Array<Byte>
    public let ticketNonce: Array<Byte>
    public let ticketAgeAdd: Int64
    public let ticketLifetimeSeconds: Int64
    public let receivedAtUnixMilliseconds: Int64
    public let serverName: String
    public let alpnProtocol: String
    public let cipherSuite: Int64

    internal init(inner: Tls13ClientResumptionTicket) {
        this._inner = inner
        this.wireTicket = inner.wireTicket.clone()
        this.resumptionPsk = inner.resumptionPsk.clone()
        this.ticketNonce = inner.ticketNonce.clone()
        this.ticketAgeAdd = inner.ticketAgeAdd
        this.ticketLifetimeSeconds = inner.ticketLifetimeSeconds
        this.receivedAtUnixMilliseconds = inner.receivedAtUnixMilliseconds
        this.serverName = inner.serverName
        this.alpnProtocol = inner.alpnProtocol
        this.cipherSuite = inner.cipherSuite
    }
}

/**
 * Validated server-side resumption context.
 * The caller must still complete the TLS 1.3 PSK+DHE key schedule and handshake.
 */
public class ContractTls13ValidatedResumption {
    public let resumptionPsk: Array<Byte>
    public let serverName: String
    public let alpnProtocol: String
    public let cipherSuite: Int64

    internal init(inner: Tls13ValidatedResumption) {
        this.resumptionPsk = inner.resumptionPsk.clone()
        this.serverName = inner.serverName
        this.alpnProtocol = inner.alpnProtocol
        this.cipherSuite = inner.cipherSuite
    }
}

/** Caller-owned X25519 state for a resumed TLS 1.3 ClientHello. */
public class ContractTls13ResumptionClientHelloX25519 {
    public let encodedClientHello: Array<Byte>
    public let privateKey: Array<Byte>
    public let publicKey: Array<Byte>

    public init(
        encodedClientHello: Array<Byte>,
        privateKey: Array<Byte>,
        publicKey: Array<Byte>
    ) {
        this.encodedClientHello = encodedClientHello.clone()
        this.privateKey = privateKey.clone()
        this.publicKey = publicKey.clone()
    }
}

/**
 * Bounded single-process owner for opaque, single-use TLS 1.3 tickets.
 * Callers must serialize access to one instance and keep 0-RTT disabled.
 */
public class ContractTls13OpaqueTicketStore {
    private let _inner: Tls13OpaqueTicketStore

    public init(maxEntries!: Int64 = 1024) {
        try {
            this._inner = Tls13OpaqueTicketStore(maxEntries: maxEntries)
        } catch (e: CryptoException) {
            throw contractTls13ResumptionException(e, "opaque ticket store initialization")
        }
    }

    public prop size: Int64 {
        get() { _inner.size }
    }

    public prop rotationGeneration: Int64 {
        get() { _inner.rotationGeneration }
    }

    public func issueNewSessionTicket(
        resumptionMasterSecret: Array<Byte>,
        serverName: String,
        alpnProtocol: String,
        cipherSuite: Int64,
        nowUnixMilliseconds: Int64,
        ticketLifetimeSeconds!: Int64 = CONTRACT_TLS13_RESUMPTION_DEFAULT_LIFETIME_SECONDS
    ): Array<Byte> {
        try {
            _inner.issueNewSessionTicket(
                resumptionMasterSecret,
                serverName,
                alpnProtocol,
                cipherSuite,
                nowUnixMilliseconds,
                ticketLifetimeSeconds: ticketLifetimeSeconds
            )
        } catch (e: CryptoException) {
            throw contractTls13ResumptionException(e, "NewSessionTicket issue")
        }
    }

    public func validateAndConsumeClientHello(
        encodedClientHello: Array<Byte>,
        nowUnixMilliseconds: Int64,
        ageToleranceMilliseconds!: Int64 =
            CONTRACT_TLS13_RESUMPTION_DEFAULT_AGE_TOLERANCE_MILLISECONDS
    ): ContractTls13ValidatedResumption {
        if (encodedClientHello.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 ClientHello must not be empty")
        }
        if (nowUnixMilliseconds < 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 resumption acceptance time must not be negative")
        }
        if (ageToleranceMilliseconds < 0 || ageToleranceMilliseconds > 60_000) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 ticket age tolerance must be between 0 and 60000 milliseconds"
            )
        }
        try {
            ContractTls13ValidatedResumption(
                _inner.validateAndConsumeClientHello(
                    encodedClientHello,
                    nowUnixMilliseconds,
                    ageToleranceMilliseconds: ageToleranceMilliseconds
                )
            )
        } catch (e: CryptoException) {
            throw contractTls13ResumptionException(
                e,
                "opaque ClientHello validation",
                verificationFailure: true
            )
        }
    }

    public func rotate(): Unit {
        _inner.rotate()
    }

    public func purgeExpired(nowUnixMilliseconds: Int64): Int64 {
        if (nowUnixMilliseconds < 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 ticket purge time must not be negative")
        }
        try {
            _inner.purgeExpired(nowUnixMilliseconds)
        } catch (e: CryptoException) {
            throw contractTls13ResumptionException(e, "opaque ticket purge")
        }
    }
}

public func contractTls13CreateClientResumptionTicket(
    encodedNewSessionTicket: Array<Byte>,
    resumptionMasterSecret: Array<Byte>,
    serverName: String,
    alpnProtocol: String,
    cipherSuite: Int64,
    receivedAtUnixMilliseconds: Int64
): ContractTls13ClientResumptionTicket {
    try {
        ContractTls13ClientResumptionTicket(
            tls13CreateClientResumptionTicket(
                encodedNewSessionTicket,
                resumptionMasterSecret,
                serverName,
                alpnProtocol,
                cipherSuite,
                receivedAtUnixMilliseconds
            )
        )
    } catch (e: CryptoException) {
        throw contractTls13ResumptionException(e, "client resumption ticket creation")
    }
}

public func contractTls13BuildClientHelloFromResumptionTicket(
    ticket: ContractTls13ClientResumptionTicket,
    nowUnixMilliseconds: Int64,
    baseClientHello: Array<Byte>
): Array<Byte> {
    try {
        tls13BuildClientHelloFromResumptionTicket(
            ticket._inner,
            nowUnixMilliseconds,
            baseClientHello
        )
    } catch (e: CryptoException) {
        throw contractTls13ResumptionException(e, "resumed ClientHello build")
    }
}

/**
 * Builds the exact single-cipher PSK+DHE/X25519 base required by the ticket,
 * then adds its opaque identity and binder. No Core-owned type crosses the API.
 */
public func contractTls13BuildClientHelloFromResumptionTicketX25519(
    ticket: ContractTls13ClientResumptionTicket,
    nowUnixMilliseconds: Int64,
    clientPrivateKey!: ?Array<Byte> = None
): ContractTls13ResumptionClientHelloX25519 {
    try {
        let privateKey = if (let Some(value) <- clientPrivateKey) {
            value.clone()
        } else {
            x25519GeneratePrivateKey()
        }
        let publicKey = x25519PublicFromPrivate(privateKey)
        let decodedBase = tlsDecodeClientHelloHandshake(
            tls13BuildClientHelloX25519WithCipherSuites(
                publicKey,
                [ticket.cipherSuite]
            )
        )
        let extensions = ArrayList<TlsExtension>()
        for (extension in decodedBase.extensions) {
            extensions.add(extension)
        }
        if (ticket.serverName.size > 0) {
            extensions.add(tlsBuildServerNameExtension(ticket.serverName))
        }
        if (ticket.alpnProtocol.size > 0) {
            extensions.add(tlsBuildAlpnExtension([ticket.alpnProtocol]))
        }
        let encodedBase = tlsEncodeClientHelloHandshake(
            TlsClientHello(
                decodedBase.random,
                decodedBase.cipherSuites,
                sessionId: decodedBase.sessionId,
                compressionMethods: decodedBase.compressionMethods,
                extensions: extensions.toArray(),
                legacyVersion: decodedBase.legacyVersion
            )
        )
        ContractTls13ResumptionClientHelloX25519(
            tls13BuildClientHelloFromResumptionTicket(
                ticket._inner,
                nowUnixMilliseconds,
                encodedBase
            ),
            privateKey,
            publicKey
        )
    } catch (e: CryptoException) {
        throw contractTls13ResumptionException(e, "resumed X25519 ClientHello build")
    }
}

private func contractTls13ResumptionException(
    exception: CryptoException,
    operation: String,
    verificationFailure!: Bool = false
): ContractException {
    ContractException(
        contractMapCoreCryptoException(exception, verificationFailure: verificationFailure),
        "TLS1.3 ${operation} failed: ${exception.message}"
    )
}
