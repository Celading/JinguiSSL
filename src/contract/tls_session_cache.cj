package jinguissl.contract

import jinguissl_core.crypto.compliance.TlsVersion
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.tls.{
    TLS_SESSION_DEFAULT_TTL_SECONDS,
    TlsSessionCache,
    TlsSessionCacheStats,
    TlsSessionIdentity,
    TlsSessionTicket
}

/** Contract-owned TLS protocol version used by stable session-cache DTOs. */
public enum ContractTlsVersion <: Equatable<ContractTlsVersion> & ToString {
    | Tls12
    | Tls13

    public operator func ==(right: ContractTlsVersion): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: ContractTlsVersion): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case Tls12 => 0
            case Tls13 => 1
        }
    }

    public func toString(): String {
        match (this) {
            case Tls12 => "TLS1.2"
            case Tls13 => "TLS1.3"
        }
    }
}

public class ContractTlsSessionIdentity {
    public let version: ContractTlsVersion
    public let resumptionId: Array<Byte>
    public let serverName: String
    public let alpnProtocol: String

    public init(
        version: ContractTlsVersion,
        resumptionId: Array<Byte>,
        serverName!: String = "",
        alpnProtocol!: String = ""
    ) {
        if (resumptionId.size == 0 || resumptionId.size > 65535) {
            throw ContractException(ContractErrorCode.BadInput, "TLS session resumption id length is invalid")
        }
        let normalizedServerName = serverName.trimAscii().toAsciiLower()
        let normalizedAlpn = alpnProtocol.trimAscii().toAsciiLower()
        if (normalizedServerName.size > 65535 || normalizedAlpn.size > 255) {
            throw ContractException(ContractErrorCode.BadInput, "TLS session identity context is too long")
        }
        this.version = version
        this.resumptionId = resumptionId.clone()
        this.serverName = normalizedServerName
        this.alpnProtocol = normalizedAlpn
    }
}

public class ContractTlsSessionTicket {
    public let version: Int64
    public let identity: ContractTlsSessionIdentity
    public let secret: Array<Byte>
    public let nonce: Array<Byte>
    public let issuedAtUnixSeconds: Int64
    public let expiresAtUnixSeconds: Int64

    public init(
        version: Int64,
        identity: ContractTlsSessionIdentity,
        secret: Array<Byte>,
        nonce: Array<Byte>,
        issuedAtUnixSeconds: Int64,
        expiresAtUnixSeconds: Int64
    ) {
        if (version <= 0 || version > 255) {
            throw ContractException(ContractErrorCode.BadInput, "TLS session ticket version is invalid")
        }
        if (secret.size == 0 || secret.size > 65535) {
            throw ContractException(ContractErrorCode.BadInput, "TLS session ticket secret length is invalid")
        }
        if (nonce.size > 255) {
            throw ContractException(ContractErrorCode.BadInput, "TLS session ticket nonce length is invalid")
        }
        if (issuedAtUnixSeconds <= 0 || expiresAtUnixSeconds <= issuedAtUnixSeconds) {
            throw ContractException(ContractErrorCode.BadInput, "TLS session ticket validity window is invalid")
        }
        this.version = version
        this.identity = ContractTlsSessionIdentity(
            identity.version,
            identity.resumptionId,
            serverName: identity.serverName,
            alpnProtocol: identity.alpnProtocol
        )
        this.secret = secret.clone()
        this.nonce = nonce.clone()
        this.issuedAtUnixSeconds = issuedAtUnixSeconds
        this.expiresAtUnixSeconds = expiresAtUnixSeconds
    }

    public func isExpired(nowUnixSeconds: Int64): Bool {
        nowUnixSeconds >= expiresAtUnixSeconds
    }
}

public class ContractTlsSessionCacheStats {
    public let size: Int64
    public let hits: Int64
    public let misses: Int64
    public let evictions: Int64
    public let expiredRemovals: Int64

    public init(size: Int64, hits: Int64, misses: Int64, evictions: Int64, expiredRemovals: Int64) {
        this.size = size
        this.hits = hits
        this.misses = misses
        this.evictions = evictions
        this.expiredRemovals = expiredRemovals
    }
}

/** Stable cache facade; no Core-owned type crosses its public surface. */
public class ContractTlsSessionCache {
    private let _inner: TlsSessionCache

    public init(maxEntries!: Int64 = 1024, defaultTtlSeconds!: Int64 = TLS_SESSION_DEFAULT_TTL_SECONDS) {
        try {
            this._inner = TlsSessionCache(maxEntries: maxEntries, defaultTtlSeconds: defaultTtlSeconds)
        } catch (e: CryptoException) {
            throw contractSessionCacheException(e, "initialization")
        }
    }

    public prop size: Int64 {
        get() { _inner.size }
    }

    public func stats(): ContractTlsSessionCacheStats {
        contractSessionCacheFromStats(_inner.stats())
    }

    public func store(ticket: ContractTlsSessionTicket): ContractTlsSessionTicket {
        try {
            contractSessionCacheFromCoreTicket(_inner.store(contractSessionCacheToCoreTicket(ticket)))
        } catch (e: CryptoException) {
            throw contractSessionCacheException(e, "ticket store")
        }
    }

    public func storeFromSecret(
        identity: ContractTlsSessionIdentity,
        secret: Array<Byte>,
        nonce!: Array<Byte> = [],
        nowUnixSeconds!: Int64 = 0,
        ttlSeconds!: Int64 = 0
    ): ContractTlsSessionTicket {
        try {
            contractSessionCacheFromCoreTicket(
                _inner.storeFromSecret(
                    contractSessionCacheToCoreIdentity(identity),
                    secret,
                    nonce: nonce,
                    nowUnixSeconds: nowUnixSeconds,
                    ttlSeconds: ttlSeconds
                )
            )
        } catch (e: CryptoException) {
            throw contractSessionCacheException(e, "ticket store-from-secret")
        }
    }

    public func load(
        identity: ContractTlsSessionIdentity,
        nowUnixSeconds!: Int64 = 0
    ): ?ContractTlsSessionTicket {
        try {
            if (let Some(ticket) <- _inner.load(
                contractSessionCacheToCoreIdentity(identity),
                nowUnixSeconds: nowUnixSeconds
            )) {
                return Some(contractSessionCacheFromCoreTicket(ticket))
            }
            None
        } catch (e: CryptoException) {
            throw contractSessionCacheException(e, "ticket load")
        }
    }

    public func remove(identity: ContractTlsSessionIdentity): Bool {
        try {
            _inner.remove(contractSessionCacheToCoreIdentity(identity))
        } catch (e: CryptoException) {
            throw contractSessionCacheException(e, "ticket remove")
        }
    }

    public func purgeExpired(nowUnixSeconds!: Int64 = 0): Int64 {
        try {
            _inner.purgeExpired(nowUnixSeconds: nowUnixSeconds)
        } catch (e: CryptoException) {
            throw contractSessionCacheException(e, "expired-ticket purge")
        }
    }

    public func clear(): Unit {
        _inner.clear()
    }
}

internal func contractSessionCacheToCoreTicket(ticket: ContractTlsSessionTicket): TlsSessionTicket {
    TlsSessionTicket(
        contractSessionCacheToCoreIdentity(ticket.identity),
        ticket.secret,
        ticket.nonce,
        ticket.issuedAtUnixSeconds,
        ticket.expiresAtUnixSeconds,
        version: ticket.version
    )
}

private func contractSessionCacheToCoreIdentity(identity: ContractTlsSessionIdentity): TlsSessionIdentity {
    TlsSessionIdentity(
        contractSessionCacheToCoreVersion(identity.version),
        identity.resumptionId,
        serverName: identity.serverName,
        alpnProtocol: identity.alpnProtocol
    )
}

private func contractSessionCacheFromCoreTicket(ticket: TlsSessionTicket): ContractTlsSessionTicket {
    ContractTlsSessionTicket(
        ticket.version,
        ContractTlsSessionIdentity(
            contractSessionCacheFromCoreVersion(ticket.identity.version),
            ticket.identity.resumptionId,
            serverName: ticket.identity.serverName,
            alpnProtocol: ticket.identity.alpnProtocol
        ),
        ticket.secret,
        ticket.nonce,
        ticket.issuedAtUnixSeconds,
        ticket.expiresAtUnixSeconds
    )
}

private func contractSessionCacheToCoreVersion(version: ContractTlsVersion): TlsVersion {
    match (version) {
        case ContractTlsVersion.Tls12 => TlsVersion.TLS1_2
        case ContractTlsVersion.Tls13 => TlsVersion.TLS1_3
    }
}

private func contractSessionCacheFromCoreVersion(version: TlsVersion): ContractTlsVersion {
    match (version) {
        case TlsVersion.TLS1_2 => ContractTlsVersion.Tls12
        case TlsVersion.TLS1_3 => ContractTlsVersion.Tls13
    }
}

private func contractSessionCacheFromStats(stats: TlsSessionCacheStats): ContractTlsSessionCacheStats {
    ContractTlsSessionCacheStats(
        stats.size,
        stats.hits,
        stats.misses,
        stats.evictions,
        stats.expiredRemovals
    )
}

private func contractSessionCacheException(exception: CryptoException, operation: String): ContractException {
    ContractException(
        contractMapCoreCryptoException(exception),
        "TLS session cache ${operation} failed: ${exception.message}"
    )
}
