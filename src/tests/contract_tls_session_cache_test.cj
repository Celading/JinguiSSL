package jinguissl.tests

import jinguissl.contract.*

@Test
public class ContractTlsSessionCacheTestSuite {
    @TestCase
    public func testContractTlsSessionCacheStaysLinkable(): Unit {
        let cache = ContractTlsSessionCache(maxEntries: 2, defaultTtlSeconds: 60)
        @Assert(cache.size, 0)

        let stats = cache.stats()
        @Assert(stats.size, 0)
        @Assert(stats.hits, 0)
        @Assert(stats.misses, 0)
        @Assert(stats.evictions, 0)
        @Assert(stats.expiredRemovals, 0)
    }

    @TestCase
    public func testContractTlsSessionCacheRejectsBadCapacity(): Unit {
        try {
            _ = ContractTlsSessionCache(maxEntries: 0, defaultTtlSeconds: 60)
            @Fail("session cache maxEntries=0 should fail through the contract facade")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "BAD_INPUT")
        }
    }
}


@Test
public class ContractSupplementarySessionCacheTestSuite {
    @TestCase
    public func testContractTlsSessionCacheClear(): Unit {
        let cache = ContractTlsSessionCache(maxEntries: 10, defaultTtlSeconds: 60)
        @Assert(cache.size, 0)
        let before = cache.stats()
        @Assert(before.size, 0)
        cache.clear()
        let after = cache.stats()
        @Assert(after.size, 0)
    }

    @TestCase
    public func testContractTlsSessionCacheRejectsNegativeTtl(): Unit {
        try {
            _ = ContractTlsSessionCache(maxEntries: 5, defaultTtlSeconds: -1)
            @Fail("negative TTL should be rejected")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "BAD_INPUT")
        }
    }

    @TestCase
    public func testContractTlsSessionCacheRejectsZeroMaxEntries(): Unit {
        try {
            _ = ContractTlsSessionCache(maxEntries: 0, defaultTtlSeconds: 60)
            @Fail("zero maxEntries should be rejected")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "BAD_INPUT")
        }
    }

    @TestCase
    public func testContractTlsSessionCacheInitialStats(): Unit {
        let cache = ContractTlsSessionCache(maxEntries: 10, defaultTtlSeconds: 600)
        @Assert(cache.size, 0)
        let stats = cache.stats()
        @Assert(stats.size, 0)
        @Assert(stats.hits, 0)
        @Assert(stats.misses, 0)
        @Assert(stats.evictions, 0)
        @Assert(stats.expiredRemovals, 0)
    }

    @TestCase
    public func testContractTlsSessionCacheMultipleStatsCheck(): Unit {
        let cache = ContractTlsSessionCache(maxEntries: 10, defaultTtlSeconds: 600)
        let s1 = cache.stats()
        @Assert(s1.size, 0)
        let s2 = cache.stats()
        @Assert(s2.size, 0)
        @Assert(s1.size, s2.size)
    }

    @TestCase
    public func testContractTlsSessionCacheLargeCapacity(): Unit {
        let cache = ContractTlsSessionCache(maxEntries: 10000, defaultTtlSeconds: 86400)
        @Assert(cache.size, 0)
        let stats = cache.stats()
        @Assert(stats.size, 0)
        @Assert(stats.hits, 0)
        @Assert(stats.misses, 0)
        @Assert(stats.evictions, 0)
        @Assert(stats.expiredRemovals, 0)
    }

    @TestCase
    public func testContractOwnedSessionTicketStoreLoadRemove(): Unit {
        let cache = ContractTlsSessionCache(maxEntries: 2, defaultTtlSeconds: 60)
        let identity = ContractTlsSessionIdentity(
            ContractTlsVersion.Tls13,
            [UInt8(0x01), UInt8(0x02)],
            serverName: "API.EXAMPLE.COM",
            alpnProtocol: "H2"
        )
        let ticket = cache.storeFromSecret(
            identity,
            Array<Byte>(32, repeat: UInt8(0x33)),
            nonce: [UInt8(0x07)],
            nowUnixSeconds: 1_800_000_000,
            ttlSeconds: 60
        )
        @Assert(ticket.identity.serverName, "api.example.com")
        @Assert(ticket.identity.alpnProtocol, "h2")
        @Assert(ticket.isExpired(1_800_000_059), false)

        if (let Some(loaded) <- cache.load(identity, nowUnixSeconds: 1_800_000_001)) {
            @Assert(loaded.secret.size, 32)
            @Assert(loaded.identity.version.toString(), "TLS1.3")
            try {
                _ = contractTls13BuildClientHelloPskFromSessionTicket(loaded)
                @Fail("local cache tickets must not become self-describing wire identities")
            } catch (e: ContractException) {
                @Assert(e.code.toString(), "UNSUPPORTED")
            }
        } else {
            @Fail("Contract-owned session ticket should load")
        }
        @Assert(cache.remove(identity), true)
        @Assert(cache.size, 0)
    }

    @TestCase
    public func testContractOwnedSessionTicketExpiryPurges(): Unit {
        let cache = ContractTlsSessionCache(maxEntries: 2, defaultTtlSeconds: 1)
        let identity = ContractTlsSessionIdentity(
            ContractTlsVersion.Tls13,
            [UInt8(0x09)],
            serverName: "expiry.example",
            alpnProtocol: "h2"
        )
        _ = cache.storeFromSecret(
            identity,
            Array<Byte>(32, repeat: UInt8(0x44)),
            nowUnixSeconds: 1_800_000_100,
            ttlSeconds: 1
        )
        @Assert(cache.purgeExpired(nowUnixSeconds: 1_800_000_101), 1)
        @Assert(cache.size, 0)
    }
}
