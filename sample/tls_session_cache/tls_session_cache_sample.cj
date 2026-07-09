/**
 * TLS 会话缓存使用示例
 */
package jinguissl.sample.tls_session_cache

import jinguissl.contract.*

main() {
    println("=== TLS Session Cache Sample ===")

    // 1. 创建缓存（最多 5 条，TTL 120 秒）
    let cache = ContractTlsSessionCache(maxEntries: 5, defaultTtlSeconds: 120)
    println("Initial size: ${cache.size}")

    // 2. 插入会话
    let entry1 = ContractTlsSessionCacheEntry(
        "session-001",
        "api.example.com",
        Array<Byte>(32, repeat: 0xaa),
        Array<Byte>(16, repeat: 0xbb)
    )
    cache.upsert(entry1)
    println("After insert 1: size=${cache.size}")

    let entry2 = ContractTlsSessionCacheEntry(
        "session-002",
        "cdn.example.com",
        Array<Byte>(32, repeat: 0xcc),
        Array<Byte>(16, repeat: 0xdd)
    )
    cache.upsert(entry2)
    println("After insert 2: size=${cache.size}")

    // 3. 查询
    let found = cache.get("session-001")
    match (found) {
        case Some(session) =>
            println()
            println("Found session: ${session.sessionId}")
            println("  Server: ${session.serverName}")
        case None =>
            println("Session session-001 not found (unexpected)")
    }

    let miss = cache.get("nonexistent")
    println("Miss check: ${miss.isNone()}")

    // 4. 统计
    _ = cache.get("session-001")
    _ = cache.get("session-001")
    _ = cache.get("nonexistent-2")
    let stats = cache.stats()
    println()
    println("Stats: hits=${stats.hits} misses=${stats.misses} evictions=${stats.evictions}")

    // 5. 清空
    cache.clear()
    println("After clear: size=${cache.size} has('session-001')=${cache.has("session-001")}")

    println()
    println("TLS session cache sample completed.")
}
