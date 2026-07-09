/**
 * AES 后端探测与引擎选择示例
 */
package jinguissl.sample.aes

import jinguissl.contract.*

main() {
    println("=== AES Backend Readiness Sample ===")

    // 1. 列举所有硬件挂载点
    let mounts = contractAesListHardwareMountPoints()
    println("Hardware Mount Points (${mounts.size}):")
    for (mount in mounts) {
        println("  ${mount.backend}: available=${mount.available} accelerated=${mount.accelerated}")
    }

    // 2. 推荐后端
    let recommendation = contractRecommendAesBackend()
    println()
    println("Recommended Backend: ${recommendation.backendHint}")
    println("  Readiness: ${recommendation.readiness.toString()}")
    println("  Reason: ${recommendation.reason}")

    // 3. 解析引擎
    let engine = contractResolveAesEngine(backendHint: "shim")
    println()
    println("Resolved Engine:")
    println("  Requested: ${engine.requested.toString()}")
    println("  Active: ${engine.active.toString()}")
    println("  Backend: ${engine.backend}")
    println("  Accelerated: ${engine.accelerated}")

    // 4. 启动自检
    let check = contractAesStartupSelfCheck(backendHint: "shim")
    println()
    println("Startup Self-Check:")
    println("  Effective Hint: ${check.effectiveBackendHint}")
    println("  Accelerated Ready: ${check.acceleratedBackendReady}")
    println("  Mount Points: ${check.mountPoints.size}")

    // 5. 当前版本 release plan
    let plan = contractAesCurrentReleasePlan(backendHint: "shim")
    println()
    println("Release Plan:")
    println("  Current Release: ${plan.currentReleaseSeries}")
    println("  Primary Backend: ${plan.primaryBackend}")
    println("  Warnings: ${plan.warnings}")

    // 6. Try 版本（安全处理不可用情况）
    let tryResult = contractTryResolveAesEngine(
        requestedEngine: ContractAesEngineKind.Hardware,
        backendHint: "none"
    )
    println()
    println("Try Engine (Hardware, none): ok=${tryResult.ok}")
    match (tryResult.code) {
        case Some(code) => println("  Code: ${code.toString()}")
        case None => ()
    }

    println()
    println("AES readiness sample completed.")
}
