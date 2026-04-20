package jinguissl_http_server_attach_planning_smoke

import std.collection.ArrayList
import std.fs.File
import jinguissl.contract.*

main(): Int64 {
    try {
        runHttpServerPlanningGateDemo()
        runHttpServerPlanningMaterialDemo()
        0
    } catch (e: Exception) {
        println("fatal=${e}")
        1
    }
}

private func runHttpServerPlanningGateDemo(): Unit {
    let planningGate = contractRequireProviderConsumptionGate(
        ContractProviderConsumptionPath.HttpServerAttachPlanning
    )
    let stableGate = contractDescribeProviderConsumptionGate(
        ContractProviderConsumptionPath.HttpServerStableAttach
    )
    let stableOutcome = contractTryRequireProviderConsumptionGate(
        ContractProviderConsumptionPath.HttpServerStableAttach
    )

    println("== http-server-planning-gate ==")
    println("planning_path=${planningGate.path}")
    println("planning_status=${planningGate.status}")
    println("planning_selected_entry=${planningGate.selectedEntryId}")
    println("planning_public_path=${planningGate.publicPath}")
    println("planning_release_path=${planningGate.releasePath}")
    println("planning_ready_now=${planningGate.readyNow}")
    println("planning_candidate_order=${joinStrings(planningGate.candidateOrder)}")
    println("planning_fallback_target=${planningGate.fallbackTarget}")
    println("planning_attach_meaning=${planningGate.guide.attachPlanMeaning}")
    println("boundary_status=${planningGate.attachBoundary.status}")
    println("boundary_stable_attach=${planningGate.attachBoundary.stableAttach}")
    println("boundary_blocking_layer=${planningGate.attachBoundary.blockingLayer}")
    println("boundary_recommended_fallback=${planningGate.attachBoundary.recommendedFallback}")
    println("stable_attach_public_path=${stableGate.publicPath}")
    println("stable_attach_ready_now=${stableGate.readyNow}")
    println("stable_attach_blocked=${joinStrings(stableGate.blockedCandidates)}")
    println("stable_attach_try_ok=${stableOutcome.ok}")
    println("stable_attach_try_code=${optionalContractCodeText(stableOutcome.code)}")
    println("stable_attach_try_ignite=${optionalIgniteCodeText(stableOutcome.igniteCode)}")
    println("planning_note=planning-only means you may validate inputs and prepare normalized TLS material now, but final listener attach must remain in upper-layer glue")
}

private func runHttpServerPlanningMaterialDemo(): Unit {
    let leafPem = readText("../../testdata/x509/policy_leaf.pem")
    let intermediatePem = readText("../../testdata/x509/policy_intermediate.pem")
    let certChainPem = "${leafPem}\n${intermediatePem}"
    let leafKeyPem = readText("../../testdata/x509/policy_leaf_key_pkcs8.pem")
    let wrongKeyPem = readText("../../testdata/x509/rsa_2048_pkcs8.pem")

    let request = ContractHttpServerTlsConfigRequest(
        certChainPem,
        leafKeyPem,
        alpnProtocols: [" H2 ", "http/1.1", "h2"],
        requireHttp2Alpn: true
    )
    let validated = contractValidateHttpServerTlsConfigRequest(request)
    let prepared = contractPrepareHttpServerTlsMaterialRequest(request)

    let missingH2Outcome = contractTryPrepareHttpServerTlsMaterialRequest(
        ContractHttpServerTlsConfigRequest(
            certChainPem,
            leafKeyPem,
            alpnProtocols: ["http/1.1"],
            requireHttp2Alpn: true
        )
    )
    let mismatchOutcome = contractTryPrepareHttpServerTlsMaterialRequest(
        ContractHttpServerTlsConfigRequest(
            certChainPem,
            wrongKeyPem,
            alpnProtocols: ["h2", "http/1.1"],
            requireHttp2Alpn: true
        )
    )
    let leafPemPresent = prepared.leafCertificatePem().contains("BEGIN CERTIFICATE")
    let bundlePemPresent = prepared.certificateChainPemBundle().contains("BEGIN CERTIFICATE")
    let privateKeyPresent = prepared.privateKeyPem.contains("BEGIN PRIVATE KEY")

    println("== http-server-planning-material ==")
    println("validation_chain_length=${validated.certificateChainLength}")
    println("validation_leaf_cn=${validated.leafSubjectCommonName}")
    println("validation_issuer_cn=${validated.leafIssuerCommonName}")
    println("validation_key_algorithm=${validated.keyAlgorithm}")
    println("validation_normalized_alpn=${joinStrings(validated.normalizedAlpnProtocols)}")
    println("material_pem_block_count=${prepared.certificateChainPemBlocks.size}")
    println("material_leaf_pem_present=${leafPemPresent}")
    println("material_bundle_present=${bundlePemPresent}")
    println("material_private_key_present=${privateKeyPresent}")
    println("missing_h2_ok=${missingH2Outcome.ok}")
    println("missing_h2_code=${optionalContractCodeText(missingH2Outcome.code)}")
    println("missing_h2_ignite=${optionalIgniteCodeText(missingH2Outcome.igniteCode)}")
    println("key_mismatch_ok=${mismatchOutcome.ok}")
    println("key_mismatch_code=${optionalContractCodeText(mismatchOutcome.code)}")
    println("key_mismatch_ignite=${optionalIgniteCodeText(mismatchOutcome.igniteCode)}")
    println("material_note=successful preparation gives upper layers normalized PEM material for planning, but it still does not create a published listener attach contract")
}

private func joinStrings(values: Array<String>): String {
    var out = ""
    var i = 0
    while (i < values.size) {
        if (i > 0) {
            out += ","
        }
        out += values[i]
        i += 1
    }
    out
}

private func optionalContractCodeText(code: ?ContractErrorCode): String {
    match (code) {
        case Some(value) => value.toString()
        case None => "none"
    }
}

private func optionalIgniteCodeText(code: ?ContractIgniteCryptoErrorCode): String {
    match (code) {
        case Some(value) => value.toString()
        case None => "none"
    }
}

private func readText(path: String): String {
    String.fromUtf8(File.readFrom(path))
}
