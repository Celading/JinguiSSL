package jinguissl.live

import std.collection.ArrayList
import jinguissl_core.crypto.digest.{sha256, sha384}
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.tls.{
    TLS13_CIPHER_SUITE_AES_256_GCM_SHA384,
    tls13ComputeFinishedVerifyData,
    tls13DecodeEncryptedExtensionsSummary,
    tls13ExtractClientServerName,
    tlsEncodeFinishedHandshake
}

public class ContractTls13WireDerivedClientHandshakeRequest {
    public let clientHello: ContractTls13HttpClientHelloX25519
    public let trust: ContractHttpClientTlsTrustRequest
    public let recordResult: ContractTls13IncrementalHandshakeResult

    public init(
        clientHello: ContractTls13HttpClientHelloX25519,
        trust: ContractHttpClientTlsTrustRequest,
        recordResult: ContractTls13IncrementalHandshakeResult
    ) {
        this.clientHello = clientHello
        this.trust = trust
        this.recordResult = recordResult
    }
}

public class ContractTls13WireDerivedClientHandshakeRuntime {
    public let runtime: ContractTls13HttpClientVerifiedSessionRuntime
    public let mappedFlight: ContractTls13ProtectedServerFlightMapping
    public let clientFinished: ContractTls13ClientFinishedOutput

    public init(
        runtime: ContractTls13HttpClientVerifiedSessionRuntime,
        mappedFlight: ContractTls13ProtectedServerFlightMapping,
        clientFinished: ContractTls13ClientFinishedOutput
    ) {
        this.runtime = runtime
        this.mappedFlight = mappedFlight
        this.clientFinished = clientFinished
    }
}

public class ContractTls13WireDerivedClientHandshakeOutcome {
    public let ok: Bool
    public let status: ContractTls13IncrementalHandshakeStatus
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?ContractTls13WireDerivedClientHandshakeRuntime
    public let peerAlert: ?ContractTlsAlertMessage
    public let recordsObserved: Int64
    public let pendingBytes: Array<Byte>
    public let needBytes: Int64

    public init(
        ok: Bool,
        status: ContractTls13IncrementalHandshakeStatus,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?ContractTls13WireDerivedClientHandshakeRuntime = None,
        peerAlert!: ?ContractTlsAlertMessage = None,
        recordsObserved!: Int64 = 0,
        pendingBytes!: Array<Byte> = [],
        needBytes!: Int64 = 0
    ) {
        if (message.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 wire-derived client handshake outcome message must not be empty"
            )
        }
        if (recordsObserved < 0 || needBytes < 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 wire-derived client handshake outcome counters must be >= 0"
            )
        }
        if (ok && status != ContractTls13IncrementalHandshakeStatus.Completed) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 wire-derived client handshake success must use COMPLETED status"
            )
        }
        if (!ok && status == ContractTls13IncrementalHandshakeStatus.Completed) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 wire-derived client handshake failure must not use COMPLETED status"
            )
        }
        if (ok) {
            if (let Some(_value) <- result) {
                ()
            } else {
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "TLS1.3 wire-derived client handshake success must carry result"
                )
            }
            if (let Some(_value) <- code) {
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "TLS1.3 wire-derived client handshake success must not carry ContractErrorCode"
                )
            }
            if (let Some(_value) <- igniteCode) {
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "TLS1.3 wire-derived client handshake success must not carry Ignite error code"
                )
            }
        } else {
            if (let Some(_value) <- result) {
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "TLS1.3 wire-derived client handshake failure must not carry result"
                )
            }
        }
        this.ok = ok
        this.status = status
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.result = result
        this.peerAlert = peerAlert
        this.recordsObserved = recordsObserved
        this.pendingBytes = pendingBytes.clone()
        this.needBytes = needBytes
    }
}

private class C188WireDerivedArtifacts {
    let serverFlight: ContractTls13HttpServerFlight
    let mappedFlight: ContractTls13ProtectedServerFlightMapping
    let clientFinished: ContractTls13ClientFinishedOutput

    init(
        serverFlight: ContractTls13HttpServerFlight,
        mappedFlight: ContractTls13ProtectedServerFlightMapping,
        clientFinished: ContractTls13ClientFinishedOutput
    ) {
        this.serverFlight = serverFlight
        this.mappedFlight = mappedFlight
        this.clientFinished = clientFinished
    }
}

private class C188WireDerivedAttempt {
    let failure: ?ContractTls13WireDerivedClientHandshakeOutcome
    let artifacts: ?C188WireDerivedArtifacts

    init(
        failure!: ?ContractTls13WireDerivedClientHandshakeOutcome = None,
        artifacts!: ?C188WireDerivedArtifacts = None
    ) {
        if (let Some(_failure) <- failure) {
            if (let Some(_artifacts) <- artifacts) {
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "TLS1.3 wire-derived attempt cannot carry failure and artifacts together"
                )
            }
        }
        this.failure = failure
        this.artifacts = artifacts
    }
}

public func contractTls13OpenHttpClientRuntimeFromWireDerivedServerFlight(
    clientHello: ContractTls13HttpClientHelloX25519,
    trust: ContractHttpClientTlsTrustRequest,
    recordResult: ContractTls13IncrementalHandshakeResult
): ContractTls13WireDerivedClientHandshakeRuntime {
    let outcome = contractTryTls13OpenHttpClientRuntimeFromWireDerivedServerFlight(
        clientHello,
        trust,
        recordResult
    )
    if (let Some(result) <- outcome.result) {
        return result
    }
    let code = match (outcome.code) {
        case Some(value) => value
        case None => ContractErrorCode.VerifyFailed
    }
    throw ContractException(code, outcome.message)
}

public func contractTls13OpenHttpClientRuntimeFromWireDerivedServerFlightRequest(
    request: ContractTls13WireDerivedClientHandshakeRequest
): ContractTls13WireDerivedClientHandshakeRuntime {
    contractTls13OpenHttpClientRuntimeFromWireDerivedServerFlight(
        request.clientHello,
        request.trust,
        request.recordResult
    )
}

public func contractTryTls13OpenHttpClientRuntimeFromWireDerivedServerFlight(
    clientHello: ContractTls13HttpClientHelloX25519,
    trust: ContractHttpClientTlsTrustRequest,
    recordResult: ContractTls13IncrementalHandshakeResult
): ContractTls13WireDerivedClientHandshakeOutcome {
    let mapAttempt = c188TryMapWireDerivedServerFlight(clientHello, recordResult)
    if (let Some(failure) <- mapAttempt.failure) {
        return failure
    }
    let artifacts = match (mapAttempt.artifacts) {
        case Some(value) => value
        case None => return c188WireFailure(
            ContractTls13IncrementalHandshakeStatus.Malformed,
            "TLS1.3 wire-derived server flight artifacts are unavailable",
            ContractErrorCode.InternalError,
            recordResult.records.size
        )
    }

    let runtimeOutcome = tls13TryOpenVerifiedClientFlightRuntime(
        clientHello,
        artifacts.serverFlight,
        trust,
        recordResult
    )
    if (!runtimeOutcome.ok) {
        return ContractTls13WireDerivedClientHandshakeOutcome(
            false,
            runtimeOutcome.status,
            runtimeOutcome.message,
            code: runtimeOutcome.code,
            igniteCode: runtimeOutcome.igniteCode,
            peerAlert: runtimeOutcome.peerAlert,
            recordsObserved: runtimeOutcome.recordsObserved,
            pendingBytes: runtimeOutcome.pendingBytes,
            needBytes: runtimeOutcome.needBytes
        )
    }
    let runtime = match (runtimeOutcome.runtime) {
        case Some(value) => value
        case None => return c188WireFailure(
            ContractTls13IncrementalHandshakeStatus.Malformed,
            "TLS1.3 wire-derived runtime result is unavailable",
            ContractErrorCode.InternalError,
            recordResult.records.size
        )
    }

    ContractTls13WireDerivedClientHandshakeOutcome(
        true,
        ContractTls13IncrementalHandshakeStatus.Completed,
        "TLS1.3 wire-derived server flight mapped and client runtime is ready",
        result: Some(ContractTls13WireDerivedClientHandshakeRuntime(
            runtime,
            artifacts.mappedFlight,
            artifacts.clientFinished
        )),
        recordsObserved: recordResult.records.size
    )
}

public func contractTryTls13OpenHttpClientRuntimeFromWireDerivedServerFlightRequest(
    request: ContractTls13WireDerivedClientHandshakeRequest
): ContractTls13WireDerivedClientHandshakeOutcome {
    contractTryTls13OpenHttpClientRuntimeFromWireDerivedServerFlight(
        request.clientHello,
        request.trust,
        request.recordResult
    )
}

private func c188TryMapWireDerivedServerFlight(
    clientHello: ContractTls13HttpClientHelloX25519,
    recordResult: ContractTls13IncrementalHandshakeResult
): C188WireDerivedAttempt {
    if (recordResult.status == ContractTls13IncrementalHandshakeStatus.NeedMoreBytes) {
        return C188WireDerivedAttempt(failure: Some(ContractTls13WireDerivedClientHandshakeOutcome(
            false,
            ContractTls13IncrementalHandshakeStatus.NeedMoreBytes,
            recordResult.message,
            recordsObserved: recordResult.records.size,
            pendingBytes: recordResult.pendingBytes,
            needBytes: recordResult.needBytes
        )))
    }
    if (recordResult.status == ContractTls13IncrementalHandshakeStatus.PeerAlert) {
        return C188WireDerivedAttempt(failure: Some(ContractTls13WireDerivedClientHandshakeOutcome(
            false,
            ContractTls13IncrementalHandshakeStatus.PeerAlert,
            recordResult.message,
            code: Some(ContractErrorCode.VerifyFailed),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(ContractErrorCode.VerifyFailed)),
            peerAlert: recordResult.peerAlert,
            recordsObserved: recordResult.records.size,
            pendingBytes: recordResult.pendingBytes,
            needBytes: recordResult.needBytes
        )))
    }
    if (recordResult.status == ContractTls13IncrementalHandshakeStatus.Malformed ||
        recordResult.status == ContractTls13IncrementalHandshakeStatus.PolicyRejected ||
        recordResult.status == ContractTls13IncrementalHandshakeStatus.VerificationFailed ||
        recordResult.status == ContractTls13IncrementalHandshakeStatus.Timeout ||
        recordResult.status == ContractTls13IncrementalHandshakeStatus.Cancelled) {
        return C188WireDerivedAttempt(failure: Some(c188FailureFromCollector(recordResult)))
    }
    if (recordResult.status != ContractTls13IncrementalHandshakeStatus.RecordsReady &&
        recordResult.status != ContractTls13IncrementalHandshakeStatus.Completed) {
        return C188WireDerivedAttempt(failure: Some(c188WireFailure(
            ContractTls13IncrementalHandshakeStatus.Malformed,
            "TLS1.3 wire-derived server flight record status is not usable",
            ContractErrorCode.BadInput,
            recordResult.records.size
        )))
    }
    if (recordResult.pendingBytes.size > 0) {
        return C188WireDerivedAttempt(failure: Some(ContractTls13WireDerivedClientHandshakeOutcome(
            false,
            ContractTls13IncrementalHandshakeStatus.NeedMoreBytes,
            "TLS1.3 wire-derived server flight still has pending partial bytes",
            recordsObserved: recordResult.records.size,
            pendingBytes: recordResult.pendingBytes,
            needBytes: recordResult.needBytes
        )))
    }
    let helloIndex = tls13ClientServerHelloRecordIndex(recordResult.records)
    if (helloIndex < 0) {
        return C188WireDerivedAttempt(failure: Some(ContractTls13WireDerivedClientHandshakeOutcome(false,
            ContractTls13IncrementalHandshakeStatus.Malformed, "TLS1.3 compatibility CCS or flight limit is invalid",
            code: Some(ContractErrorCode.BadInput), recordsObserved: recordResult.records.size)))
    }
    if (helloIndex == recordResult.records.size) {
        return C188WireDerivedAttempt(failure: Some(ContractTls13WireDerivedClientHandshakeOutcome(
            false, ContractTls13IncrementalHandshakeStatus.NeedMoreBytes,
            "TLS1.3 server flight needs ServerHello", needBytes: 1)))
    }
    let serverHelloRecord = recordResult.records[helloIndex]
    if (serverHelloRecord.version != ContractTlsVersion.Tls12 ||
        serverHelloRecord.contentType != ContractTlsRecordContentType.Handshake) {
        return C188WireDerivedAttempt(failure: Some(c188WireFailure(
            ContractTls13IncrementalHandshakeStatus.Malformed,
            "TLS1.3 wire-derived server flight first record is not ServerHello handshake",
            ContractErrorCode.BadInput, recordResult.records.size)))
    }
    try {
        let read = tls13ReadClientHandshakeMessages(clientHello, serverHelloRecord.payload, recordResult.records)
        if (let Some(alert) <- read.peerAlert) {
            return C188WireDerivedAttempt(failure: Some(ContractTls13WireDerivedClientHandshakeOutcome(
                false, ContractTls13IncrementalHandshakeStatus.PeerAlert, "TLS1.3 protected peer alert",
                code: Some(ContractErrorCode.VerifyFailed), peerAlert: Some(alert), recordsObserved: recordResult.records.size)))
        }
        if (!read.complete) {
            return C188WireDerivedAttempt(failure: Some(ContractTls13WireDerivedClientHandshakeOutcome(
                false, ContractTls13IncrementalHandshakeStatus.NeedMoreBytes,
                "TLS1.3 server flight needs more handshake message bytes",
                recordsObserved: recordResult.records.size, needBytes: read.needBytes)))
        }
        let encryptedExtensions = read.messages[0]
        let certificateHandshake = read.messages[1]
        let certificateVerifyHandshake = read.messages[2]
        let finishedHandshake = read.messages[3]
        let (selectedAlpn, acknowledgedServerName) = tls13DecodeEncryptedExtensionsSummary(encryptedExtensions)
        let requestedServerName = tls13ExtractClientServerName(clientHello.encodedClientHello)
        let transcriptHash = c188Tls13ServerFlightTranscriptHash(read.binding.cipherSuite,
            clientHello.encodedClientHello, serverHelloRecord.payload, encryptedExtensions)
        let fullTranscriptHash = c188Tls13FullServerFlightTranscriptHash(read.binding.cipherSuite,
            clientHello.encodedClientHello, serverHelloRecord.payload, encryptedExtensions,
            certificateHandshake, certificateVerifyHandshake, finishedHandshake)
        let encodedClientFinished = tlsEncodeFinishedHandshake(
            tls13ComputeFinishedVerifyData(read.secrets.clientHsTrafficSecret, fullTranscriptHash))
        let encodedClientFinishedRecord = read.channel.seal(ContractTlsRecordContentType.Handshake, encodedClientFinished)
        let serverFlight = ContractTls13HttpServerFlight(serverHelloRecord.payload, encryptedExtensions,
            certificateHandshake, certificateVerifyHandshake, finishedHandshake, transcriptHash,
            selectedAlpn: selectedAlpn, requestedServerName: requestedServerName,
            acknowledgedServerName: acknowledgedServerName)
        let mapped = ContractTls13ProtectedServerFlightMapping(serverFlight, serverHelloRecord.payload,
            encryptedExtensions, certificateHandshake, certificateVerifyHandshake, finishedHandshake, read.decodedRecords)
        return C188WireDerivedAttempt(artifacts: Some(C188WireDerivedArtifacts(serverFlight, mapped,
            ContractTls13ClientFinishedOutput(encodedClientFinished, encodedClientFinishedRecord))))
    } catch (e: ContractException) {
        let status = if (e.code == ContractErrorCode.BadInput) {
            ContractTls13IncrementalHandshakeStatus.Malformed
        } else { ContractTls13IncrementalHandshakeStatus.VerificationFailed }
        return C188WireDerivedAttempt(failure: Some(c188WireFailure(status, e.message, e.code, recordResult.records.size)))
    } catch (e: CryptoException) {
        return C188WireDerivedAttempt(failure: Some(c188WireFailure(
            ContractTls13IncrementalHandshakeStatus.VerificationFailed,
            "TLS1.3 wire-derived crypto mapping failed: ${e.message}", ContractErrorCode.VerifyFailed, recordResult.records.size)))
    }
}

private func c188Tls13ServerFlightTranscriptHash(
    cipherSuite: Int64,
    encodedClientHello: Array<Byte>,
    serverHello: Array<Byte>,
    encryptedExtensions: Array<Byte>
): Array<Byte> {
    c188Tls13HashForCipherSuite(
        cipherSuite,
        c188ConcatBytes([encodedClientHello, serverHello, encryptedExtensions])
    )
}

private func c188Tls13FullServerFlightTranscriptHash(
    cipherSuite: Int64,
    encodedClientHello: Array<Byte>,
    serverHello: Array<Byte>,
    encryptedExtensions: Array<Byte>,
    certificateHandshake: Array<Byte>,
    certificateVerifyHandshake: Array<Byte>,
    finishedHandshake: Array<Byte>
): Array<Byte> {
    c188Tls13HashForCipherSuite(
        cipherSuite,
        c188ConcatBytes([
            encodedClientHello,
            serverHello,
            encryptedExtensions,
            certificateHandshake,
            certificateVerifyHandshake,
            finishedHandshake
        ])
    )
}

private func c188Tls13HashForCipherSuite(cipherSuite: Int64, data: Array<Byte>): Array<Byte> {
    if (cipherSuite == TLS13_CIPHER_SUITE_AES_256_GCM_SHA384) {
        return sha384(data)
    }
    sha256(data)
}

private func c188ConcatBytes(parts: Array<Array<Byte>>): Array<Byte> {
    let out = ArrayList<Byte>()
    for (part in parts) {
        for (b in part) {
            out.add(b)
        }
    }
    out.toArray()
}

private func c188FailureFromCollector(
    recordResult: ContractTls13IncrementalHandshakeResult
): ContractTls13WireDerivedClientHandshakeOutcome {
    let code = match (recordResult.code) {
        case Some(value) => value
        case None => ContractErrorCode.BadInput
    }
    ContractTls13WireDerivedClientHandshakeOutcome(
        false,
        recordResult.status,
        recordResult.message,
        code: Some(code),
        igniteCode: Some(contractMapToIgniteCryptoErrorCode(code)),
        peerAlert: recordResult.peerAlert,
        recordsObserved: recordResult.records.size,
        pendingBytes: recordResult.pendingBytes,
        needBytes: recordResult.needBytes
    )
}

private func c188WireFailure(
    status: ContractTls13IncrementalHandshakeStatus,
    message: String,
    code: ContractErrorCode,
    recordsObserved: Int64
): ContractTls13WireDerivedClientHandshakeOutcome {
    ContractTls13WireDerivedClientHandshakeOutcome(
        false,
        status,
        message,
        code: Some(code),
        igniteCode: Some(contractMapToIgniteCryptoErrorCode(code)),
        recordsObserved: recordsObserved
    )
}

private func c188BytesEqual(left: Array<Byte>, right: Array<Byte>): Bool {
    if (left.size != right.size) {
        return false
    }
    var i: Int64 = 0
    while (i < left.size) {
        if (left[i] != right[i]) {
            return false
        }
        i += 1
    }
    true
}
