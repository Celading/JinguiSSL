package jinguissl.live

import std.collection.ArrayList
import jinguissl_core.crypto.digest.{sha256, sha384}
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.tls.{
    TLS13_CIPHER_SUITE_AES_256_GCM_SHA384, Tls13HandshakeSecrets,
    tlsDecodeClientHelloHandshake, tlsDecodeEncryptedExtensionsHandshake, tlsParseAlpnExtension,
    tls13DeriveSecretsFromX25519ForCipherSuite, tls13ExtractServerX25519KeyShare
}

// Record boundaries carry encryption sequence numbers, not handshake message boundaries.
// Limits bound caller-supplied flights without retaining repeated partial-buffer copies.
private let TLS13_CLIENT_MAX_MESSAGE_BYTES: Int64 = 1048576
private let TLS13_CLIENT_MAX_FLIGHT_BYTES: Int64 = 4194304
private let TLS13_CLIENT_MAX_FLIGHT_RECORDS: Int64 = 4096

class Tls13ClientHandshakeMessages {
    let messages: Array<Array<Byte>>
    let decodedRecords: Int64
    let complete: Bool
    let needBytes: Int64
    let channel: ContractTlsRecordChannel
    let secrets: Tls13HandshakeSecrets
    let binding: ContractTls13CipherBinding
    let peerAlert: ?ContractTlsAlertMessage

    init(messages: Array<Array<Byte>>, decodedRecords: Int64, complete: Bool, needBytes: Int64,
        channel: ContractTlsRecordChannel, secrets: Tls13HandshakeSecrets,
        binding: ContractTls13CipherBinding, peerAlert!: ?ContractTlsAlertMessage = None) {
        this.messages = messages
        this.decodedRecords = decodedRecords
        this.complete = complete
        this.needBytes = needBytes
        this.channel = channel
        this.secrets = secrets
        this.binding = binding
        this.peerAlert = peerAlert
    }
}

func tls13ClientServerHelloRecordIndex(records: Array<ContractTls13IncrementalRecordFrame>): Int64 {
    if (records.size > TLS13_CLIENT_MAX_FLIGHT_RECORDS) { return -1 }
    var index: Int64 = 0
    while (index < records.size && records[index].contentType == ContractTlsRecordContentType.ChangeCipherSpec) {
        let record = records[index]
        if (record.version != ContractTlsVersion.Tls12 || record.payload != [UInt8(1)]) { return -1 }
        index += 1
    }
    index
}

func tls13ReadClientHandshakeMessages(
    clientHello: ContractTls13HttpClientHelloX25519,
    serverHello: Array<Byte>,
    records: Array<ContractTls13IncrementalRecordFrame>
): Tls13ClientHandshakeMessages {
    if (records.size > TLS13_CLIENT_MAX_FLIGHT_RECORDS) {
        throw ContractException(ContractErrorCode.BadInput, "TLS1.3 server flight record limit exceeded")
    }
    let binding = contractTls13ResolveCipherBindingFromServerHello(serverHello)
    let transcript = ArrayList<Byte>()
    for (bytes in [clientHello.encodedClientHello, serverHello]) {
        for (b in bytes) { transcript.add(b) }
    }
    let helloHash = if (binding.cipherSuite == TLS13_CIPHER_SUITE_AES_256_GCM_SHA384) {
        sha384(transcript.toArray())
    } else { sha256(transcript.toArray()) }
    let secrets = tls13DeriveSecretsFromX25519ForCipherSuite(
        clientHello.clientPrivateKey, tls13ExtractServerX25519KeyShare(serverHello), helloHash, binding.cipherSuite)
    let (clientKey, clientIv) = contractTls13DeriveApplicationTrafficKeyIv(
        secrets.clientHsTrafficSecret, keyLen: binding.keyLen, ivLen: binding.ivLen)
    let (serverKey, serverIv) = contractTls13DeriveApplicationTrafficKeyIv(
        secrets.serverHsTrafficSecret, keyLen: binding.keyLen, ivLen: binding.ivLen)
    let channel = contractTls13CreateClientRecordChannel(
        ContractTls13ApplicationKeyMaterial(clientKey, clientIv, serverKey, serverIv), algorithm: binding.algorithm)
    let messages = ArrayList<Array<Byte>>()
    let pending = ArrayList<Byte>()
    let expectedTypes = [UInt8(8), UInt8(11), UInt8(15), UInt8(20)]
    var messageSize: Int64 = 4
    var total: Int64 = 0
    var decoded: Int64 = 0
    var recordIndex: Int64 = tls13ClientServerHelloRecordIndex(records) + 1
    while (recordIndex < records.size) {
        let record = records[recordIndex]
        if (record.contentType == ContractTlsRecordContentType.ChangeCipherSpec) {
            if (record.version != ContractTlsVersion.Tls12 || record.payload != [UInt8(1)] || pending.size != 0) {
                throw ContractException(ContractErrorCode.BadInput, "TLS1.3 compatibility ChangeCipherSpec record is malformed or interrupts a handshake message")
            }
            recordIndex += 1
            continue
        }
        if (record.version != ContractTlsVersion.Tls12 || record.contentType != ContractTlsRecordContentType.ApplicationData) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 encrypted handshake record envelope is invalid")
        }
        let plain = try { channel.open(record.encodedRecord) } catch (e: ContractException) {
            throw ContractException(ContractErrorCode.VerifyFailed, e.message)
        }
        decoded += 1
        if (plain.contentType == ContractTlsRecordContentType.Alert) {
            if (pending.size != 0) {
                throw ContractException(ContractErrorCode.BadInput, "TLS1.3 alert interrupts a handshake message")
            }
            return Tls13ClientHandshakeMessages(messages.toArray(), decoded, false, 0, channel, secrets, binding,
                peerAlert: Some(contractTlsDecodeAlertPayload(plain.fragment)))
        }
        if (plain.contentType != ContractTlsRecordContentType.Handshake || plain.fragment.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 server flight record did not open as a nonempty HANDSHAKE")
        }
        total += plain.fragment.size
        if (total > TLS13_CLIENT_MAX_FLIGHT_BYTES) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 server flight byte limit exceeded")
        }
        var offset: Int64 = 0
        for (b in plain.fragment) {
            pending.add(b)
            offset += 1
            if (pending.size == 4) {
                if (pending[0] != expectedTypes[messages.size]) {
                    throw ContractException(ContractErrorCode.BadInput, "TLS1.3 server handshake message order is invalid")
                }
                let bodySize = (Int64(pending[1]) << 16) + (Int64(pending[2]) << 8) + Int64(pending[3])
                if (bodySize > TLS13_CLIENT_MAX_MESSAGE_BYTES) {
                    throw ContractException(ContractErrorCode.BadInput, "TLS1.3 handshake message length limit exceeded")
                }
                messageSize = bodySize + 4
            }
            if (pending.size == messageSize) {
                messages.add(pending.toArray())
                if (messages.size == 1) {
                    tls13ValidateClientEncryptedExtensions(clientHello, messages[0])
                }
                pending.clear()
                messageSize = 4
                if (messages.size == 4) {
                    // Finished changes traffic keys; it must end at a record boundary.
                    if (offset != plain.fragment.size) {
                        throw ContractException(ContractErrorCode.BadInput, "TLS1.3 bytes after Finished violate the key-change record boundary")
                    }
                    return Tls13ClientHandshakeMessages(messages.toArray(), decoded, true, 0, channel, secrets, binding)
                }
            }
        }
        recordIndex += 1
    }
    Tls13ClientHandshakeMessages(messages.toArray(), decoded, false,
        if (pending.size == 0) { Int64(1) } else { messageSize - pending.size }, channel, secrets, binding)
}

func tls13RequireExpectedClientHandshakeMessages(
    read: Tls13ClientHandshakeMessages, expected: ContractTls13HttpServerFlight
): Unit {
    let messages = [expected.encryptedExtensions, expected.certificateHandshake,
        expected.certificateVerifyHandshake, expected.finishedHandshake]
    let labels = ["EncryptedExtensions", "Certificate", "CertificateVerify", "Finished"]
    var index: Int64 = 0
    while (index < messages.size) {
        if (read.messages[index] != messages[index]) {
            throw ContractException(ContractErrorCode.VerifyFailed, "TLS1.3 protected server flight ${labels[index]} payload does not match expected flight")
        }
        index += 1
    }
}

// Reject unsolicited, duplicate or misplaced extensions instead of inferring a canonical byte encoding.
private func tls13ValidateClientEncryptedExtensions(
    clientHello: ContractTls13HttpClientHelloX25519, encoded: Array<Byte>
): Unit {
    try {
        let hello = tlsDecodeClientHelloHandshake(clientHello.encodedClientHello)
        let extensions = tlsDecodeEncryptedExtensionsHandshake(encoded).extensions
        let seen = ArrayList<Int64>()
        for (ext in extensions) {
            if (seen.contains(ext.extType) || (ext.extType != 0 && ext.extType != 10 && ext.extType != 16)) {
                throw ContractException(ContractErrorCode.BadInput, "TLS1.3 duplicate or misplaced EncryptedExtensions extension")
            }
            seen.add(ext.extType)
            var offered = false
            for (offer in hello.extensions) {
                if (offer.extType == ext.extType) { offered = true }
            }
            if (!offered) {
                throw ContractException(ContractErrorCode.BadInput, "TLS1.3 unsolicited EncryptedExtensions extension")
            }
            if (ext.extType == 0 && ext.data.size != 0) {
                throw ContractException(ContractErrorCode.BadInput, "TLS1.3 server_name acknowledgement must be empty")
            }
            if (ext.extType == 16) {
                let protocols = tlsParseAlpnExtension(ext)
                if (protocols.size != 1 || protocols[0].size == 0) {
                    throw ContractException(ContractErrorCode.BadInput, "TLS1.3 ALPN must select exactly one protocol")
                }
                var selectedOffered = false
                for (offer in hello.extensions) {
                    if (offer.extType == 16 && tlsParseAlpnExtension(offer).contains(protocols[0])) { selectedOffered = true }
                }
                if (!selectedOffered) {
                    throw ContractException(ContractErrorCode.BadInput, "TLS1.3 ALPN selection was not offered")
                }
            }
            if (ext.extType == 10) {
                if (ext.data.size < 4 || ext.data.size % 2 != 0 ||
                    (Int64(ext.data[0]) << 8) + Int64(ext.data[1]) != ext.data.size - 2) {
                    throw ContractException(ContractErrorCode.BadInput, "TLS1.3 supported_groups extension length is invalid")
                }
            }
        }
    } catch (e: CryptoException) {
        throw ContractException(ContractErrorCode.BadInput, "TLS1.3 EncryptedExtensions encoding is invalid: ${e.message}")
    }
}
