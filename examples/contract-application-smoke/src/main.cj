package jinguissl_contract_application_smoke

import jinguissl.contract.*

private let SHA256_ABC: String =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

main(): Int64 {
    let payload: Array<Byte> = [0x61, 0x62, 0x63]
    let digest = contractBytesToHexLower(contractSha256(payload))

    if (digest != SHA256_ABC) {
        println("fatal=JinguiSSLContract SHA-256 application smoke mismatch")
        println("actual=${digest}")
        return 1
    }

    println("jinguissl_contract_application_smoke=pass")
    println("sha256_abc=${digest}")
    0
}
