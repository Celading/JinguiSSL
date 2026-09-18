package jinguissl_protocol_crypto_smoke

import std.time.MonoTime
import jinguissl.contract.*

func require(value: Bool): Unit { if (!value) { throw Exception("protocol consumer mismatch") } }

main(): Int64 {
    require(contractBlake2s("abc".toArray()) == [UInt8(0x50),0x8c,0x5e,0x8c,0x32,0x7c,0x14,0xe2,
        0xe1,0xa7,0x2b,0xa3,0x4e,0xeb,0x45,0x2f,0x37,0x45,0x8b,0x20,0x9e,0xd6,0x3a,0x29,0x4d,0x99,0x9b,0x4c,0x86,0x67,0x59,0x82])
    let digest = ContractBlake2sContext(key: [UInt8(1),2,3],digestLength: 16)
    digest.update("a".toArray()); digest.update("bc".toArray())
    require(digest.finalDigest() == contractBlake2s("abc".toArray(),key: [UInt8(1),2,3],digestLength: 16))
    let key = Array<Byte>(32,repeat: 0)
    require(contractHchacha20(key,Array<Byte>(16,repeat: 0)).size == 32)
    let nonce = Array<Byte>(24,repeat: 0)
    let (encrypted,tag) = contractXchacha20Poly1305Encrypt(key,nonce,"payload".toArray(),aad: "header".toArray())
    require(contractXchacha20Poly1305Decrypt(key,nonce,encrypted,tag,aad: "header".toArray()) == "payload".toArray())
    let ctx = ContractAesGcmContext(key)
    let cipher = Array<Byte>(7,repeat: 0)
    let auth = Array<Byte>(16,repeat: 0)
    let clear = Array<Byte>(7,repeat: 0)
    ctx.encryptInto(nonce,"payload".toArray(),cipher,auth)
    ctx.decryptInto(nonce,cipher,auth,clear)
    require(clear == "payload".toArray())
    ctx.destroy()
    println("direct Contract crypto consumer: passed")

    // Same-host diagnostic only. Existing Auto dispatch; report its actual selection.
    // Separate keys per mode; every invocation uses a unique nonce for that key.
    let engine = contractResolveAesEngine()
    println("AES engine=${engine.active} backend=${engine.backend} accelerated=${engine.accelerated}")
    for (reuse in [false,true]) {
        let benchKey = Array<Byte>(32,repeat: if (reuse) { UInt8(2) } else { UInt8(1) })
        let context = ContractAesGcmContext(benchKey)
        let input = Array<Byte>(1024,repeat: 3)
        let output = Array<Byte>(1024,repeat: 0)
        let outputTag = Array<Byte>(16,repeat: 0)
        var counter: Int64 = 0
        var checksum: Int64 = 0
        for (sample in 0..7) {
            let start = MonoTime.now()
            for (_ in 0..64) {
                let iv = Array<Byte>(12,repeat: 0)
                iv[10] = UInt8(counter/256); iv[11] = UInt8(counter%256); counter += 1
                if (reuse) {
                    context.encryptInto(iv,input,output,outputTag)
                    checksum += Int64(output[0]) + Int64(outputTag[0])
                } else {
                    let result = contractAesGcmEncrypt(benchKey,iv,input)
                    checksum += Int64(result.ciphertext[0]) + Int64(result.tag[0])
                }
            }
            let elapsed = (MonoTime.now()-start).toNanoseconds()
            if (sample >= 2) { println("aes-gcm reuse=${reuse} bytes=65536 elapsed_ns=${elapsed}") }
        }
        context.destroy()
        println("benchmark checksum=${checksum}")
    }
    0
}
