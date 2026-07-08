 package jinguissl.tests

 import jinguissl.contract.*

 // Test vectors matching the core-level quic_aead_test.cj
 private let TEST_KEY: Array<Byte> = [
     UInt8(0x1f), UInt8(0x36), UInt8(0x96), UInt8(0x13),
     UInt8(0xdd), UInt8(0x76), UInt8(0xd5), UInt8(0x46),
     UInt8(0x77), UInt8(0x30), UInt8(0xef), UInt8(0xcb),
     UInt8(0xe3), UInt8(0xb1), UInt8(0xa2), UInt8(0x2d)
 ]
 private let TEST_IV: Array<Byte> = [
     UInt8(0xfa), UInt8(0x04), UInt8(0x4b), UInt8(0x2f),
     UInt8(0x42), UInt8(0xa3), UInt8(0xfd), UInt8(0x3b),
     UInt8(0x46), UInt8(0xfb), UInt8(0x25), UInt8(0x5c)
 ]

 @Test
 public class ContractQuicAeadTestSuite {

     @TestCase
     public func testRoundTrip(): Unit {
         let pt = "hello quic".toArray()
         let aad = "aad".toArray()
         let sealed = contractQuicAeadEncrypt(TEST_KEY, TEST_IV, 42, pt, aad)
         @Assert(sealed.size, pt.size + 16)
         let recovered = contractQuicAeadDecrypt(TEST_KEY, TEST_IV, 42, sealed, aad)
         @Assert(recovered, pt)
     }

     @TestCase
     public func testWrongPnFails(): Unit {
         let pt = "hello quic".toArray()
         let aad = "aad".toArray()
         let sealed = contractQuicAeadEncrypt(TEST_KEY, TEST_IV, 7, pt, aad)
         try {
             _ = contractQuicAeadDecrypt(TEST_KEY, TEST_IV, 99, sealed, aad)
             @Fail("AEAD should fail with wrong packet number")
         } catch (_: Exception) {
             @Assert(true)
         }
     }

     @TestCase
     public func testWrongKeyFails(): Unit {
         let pt = "hello quic".toArray()
         let aad = "aad".toArray()
         let sealed = contractQuicAeadEncrypt(TEST_KEY, TEST_IV, 7, pt, aad)
         let badKey = Array<Byte>(16, repeat: 0xab)
         try {
             _ = contractQuicAeadDecrypt(badKey, TEST_IV, 7, sealed, aad)
             @Fail("AEAD should fail with wrong key")
         } catch (_: Exception) {
             @Assert(true)
         }
     }

     @TestCase
     public func testEmptyPlaintext(): Unit {
         let aad = "aad".toArray()
         let sealed = contractQuicAeadEncrypt(TEST_KEY, TEST_IV, 0, [], aad)
         @Assert(sealed.size, 16) // only tag
         let recovered = contractQuicAeadDecrypt(TEST_KEY, TEST_IV, 0, sealed, aad)
         @Assert(recovered, [])
     }

     @TestCase
     public func testDifferentPnChangesCiphertext(): Unit {
         let pt = "hello quic".toArray()
         let aad = "aad".toArray()
         let s1 = contractQuicAeadEncrypt(TEST_KEY, TEST_IV, 1, pt, aad)
         let s2 = contractQuicAeadEncrypt(TEST_KEY, TEST_IV, 2, pt, aad)
         @Assert(s1 != s2, true)
     }
 }
