 package jinguissl.contract

 import jinguissl_core.crypto.quic.{
     quicRetryIntegrityTag as Core_quicRetryIntegrityTag,
     quicVerifyRetryIntegrity as Core_quicVerifyRetryIntegrity
 }

 /**
  * contractQuicRetryIntegrityTag — compute Retry Integrity Tag (RFC 9001 §5.8 / RFC 9369 §5.8).
  *
  * aad = concat(len(origDestConnId), origDestConnId, retryPacket)
  * tag = AES-128-GCM(RetryIntegrityKey, RetryIntegrityNonce, nil, aad)[0..16]
  *
  * @param retryPacket the Retry packet bytes WITHOUT the trailing 16-byte tag
  * @param origDestConnId the Original Destination Connection ID from the client's Initial
  * @param isV2 true for QUIC v2, false for QUIC v1
  * @returns 16-byte integrity tag
  */
 public func contractQuicRetryIntegrityTag(
     retryPacket: Array<Byte>,
     origDestConnId: Array<Byte>,
     isV2: Bool
 ): Array<Byte> {
     Core_quicRetryIntegrityTag(retryPacket, origDestConnId, isV2)
 }

 /**
  * contractQuicVerifyRetryIntegrity — verify Retry Integrity Tag.
  *
  * @param retryPacketWithTag the full Retry packet INCLUDING the 16-byte tag
  * @param origDestConnId the Original Destination Connection ID
  * @param isV2 true for QUIC v2
  * @returns true if tag is valid, false otherwise
  */
 public func contractQuicVerifyRetryIntegrity(
     retryPacketWithTag: Array<Byte>,
     origDestConnId: Array<Byte>,
     isV2: Bool
 ): Bool {
     Core_quicVerifyRetryIntegrity(retryPacketWithTag, origDestConnId, isV2)
 }
