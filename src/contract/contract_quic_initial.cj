 package jinguissl.contract

 import jinguissl_core.crypto.quic.{
     QUIC_SALT_V1 as Core_QUIC_SALT_V1,
     QUIC_SALT_V2 as Core_QUIC_SALT_V2,
     quicInitialSecrets as Core_quicInitialSecrets,
     quicInitialKeyIv as Core_quicInitialKeyIv,
     quicInitialHpKey as Core_quicInitialHpKey,
     quicInitialKeyDerive as Core_quicInitialKeyDerive
 }

 /**
  * QUIC_SALT_V1 — QUIC v1 initial salt (RFC 9001 §5.2), 20 bytes.
  */
 public let QUIC_SALT_V1: Array<Byte> = Core_QUIC_SALT_V1

 /**
  * QUIC_SALT_V2 — QUIC v2 initial salt (RFC 9369 §5.2), 20 bytes.
  */
 public let QUIC_SALT_V2: Array<Byte> = Core_QUIC_SALT_V2

 /**
  * contractQuicInitialSecrets — derive initial secrets for client and server.
  *
  * initial_secret = HKDF-Extract(salt, conn_id)
  * client_secret  = HKDF-Expand-Label(initial_secret, "client in",  32)
  * server_secret  = HKDF-Expand-Label(initial_secret, "server in",  32)
  *
  * @param connId QUIC connection ID
  * @param isV2 true for QUIC v2, false for QUIC v1
  * @returns (client_secret, server_secret) each 32 bytes
  */
 public func contractQuicInitialSecrets(
     connId: Array<Byte>, isV2: Bool
 ): (Array<Byte>, Array<Byte>) {
     Core_quicInitialSecrets(connId, isV2)
 }

 /**
  * contractQuicInitialKeyIv — derive initial key and IV from a traffic secret.
  *
  * key = HKDF-Expand-Label(secret, "quic key" / "quicv2 key",  16)
  * iv  = HKDF-Expand-Label(secret, "quic iv"  / "quicv2 iv",   12)
  *
  * @param secret 32-byte traffic secret (client or server)
  * @param isV2 true for QUIC v2
  * @returns (key, iv)
  */
 public func contractQuicInitialKeyIv(
     secret: Array<Byte>, isV2: Bool
 ): (Array<Byte>, Array<Byte>) {
     Core_quicInitialKeyIv(secret, isV2)
 }

 /**
  * contractQuicInitialHpKey — derive initial header protection key.
  *
  * hp = HKDF-Expand-Label(secret, "quic hp" / "quicv2 hp", 16)
  *
  * @param secret 32-byte traffic secret
  * @param isV2 true for QUIC v2
  * @returns 16-byte header protection key
  */
 public func contractQuicInitialHpKey(
     secret: Array<Byte>, isV2: Bool
 ): Array<Byte> {
     Core_quicInitialHpKey(secret, isV2)
 }

 /**
  * contractQuicInitialKeyDerive — one-shot client-side initial key material.
  *
  * Derives (key, iv, hp_key) from connection ID in a single call.
  *
  * @param connId QUIC connection ID
  * @param isV2 true for QUIC v2
  * @returns (key, iv, hpKey)
  */
 public func contractQuicInitialKeyDerive(
     connId: Array<Byte>, isV2: Bool
 ): (Array<Byte>, Array<Byte>, Array<Byte>) {
     Core_quicInitialKeyDerive(connId, isV2)
 }
