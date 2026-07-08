 package jinguissl.contract

 import jinguissl_core.crypto.quic.{
     quicHpAesEncrypt as Core_quicHpAesEncrypt,
     quicHpChaChaEncrypt as Core_quicHpChaChaEncrypt
 }

 /**
  * contractQuicHpAesEncrypt — QUIC AES-based header protection mask (RFC 9001 §5.4.1).
  *
  * mask = AES-ECB(hp_key, sample); returns (first_byte_mask, pn_mask)
  *
  * @param sample 16-byte sample from the protected ciphertext
  * @param key 16-byte header protection key
  * @returns (first_byte_mask, pn_mask_bytes) where pn_mask is 15 bytes
  */
 public func contractQuicHpAesEncrypt(
     sample: Array<Byte>, key: Array<Byte>
 ): (Byte, Array<Byte>) {
     Core_quicHpAesEncrypt(sample, key)
 }

 /**
  * contractQuicHpChaChaEncrypt — QUIC ChaCha20-based header protection mask (RFC 9001 §5.4.2).
  *
  * mask = ChaCha20(hp_key, counter, nonce); returns (first_byte_mask, pn_mask)
  *
  * @param sample 16-byte sample where sample[0..4]=counter (LE), sample[4..16]=nonce
  * @param key 32-byte header protection key
  * @returns (first_byte_mask, pn_mask_bytes) where pn_mask is 4 bytes
  */
 public func contractQuicHpChaChaEncrypt(
     sample: Array<Byte>, key: Array<Byte>
 ): (Byte, Array<Byte>) {
     Core_quicHpChaChaEncrypt(sample, key)
 }
