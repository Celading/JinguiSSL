 package jinguissl.contract

 import jinguissl_core.crypto.quic.{
     quicAeadEncrypt as Core_quicAeadEncrypt,
     quicAeadDecrypt as Core_quicAeadDecrypt
 }

 /**
  * contractQuicAeadEncrypt — QUIC AEAD encryption (RFC 9001 §5).
  *
  * Uses AES-GCM or ChaCha20-Poly1305 depending on key length.
  * Returns ciphertext ‖ tag as on the wire.
  *
  * @param key 16-byte (AES-128) or 32-byte (ChaCha20) key
  * @param iv 12-byte QUIC IV
  * @param pn QUIC packet number (used in nonce construction)
  * @param plaintext plaintext to encrypt
  * @param aad additional authenticated data
  * @returns ciphertext ‖ 16-byte authentication tag
  */
 public func contractQuicAeadEncrypt(
     key: Array<Byte>, iv: Array<Byte>, pn: Int64,
     plaintext: Array<Byte>, aad: Array<Byte>
 ): Array<Byte> {
     Core_quicAeadEncrypt(key, iv, pn, plaintext, aad)
 }

 /**
  * contractQuicAeadDecrypt — QUIC AEAD decryption (RFC 9001 §5).
  *
  * Input: ciphertext ‖ tag (as on the wire).
  *
  * @param key 16-byte (AES-128) or 32-byte (ChaCha20) key
  * @param iv 12-byte QUIC IV
  * @param pn QUIC packet number (used in nonce construction)
  * @param ciphertextWithTag ciphertext ‖ 16-byte authentication tag
  * @param aad additional authenticated data
  * @returns plaintext
  * @throws CryptoException if decryption or tag verification fails
  */
 public func contractQuicAeadDecrypt(
     key: Array<Byte>, iv: Array<Byte>, pn: Int64,
     ciphertextWithTag: Array<Byte>, aad: Array<Byte>
 ): Array<Byte> {
     Core_quicAeadDecrypt(key, iv, pn, ciphertextWithTag, aad)
 }
