part of '../algorithms.dart';

/// Encryption and decryption algorithms.
sealed class EncryptionAlgorithm extends Algorithm {
  const EncryptionAlgorithm();
}

/// Symmetric encryption algorithm identifiers (AES families).
sealed class SymmetricEncryptionAlgorithm extends EncryptionAlgorithm {
  const SymmetricEncryptionAlgorithm();

  /// AES-CBC with HMAC authentication using the provided digest.
  const factory SymmetricEncryptionAlgorithm.cbcWithHmac(DigestAlgorithm hash) =
      AesCbcPkcs7HmacEncryptionAlgorithm;

  /// AES-CBC with PKCS#7 padding.
  const factory SymmetricEncryptionAlgorithm.cbcWithPkcs7() =
      AesCbcPkcs7EncryptionAlgorithm;

  /// AES-GCM.
  const factory SymmetricEncryptionAlgorithm.gcm() = AesGcmEncryptionAlgorithm;

  /// AES-EAX.
  const factory SymmetricEncryptionAlgorithm.eax() = AesEaxEncryptionAlgorithm;

  /// AES Key Wrap (RFC 3394 default IV variant).
  const factory SymmetricEncryptionAlgorithm.keyWrap() =
      AesKeyWrapEncryptionAlgorithm;

  /// ChaCha20-Poly1305 AEAD (RFC 8439).
  ///
  /// Uses a 256-bit key and a 96-bit nonce ([initializationVector]).
  const factory SymmetricEncryptionAlgorithm.chacha20Poly1305() =
      ChaCha20Poly1305EncryptionAlgorithm;
}

/// Base class for asymmetric encryption algorithm identifiers.
sealed class AsymmetricEncryptionAlgorithm extends EncryptionAlgorithm {
  const AsymmetricEncryptionAlgorithm();
}

/// RSA encryption identifiers.
sealed class RsaEncryptionAlgorithm extends AsymmetricEncryptionAlgorithm {
  /// RSAES-PKCS1-v1_5.
  const factory RsaEncryptionAlgorithm.pkcs1() = RsaPkcs1EncryptionAlgorithm;

  /// RSAES-OAEP with SHA-1.
  const factory RsaEncryptionAlgorithm.oaepWithSha1() =
      RsaOaepSha1EncryptionAlgorithm;

  /// RSAES-OAEP with SHA-256.
  const factory RsaEncryptionAlgorithm.oaepWithSha256() =
      RsaOaepSha256EncryptionAlgorithm;

  const RsaEncryptionAlgorithm();
}
