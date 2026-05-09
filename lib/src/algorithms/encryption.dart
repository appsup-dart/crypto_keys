part of '../algorithms.dart';

/// Identifier for encryption and decryption algorithms.
sealed class EncryptionAlgorithmIdentifier extends AlgorithmIdentifier {
  const EncryptionAlgorithmIdentifier._(super.name) : super._();
}

/// Symmetric encryption algorithm identifiers (AES families).
sealed class SymmetricEncryptionAlgorithmIdentifier
    extends EncryptionAlgorithmIdentifier {
  const SymmetricEncryptionAlgorithmIdentifier._(super.name) : super._();

  /// AES-CBC with HMAC authentication using the provided digest.
  factory SymmetricEncryptionAlgorithmIdentifier.cbcWithHmac(
    DigestAlgorithmIdentifier hash,
  ) = AesCbcPkcs7HmacEncryptionAlgorithmIdentifier;

  /// AES-CBC with PKCS#7 padding.
  const factory SymmetricEncryptionAlgorithmIdentifier.cbcWithPkcs7() =
      AesCbcPkcs7EncryptionAlgorithmIdentifier;

  /// AES-GCM.
  const factory SymmetricEncryptionAlgorithmIdentifier.gcm() =
      AesGcmEncryptionAlgorithmIdentifier;

  /// AES-EAX.
  const factory SymmetricEncryptionAlgorithmIdentifier.eax() =
      AesEaxEncryptionAlgorithmIdentifier;

  /// AES Key Wrap (RFC 3394 default IV variant).
  const factory SymmetricEncryptionAlgorithmIdentifier.keyWrap() =
      AesKeyWrapEncryptionAlgorithmIdentifier;

  /// ChaCha20-Poly1305 AEAD (RFC 8439).
  ///
  /// Uses a 256-bit key and a 96-bit nonce ([initializationVector]).
  const factory SymmetricEncryptionAlgorithmIdentifier.chacha20Poly1305() =
      ChaCha20Poly1305EncryptionAlgorithmIdentifier;
}

/// Base class for asymmetric encryption algorithm identifiers.
sealed class AsymmetricEncryptionAlgorithmIdentifier
    extends EncryptionAlgorithmIdentifier {
  const AsymmetricEncryptionAlgorithmIdentifier._(super.name) : super._();
}

/// RSA encryption identifiers.
sealed class RsaEncryptionAlgorithmIdentifier
    extends AsymmetricEncryptionAlgorithmIdentifier {
  /// RSAES-PKCS1-v1_5.
  const factory RsaEncryptionAlgorithmIdentifier.pkcs1() =
      RsaPkcs1EncryptionAlgorithmIdentifier;

  /// RSAES-OAEP with SHA-1.
  const factory RsaEncryptionAlgorithmIdentifier.oaepWithSha1() =
      RsaOaepSha1EncryptionAlgorithmIdentifier;

  /// RSAES-OAEP with SHA-256.
  const factory RsaEncryptionAlgorithmIdentifier.oaepWithSha256() =
      RsaOaepSha256EncryptionAlgorithmIdentifier;

  const RsaEncryptionAlgorithmIdentifier._(super.name) : super._();
}
