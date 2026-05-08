part of '../algorithms.dart';

/// Identifier for encryption and decryption algorithms.
abstract class EncryptionAlgorithmIdentifier extends AlgorithmIdentifier {
  EncryptionAlgorithmIdentifier._(super.name, super.factory) : super._();
}

/// Symmetric encryption algorithm identifiers (AES families).
class SymmetricEncryptionAlgorithmIdentifier
    extends EncryptionAlgorithmIdentifier {
  SymmetricEncryptionAlgorithmIdentifier._(super.name, super.factory)
    : super._();

  /// AES-CBC with HMAC authentication using the provided digest.
  factory SymmetricEncryptionAlgorithmIdentifier.cbcWithHmac(
    DigestAlgorithmIdentifier hash,
  ) => ._(
    'enc/AES/CBC/PKCS7+HMAC/${hash.nameSuffix}',
    () => pce.AesCbcAuthenticatedCipherWithHash(
      SigningAlgorithmIdentifier.hmac(hash).createAlgorithm() as pc.Mac,
    ),
  );

  /// AES-CBC with PKCS#7 padding.
  factory SymmetricEncryptionAlgorithmIdentifier.cbcWithPkcs7() => ._(
    'enc/AES/CBC/PKCS7',
    () => pc.PaddedBlockCipherImpl(
      pc.PKCS7Padding(),
      pc.CBCBlockCipher(pc.AESEngine()),
    ),
  );

  /// AES-GCM.
  factory SymmetricEncryptionAlgorithmIdentifier.gcm() =>
      ._('enc/AES/GCM', () => pc.GCMBlockCipher(pc.AESEngine()));

  /// AES-EAX.
  factory SymmetricEncryptionAlgorithmIdentifier.eax() =>
      ._('enc/AES/EAX', () => pc.AEADCipher('AES/EAX'));

  /// AES Key Wrap (RFC 3394 default IV variant).
  factory SymmetricEncryptionAlgorithmIdentifier.keyWrap() =>
      ._('enc/AES/KW', () => pce.AESKeyWrap());

  /// ChaCha20-Poly1305 AEAD (RFC 8439).
  ///
  /// Uses a 256-bit key and a 96-bit nonce ([initializationVector]).
  factory SymmetricEncryptionAlgorithmIdentifier.chacha20Poly1305() => ._(
    'enc/ChaCha20/Poly1305',
    () => pc.ChaCha20Poly1305(pc.ChaCha7539Engine(), pc.Poly1305()),
  );
}

/// Base class for asymmetric encryption algorithm identifiers.
class AsymmetricEncryptionAlgorithmIdentifier
    extends EncryptionAlgorithmIdentifier {
  AsymmetricEncryptionAlgorithmIdentifier._(super.name, super.factory)
    : super._();
}

/// RSA encryption identifiers.
class RsaEncryptionAlgorithmIdentifier
    extends AsymmetricEncryptionAlgorithmIdentifier {
  RsaEncryptionAlgorithmIdentifier._(super.name, super.factory) : super._();

  /// RSAES-PKCS1-v1_5.
  factory RsaEncryptionAlgorithmIdentifier.pkcs1() =>
      ._('enc/RSA/PKCS1', () => pc.PKCS1Encoding(pc.RSAEngine()));

  /// RSAES-OAEP with SHA-1.
  factory RsaEncryptionAlgorithmIdentifier.oaepWithSha1() => ._(
    'enc/RSA/ECB/OAEPWithSHA-1AndMGF1Padding',
    () => pc.OAEPEncoding.withSHA1(pc.RSAEngine()),
  );

  /// RSAES-OAEP with SHA-256.
  factory RsaEncryptionAlgorithmIdentifier.oaepWithSha256() => ._(
    'enc/RSA/ECB/OAEPWithSHA-256AndMGF1Padding',
    () => pc.OAEPEncoding.withSHA256(pc.RSAEngine()),
  );
}

/// Placeholder type for EC-based encryption identifiers.
class EcEncryptionAlgorithmIdentifier
    extends AsymmetricEncryptionAlgorithmIdentifier {
  EcEncryptionAlgorithmIdentifier._(super.name, super.factory) : super._();
}
