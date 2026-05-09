part of '../catalog.dart';

/// Browsable catalog of encryption algorithms.
class EncryptionAlgorithms {
  /// AES encryption
  final aes = const AesEncryptionAlgorithms._();

  /// RSA encryption
  final rsa = const RsaEncryptionAlgorithms._();

  /// ChaCha20-Poly1305 (RFC 8439)
  final chacha20 = const ChaCha20Poly1305Algorithms._();

  const EncryptionAlgorithms._();
}

/// ChaCha20-Poly1305 AEAD (RFC 8439).
class ChaCha20Poly1305Algorithms {
  const ChaCha20Poly1305Algorithms._();

  final SymmetricEncryptionAlgorithm poly1305 = const .chacha20Poly1305();
}

/// Browsable catalog of AES encryption algorithms.
class AesEncryptionAlgorithms {
  /// AES CBC
  final SymmetricEncryptionAlgorithm cbc = const .cbcWithPkcs7();

  /// AES-CBC + HMAC authenticated encryption variants.
  final AesWithHmacEncryptionAlgorithms cbcWithHmac =
      const AesWithHmacEncryptionAlgorithms._();

  /// AES GCM
  final SymmetricEncryptionAlgorithm gcm = const .gcm();

  /// AES EAX
  final SymmetricEncryptionAlgorithm eax = const .eax();

  /// AES Key Wrap with default initial value
  final SymmetricEncryptionAlgorithm keyWrap = const .keyWrap();

  const AesEncryptionAlgorithms._();
}

/// Browsable catalog of AES-CBC-HMAC authenticated encryption algorithms.
class AesWithHmacEncryptionAlgorithms {
  /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
  final SymmetricEncryptionAlgorithm sha256 = const .cbcWithHmac(.sha256);

  /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
  final SymmetricEncryptionAlgorithm sha384 = const .cbcWithHmac(.sha384);

  /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
  final SymmetricEncryptionAlgorithm sha512 = const .cbcWithHmac(.sha512);

  const AesWithHmacEncryptionAlgorithms._();
}

/// Browsable catalog of RSA encryption algorithms.
class RsaEncryptionAlgorithms {
  /// RSAES-PKCS1-v1_5
  final RsaEncryptionAlgorithm pkcs1 = const .pkcs1();

  /// RSAES OAEP using default parameters
  final RsaEncryptionAlgorithm oaep = const .oaepWithSha1();

  /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
  final RsaEncryptionAlgorithm oaep256 = const .oaepWithSha256();

  const RsaEncryptionAlgorithms._();
}
