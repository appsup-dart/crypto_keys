part of '../algorithms.dart';

/// Digest (hash) algorithms.
///
/// Construct via static members such as [DigestAlgorithm.sha256].
sealed class DigestAlgorithm extends Algorithm {
  const DigestAlgorithm();

  /// Short label for compound paths (HMAC, KDF, ECDSA/RSA-PKCS1 digest names).
  String get name;

  /// SHA-1
  static const DigestAlgorithm sha1 = DigestSha1._();

  /// SHA-224
  static const DigestAlgorithm sha224 = DigestSha2._(.bits224);

  /// SHA-256
  static const DigestAlgorithm sha256 = DigestSha2._(.bits256);

  /// SHA-384
  static const DigestAlgorithm sha384 = DigestSha2._(.bits384);

  /// SHA-512
  static const DigestAlgorithm sha512 = DigestSha2._(.bits512);

  /// SHA-512/t with caller-provided digest output size (in bytes).
  static DigestAlgorithm sha512t(int digestSizeBytes) =>
      DigestSha2._(.bits512, digestSizeBytes);

  /// SHA3-224
  static const DigestAlgorithm sha3_224 = DigestSha3._(.bits224);

  /// SHA3-256
  static const DigestAlgorithm sha3_256 = DigestSha3._(.bits256);

  /// SHA3-384
  static const DigestAlgorithm sha3_384 = DigestSha3._(.bits384);

  /// SHA3-512
  static const DigestAlgorithm sha3_512 = DigestSha3._(.bits512);
}
