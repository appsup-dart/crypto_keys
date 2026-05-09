part of '../catalog.dart';

/// Browsable catalog of digest/hash algorithms.
class DigestAlgorithms {
  const DigestAlgorithms();

  /// SHA-1 digest
  final DigestAlgorithm sha1 = .sha1;

  /// SHA-224 digest
  final DigestAlgorithm sha224 = .sha224;

  /// SHA-256 digest
  final DigestAlgorithm sha256 = .sha256;

  /// SHA-384 digest
  final DigestAlgorithm sha384 = .sha384;

  /// SHA-512 digest
  final DigestAlgorithm sha512 = .sha512;

  /// SHA-512/t digest
  DigestAlgorithm sha512t(int digestSizeBytes) => .sha512t(digestSizeBytes);

  /// SHA3-224 digest
  final DigestAlgorithm sha3_224 = .sha3_224;

  /// SHA3-256 digest
  final DigestAlgorithm sha3_256 = .sha3_256;

  /// SHA3-384 digest
  final DigestAlgorithm sha3_384 = .sha3_384;

  /// SHA3-512 digest
  final DigestAlgorithm sha3_512 = .sha3_512;
}
