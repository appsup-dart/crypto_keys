part of '../catalog.dart';

/// Browsable catalog of digest/hash algorithm identifiers.
class DigestAlgorithms extends Identifier {
  const DigestAlgorithms() : super('digest');

  /// SHA-1 digest
  DigestAlgorithmIdentifier get sha1 => .sha1;

  /// SHA-224 digest
  DigestAlgorithmIdentifier get sha224 => .sha224;

  /// SHA-256 digest
  DigestAlgorithmIdentifier get sha256 => .sha256;

  /// SHA-384 digest
  DigestAlgorithmIdentifier get sha384 => .sha384;

  /// SHA-512 digest
  DigestAlgorithmIdentifier get sha512 => .sha512;

  /// SHA-512/t digest
  DigestAlgorithmIdentifier sha512t(int digestSizeBytes) =>
      .sha512t(digestSizeBytes);
}
