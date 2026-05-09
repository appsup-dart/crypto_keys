part of '../algorithms.dart';

/// Identifier for cryptographic digest/hash algorithms.
class DigestAlgorithmIdentifier extends AlgorithmIdentifier {
  final String nameSuffix;

  const DigestAlgorithmIdentifier._(super.name, this.nameSuffix) : super._();

  // --- SHA-2 ---

  /// SHA-1
  static const DigestAlgorithmIdentifier sha1 = ._('digest/SHA-1', 'SHA-1');

  /// SHA-224
  static const DigestAlgorithmIdentifier sha224 = ._('digest/SHA-224', 'SHA-224');

  /// SHA-256
  static const DigestAlgorithmIdentifier sha256 = ._('digest/SHA-256', 'SHA-256');

  /// SHA-384
  static const DigestAlgorithmIdentifier sha384 = ._('digest/SHA-384', 'SHA-384');

  /// SHA-512
  static const DigestAlgorithmIdentifier sha512 = ._('digest/SHA-512', 'SHA-512');

  /// SHA-512/t with caller-provided digest output size (in bytes).
  static DigestAlgorithmIdentifier sha512t(int digestSizeBytes) =>
      DigestAlgorithmIdentifier._(
        'digest/SHA-512/${digestSizeBytes * 8}',
        'SHA-512/${digestSizeBytes * 8}',
      );

  // --- SHA-3 (FIPS 202) ---

  /// SHA3-224
  static const DigestAlgorithmIdentifier sha3_224 = ._('digest/SHA3-224', 'SHA3-224');

  /// SHA3-256
  static const DigestAlgorithmIdentifier sha3_256 = ._('digest/SHA3-256', 'SHA3-256');

  /// SHA3-384
  static const DigestAlgorithmIdentifier sha3_384 = ._('digest/SHA3-384', 'SHA3-384');

  /// SHA3-512
  static const DigestAlgorithmIdentifier sha3_512 = ._('digest/SHA3-512', 'SHA3-512');
}
