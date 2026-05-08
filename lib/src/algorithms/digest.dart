part of '../algorithms.dart';

/// Identifier for cryptographic digest/hash algorithms.
class DigestAlgorithmIdentifier extends AlgorithmIdentifier {
  DigestAlgorithmIdentifier._(super.name, super.factory) : super._();

  // --- SHA-2 ---

  /// SHA-1
  static final DigestAlgorithmIdentifier sha1 = ._(
    'digest/SHA-1',
    () => pc.SHA1Digest(),
  );

  /// SHA-224
  static final DigestAlgorithmIdentifier sha224 = ._(
    'digest/SHA-224',
    () => pc.SHA224Digest(),
  );

  /// SHA-256
  static final DigestAlgorithmIdentifier sha256 = ._(
    'digest/SHA-256',
    () => pc.SHA256Digest(),
  );

  /// SHA-384
  static final DigestAlgorithmIdentifier sha384 = ._(
    'digest/SHA-384',
    () => pc.SHA384Digest(),
  );

  /// SHA-512
  static final DigestAlgorithmIdentifier sha512 = ._(
    'digest/SHA-512',
    () => pc.SHA512Digest(),
  );

  /// SHA-512/t with caller-provided digest output size (in bytes).
  static DigestAlgorithmIdentifier sha512t(int digestSizeBytes) =>
      DigestAlgorithmIdentifier._(
        'digest/SHA-512/${digestSizeBytes * 8}',
        () => pc.SHA512tDigest(digestSizeBytes),
      );

  // --- SHA-3 (FIPS 202) ---

  /// SHA3-224
  static final DigestAlgorithmIdentifier sha3_224 = ._(
    'digest/SHA3-224',
    () => pc.SHA3Digest(224),
  );

  /// SHA3-256
  static final DigestAlgorithmIdentifier sha3_256 = ._(
    'digest/SHA3-256',
    () => pc.SHA3Digest(256),
  );

  /// SHA3-384
  static final DigestAlgorithmIdentifier sha3_384 = ._(
    'digest/SHA3-384',
    () => pc.SHA3Digest(384),
  );

  /// SHA3-512
  static final DigestAlgorithmIdentifier sha3_512 = ._(
    'digest/SHA3-512',
    () => pc.SHA3Digest(512),
  );
}
