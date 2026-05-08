part of '../algorithms.dart';

/// Identifier for cryptographic digest/hash algorithms.
class DigestAlgorithmIdentifier extends AlgorithmIdentifier {
  DigestAlgorithmIdentifier._(super.name, super.factory) : super._();

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
}
