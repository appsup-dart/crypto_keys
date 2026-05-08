part of '../algorithms.dart';

/// Identifier for key-agreement and key-derivation algorithms.
class DerivationAlgorithmIdentifier extends AlgorithmIdentifier {
  DerivationAlgorithmIdentifier._(super.name, super.factory) : super._();

  /// Concat KDF with caller-provided digest.
  factory DerivationAlgorithmIdentifier.concatKdf(
    DigestAlgorithmIdentifier hash,
  ) => ._(
    'derive/ConcatKDF/${hash.nameSuffix}',
    () => hash.createAlgorithm() as pc.Digest,
  );

  /// PBKDF2-HMAC with caller-provided digest.
  factory DerivationAlgorithmIdentifier.pbkdf2(
    DigestAlgorithmIdentifier hash,
  ) => ._(
    'derive/PBKDF2/${hash.nameSuffix}',
    () => pc.PBKDF2KeyDerivator(
      pc.HMac(hash.createAlgorithm() as pc.Digest, hash.blockLength),
    ),
  );

  /// HKDF with caller-provided digest.
  factory DerivationAlgorithmIdentifier.hkdf(DigestAlgorithmIdentifier hash) =>
      ._(
        'derive/HKDF/${hash.nameSuffix}',
        () => pc.HKDFKeyDerivator(hash.createAlgorithm() as pc.Digest),
      );

  /// ECDH shared-secret agreement.
  factory DerivationAlgorithmIdentifier.ecdh() =>
      ._('derive/ECDH', () => pc.SHA256Digest());
}
