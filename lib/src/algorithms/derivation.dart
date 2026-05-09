part of '../algorithms.dart';

/// Identifier for key-agreement and key-derivation algorithms.
sealed class DerivationAlgorithmIdentifier extends AlgorithmIdentifier {
  const DerivationAlgorithmIdentifier._(super.name) : super._();

  /// Concat KDF with caller-provided digest.
  factory DerivationAlgorithmIdentifier.concatKdf(
    DigestAlgorithmIdentifier hash,
  ) = _ConcatKdfDerivationAlgorithmIdentifier;

  /// PBKDF2-HMAC with caller-provided digest.
  factory DerivationAlgorithmIdentifier.pbkdf2(
    DigestAlgorithmIdentifier hash,
  ) = _Pbkdf2DerivationAlgorithmIdentifier;

  /// HKDF with caller-provided digest.
  factory DerivationAlgorithmIdentifier.hkdf(
    DigestAlgorithmIdentifier hash,
  ) = _HkdfDerivationAlgorithmIdentifier;

  /// ECDH shared-secret agreement.
  const factory DerivationAlgorithmIdentifier.ecdh() =
      _EcdhDerivationAlgorithmIdentifier;
}
