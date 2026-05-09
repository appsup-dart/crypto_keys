part of '../algorithms.dart';

/// Key-agreement and key-derivation algorithms.
sealed class DerivationAlgorithm extends Algorithm {
  const DerivationAlgorithm();

  /// Concat KDF with caller-provided digest.
  const factory DerivationAlgorithm.concatKdf(DigestAlgorithm hash) =
      _ConcatKdfDerivationAlgorithm;

  /// PBKDF2-HMAC with caller-provided digest.
  const factory DerivationAlgorithm.pbkdf2(DigestAlgorithm hash) =
      _Pbkdf2DerivationAlgorithm;

  /// HKDF with caller-provided digest.
  const factory DerivationAlgorithm.hkdf(DigestAlgorithm hash) =
      _HkdfDerivationAlgorithm;

  /// ECDH shared-secret agreement.
  const factory DerivationAlgorithm.ecdh() = _EcdhDerivationAlgorithm;
}
