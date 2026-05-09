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

  /// X25519 (Curve25519) shared-secret agreement.
  const factory DerivationAlgorithm.x25519() = _X25519DerivationAlgorithm;

  /// Argon2id password-based key derivation (RFC 9106).
  const factory DerivationAlgorithm.argon2id() = _Argon2idDerivationAlgorithm;
}
