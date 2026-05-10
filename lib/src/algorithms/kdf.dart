part of '../algorithms.dart';

/// Key-derivation markers for password stretching ([PasswordKdfAlgorithm]) and
/// shared-secret expansion ([SecretKdfAlgorithm]).
///
/// Example on `Password` / `SecretBytes`:
///
/// ```dart
/// pw.deriveBits(.pbkdf2(
///   hash: .sha256,
///   salt: salt,
///   iterations: 100_000,
///   keyBitLength: 256,
/// ));
/// ikm.deriveBits(.hkdf(hash: .sha256, salt: salt, keyBitLength: 256));
/// ```
///
/// Union of password-based and shared-secret [KdfAlgorithm] families.
sealed class KdfAlgorithm extends Algorithm {
  const KdfAlgorithm();
}

/// Key-derivation algorithms for [Password.deriveBits] (PBKDF2, Argon2id).
sealed class PasswordKdfAlgorithm extends KdfAlgorithm {
  const PasswordKdfAlgorithm();

  /// PBKDF2-HMAC with caller-provided digest.
  const factory PasswordKdfAlgorithm.pbkdf2(DigestAlgorithm hash) =
      Pbkdf2KdfAlgorithm;

  /// Argon2id (RFC 9106).
  const factory PasswordKdfAlgorithm.argon2id() = Argon2idKdfAlgorithm;
}

/// Key-derivation algorithms for [SecretBytes.deriveBits] (HKDF, Concat KDF).
sealed class SecretKdfAlgorithm extends KdfAlgorithm {
  const SecretKdfAlgorithm();

  /// Concat KDF with caller-provided digest.
  const factory SecretKdfAlgorithm.concatKdf(DigestAlgorithm hash) =
      ConcatKdfAlgorithm;

  /// HKDF with caller-provided digest.
  const factory SecretKdfAlgorithm.hkdf(DigestAlgorithm hash) =
      HkdfKdfAlgorithm;
}
