part of '../algorithms.dart';

/// Sealed union of password-based and secret-bytes [KdfAlgorithm] families
/// ([PasswordKdfAlgorithm], [SecretKdfAlgorithm]).
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
