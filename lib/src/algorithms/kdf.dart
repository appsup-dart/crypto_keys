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

final class ConcatKdfAlgorithm extends SecretKdfAlgorithm {
  final DigestAlgorithm hash;

  const ConcatKdfAlgorithm(this.hash) : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is ConcatKdfAlgorithm && hash == other.hash;

  @override
  int get hashCode => Object.hash(1, hash);
}

final class Pbkdf2KdfAlgorithm extends PasswordKdfAlgorithm {
  final DigestAlgorithm hash;

  const Pbkdf2KdfAlgorithm(this.hash) : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Pbkdf2KdfAlgorithm && hash == other.hash;

  @override
  int get hashCode => Object.hash(2, hash);
}

final class HkdfKdfAlgorithm extends SecretKdfAlgorithm {
  final DigestAlgorithm hash;

  const HkdfKdfAlgorithm(this.hash) : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) || other is HkdfKdfAlgorithm && hash == other.hash;

  @override
  int get hashCode => Object.hash(3, hash);
}

final class Argon2idKdfAlgorithm extends PasswordKdfAlgorithm {
  const Argon2idKdfAlgorithm() : super();

  @override
  bool operator ==(Object other) => other is Argon2idKdfAlgorithm;

  @override
  int get hashCode => (Argon2idKdfAlgorithm).hashCode;
}
