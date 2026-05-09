part of '../catalog.dart';

/// Key-derivation algorithms ([Password.deriveBits], [SecretBytes.deriveBits]).
class KdfAlgorithms {
  /// Password-based KDFs ([Password].deriveBits).
  final password = const PasswordKdfCatalog._();

  /// KDFs on secret keying material ([SecretBytes].deriveBits).
  final secret = const SecretKdfCatalog._();

  const KdfAlgorithms._();
}

/// Catalog entries for [PasswordKdfAlgorithm].
class PasswordKdfCatalog {
  /// PBKDF2 with HMAC-SHA-1, SHA-256, SHA-384, or SHA-512.
  final pbkdf2 = const Pbkdf2Algorithms._();

  /// Argon2id (RFC 9106): same marker as [PasswordKdfAlgorithm.argon2id].
  /// Tune cost with [Argon2idKdfParams] on [Password.deriveBits].
  final PasswordKdfAlgorithm argon2id = const .argon2id();

  const PasswordKdfCatalog._();
}

/// Catalog entries for [SecretKdfAlgorithm].
class SecretKdfCatalog {
  final concatKdf = const ConcatKdfAlgorithms._();

  final hkdf = const HkdfAlgorithms._();

  const SecretKdfCatalog._();
}

/// Browsable catalog of Concat KDF algorithms.
class ConcatKdfAlgorithms {
  /// Concat KDF using SHA-256
  final SecretKdfAlgorithm sha256 = const .concatKdf(.sha256);

  /// Concat KDF using SHA-384
  final SecretKdfAlgorithm sha384 = const .concatKdf(.sha384);

  /// Concat KDF using SHA-512
  final SecretKdfAlgorithm sha512 = const .concatKdf(.sha512);

  /// Concat KDF using a caller-selected digest algorithm.
  SecretKdfAlgorithm withHash(DigestAlgorithm hash) => .concatKdf(hash);

  const ConcatKdfAlgorithms._();
}

/// Browsable catalog of PBKDF2 algorithms.
class Pbkdf2Algorithms {
  /// PBKDF2 using HMAC-SHA-1
  final PasswordKdfAlgorithm sha1 = const .pbkdf2(.sha1);

  /// PBKDF2 using HMAC-SHA-256
  final PasswordKdfAlgorithm sha256 = const .pbkdf2(.sha256);

  /// PBKDF2 using HMAC-SHA-384
  final PasswordKdfAlgorithm sha384 = const .pbkdf2(.sha384);

  /// PBKDF2 using HMAC-SHA-512
  final PasswordKdfAlgorithm sha512 = const .pbkdf2(.sha512);

  /// PBKDF2 using HMAC with a caller-selected digest algorithm.
  PasswordKdfAlgorithm withHash(DigestAlgorithm hash) => .pbkdf2(hash);

  const Pbkdf2Algorithms._();
}

/// Browsable catalog of HKDF algorithms.
class HkdfAlgorithms {
  /// HKDF using SHA-256
  final SecretKdfAlgorithm sha256 = const .hkdf(.sha256);

  /// HKDF using SHA-384
  final SecretKdfAlgorithm sha384 = const .hkdf(.sha384);

  /// HKDF using SHA-512
  final SecretKdfAlgorithm sha512 = const .hkdf(.sha512);

  /// HKDF using a caller-selected digest algorithm.
  SecretKdfAlgorithm withHash(DigestAlgorithm hash) => .hkdf(hash);

  const HkdfAlgorithms._();
}
