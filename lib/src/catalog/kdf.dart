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
  final Argon2idKdfAlgorithm argon2id = const Argon2idKdfAlgorithm();

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
  final ConcatKdfAlgorithm sha256 = const ConcatKdfAlgorithm(
    DigestAlgorithm.sha256,
  );

  /// Concat KDF using SHA-384
  final ConcatKdfAlgorithm sha384 = const ConcatKdfAlgorithm(
    DigestAlgorithm.sha384,
  );

  /// Concat KDF using SHA-512
  final ConcatKdfAlgorithm sha512 = const ConcatKdfAlgorithm(
    DigestAlgorithm.sha512,
  );

  /// Concat KDF using a caller-selected digest algorithm.
  ConcatKdfAlgorithm withHash(DigestAlgorithm hash) => ConcatKdfAlgorithm(hash);

  const ConcatKdfAlgorithms._();
}

/// Browsable catalog of PBKDF2 algorithms.
class Pbkdf2Algorithms {
  /// PBKDF2 using HMAC-SHA-1
  final Pbkdf2Algorithm sha1 = const Pbkdf2Algorithm(
    DigestAlgorithm.sha1,
  );

  /// PBKDF2 using HMAC-SHA-256
  final Pbkdf2Algorithm sha256 = const Pbkdf2Algorithm(
    DigestAlgorithm.sha256,
  );

  /// PBKDF2 using HMAC-SHA-384
  final Pbkdf2Algorithm sha384 = const Pbkdf2Algorithm(
    DigestAlgorithm.sha384,
  );

  /// PBKDF2 using HMAC-SHA-512
  final Pbkdf2Algorithm sha512 = const Pbkdf2Algorithm(
    DigestAlgorithm.sha512,
  );

  /// PBKDF2 using HMAC with a caller-selected digest algorithm.
  Pbkdf2Algorithm withHash(DigestAlgorithm hash) => Pbkdf2Algorithm(hash);

  const Pbkdf2Algorithms._();
}

/// Browsable catalog of HKDF algorithms.
class HkdfAlgorithms {
  /// HKDF using SHA-256
  final HkdfAlgorithm sha256 = const HkdfAlgorithm(
    DigestAlgorithm.sha256,
  );

  /// HKDF using SHA-384
  final HkdfAlgorithm sha384 = const HkdfAlgorithm(
    DigestAlgorithm.sha384,
  );

  /// HKDF using SHA-512
  final HkdfAlgorithm sha512 = const HkdfAlgorithm(
    DigestAlgorithm.sha512,
  );

  /// HKDF using a caller-selected digest algorithm.
  HkdfAlgorithm withHash(DigestAlgorithm hash) => HkdfAlgorithm(hash);

  const HkdfAlgorithms._();
}
