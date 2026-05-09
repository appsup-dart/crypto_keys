part of '../catalog.dart';

/// Browsable catalog of key derivation and key agreement algorithms.
class DerivationAlgorithms {
  /// ECDH shared-secret derivation.
  DerivationAlgorithm get ecdh => .ecdh();

  /// Concat KDF
  final concatKdf = const ConcatKdfAlgorithms._();

  /// PBKDF2
  final pbkdf2 = const Pbkdf2Algorithms._();

  /// HKDF
  final hkdf = const HkdfAlgorithms._();

  const DerivationAlgorithms._();
}

/// Browsable catalog of Concat KDF algorithms.
class ConcatKdfAlgorithms {
  /// Concat KDF using SHA-256
  final DerivationAlgorithm sha256 = const .concatKdf(.sha256);

  /// Concat KDF using SHA-384
  final DerivationAlgorithm sha384 = const .concatKdf(.sha384);

  /// Concat KDF using SHA-512
  final DerivationAlgorithm sha512 = const .concatKdf(.sha512);

  /// Concat KDF using a caller-selected digest algorithm.
  DerivationAlgorithm withHash(DigestAlgorithm hash) =>
      DerivationAlgorithm.concatKdf(hash);

  const ConcatKdfAlgorithms._();
}

/// Browsable catalog of PBKDF2 algorithms.
class Pbkdf2Algorithms {
  /// PBKDF2 using HMAC-SHA-1
  final DerivationAlgorithm sha1 = const .pbkdf2(.sha1);

  /// PBKDF2 using HMAC-SHA-256
  final DerivationAlgorithm sha256 = const .pbkdf2(.sha256);

  /// PBKDF2 using HMAC-SHA-384
  final DerivationAlgorithm sha384 = const .pbkdf2(.sha384);

  /// PBKDF2 using HMAC-SHA-512
  final DerivationAlgorithm sha512 = const .pbkdf2(.sha512);

  /// PBKDF2 using HMAC with a caller-selected digest algorithm.
  DerivationAlgorithm withHash(DigestAlgorithm hash) =>
      DerivationAlgorithm.pbkdf2(hash);

  const Pbkdf2Algorithms._();
}

/// Browsable catalog of HKDF algorithms.
class HkdfAlgorithms {
  /// HKDF using SHA-256
  final DerivationAlgorithm sha256 = const .hkdf(.sha256);

  /// HKDF using SHA-384
  final DerivationAlgorithm sha384 = const .hkdf(.sha384);

  /// HKDF using SHA-512
  final DerivationAlgorithm sha512 = const .hkdf(.sha512);

  /// HKDF using a caller-selected digest algorithm.
  DerivationAlgorithm withHash(DigestAlgorithm hash) =>
      DerivationAlgorithm.hkdf(hash);

  const HkdfAlgorithms._();
}
