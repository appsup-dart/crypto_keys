part of '../catalog.dart';

/// Browsable catalog of key derivation and key agreement algorithms.
class DerivationAlgorithms extends Identifier {
  /// ECDH shared-secret derivation.
  DerivationAlgorithmIdentifier get ecdh => .ecdh();

  /// Contains the identifiers for supported Concat KDF algorithms
  final concatKdf = const ConcatKdfAlgorithms._();

  /// Contains the identifiers for supported PBKDF2 algorithms.
  final pbkdf2 = const Pbkdf2Algorithms._();

  /// Contains the identifiers for supported HKDF algorithms.
  final hkdf = const HkdfAlgorithms._();

  const DerivationAlgorithms._() : super('derive');
}

/// Browsable catalog of Concat KDF algorithms.
class ConcatKdfAlgorithms extends Identifier {
  /// Concat KDF using SHA-256
  DerivationAlgorithmIdentifier get sha256 => .concatKdf(.sha256);

  /// Concat KDF using SHA-384
  DerivationAlgorithmIdentifier get sha384 => .concatKdf(.sha384);

  /// Concat KDF using SHA-512
  DerivationAlgorithmIdentifier get sha512 => .concatKdf(.sha512);

  /// Concat KDF using a caller-selected digest algorithm.
  DerivationAlgorithmIdentifier withHash(DigestAlgorithmIdentifier hash) =>
      DerivationAlgorithmIdentifier.concatKdf(hash);

  const ConcatKdfAlgorithms._() : super('derive/ConcatKDF');
}

/// Browsable catalog of PBKDF2 algorithms.
class Pbkdf2Algorithms extends Identifier {
  /// PBKDF2 using HMAC-SHA-1
  DerivationAlgorithmIdentifier get sha1 => .pbkdf2(.sha1);

  /// PBKDF2 using HMAC-SHA-256
  DerivationAlgorithmIdentifier get sha256 => .pbkdf2(.sha256);

  /// PBKDF2 using HMAC-SHA-384
  DerivationAlgorithmIdentifier get sha384 => .pbkdf2(.sha384);

  /// PBKDF2 using HMAC-SHA-512
  DerivationAlgorithmIdentifier get sha512 => .pbkdf2(.sha512);

  /// PBKDF2 using HMAC with a caller-selected digest algorithm.
  DerivationAlgorithmIdentifier withHash(DigestAlgorithmIdentifier hash) =>
      DerivationAlgorithmIdentifier.pbkdf2(hash);

  const Pbkdf2Algorithms._() : super('derive/PBKDF2');
}

/// Browsable catalog of HKDF algorithms.
class HkdfAlgorithms extends Identifier {
  /// HKDF using SHA-256
  DerivationAlgorithmIdentifier get sha256 => .hkdf(.sha256);

  /// HKDF using SHA-384
  DerivationAlgorithmIdentifier get sha384 => .hkdf(.sha384);

  /// HKDF using SHA-512
  DerivationAlgorithmIdentifier get sha512 => .hkdf(.sha512);

  /// HKDF using a caller-selected digest algorithm.
  DerivationAlgorithmIdentifier withHash(DigestAlgorithmIdentifier hash) =>
      DerivationAlgorithmIdentifier.hkdf(hash);

  const HkdfAlgorithms._() : super('derive/HKDF');
}
