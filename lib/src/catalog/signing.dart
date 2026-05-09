part of '../catalog.dart';

/// Browsable catalog of signing algorithm identifiers.
class SigningAlgorithms extends Identifier {
  /// Contains the identifiers for supported HMAC signing algorithms
  final hmac = const HmacSigningAlgorithms._();

  /// Contains the identifiers for supported RSA signing algorithms
  final rsa = const RsaSigningAlgorithms._();

  /// Contains the identifiers for supported ECDSA signing algorithms
  final ecdsa = const EcdsaSigningAlgorithms._();

  /// Ed25519 (RFC 8032)
  final ed25519 = const Ed25519SigningAlgorithms._();

  const SigningAlgorithms._() : super('sig');
}

/// Browsable catalog of HMAC signing algorithms.
class HmacSigningAlgorithms extends Identifier {
  /// HMAC using SHA-256
  SymmetricSigningAlgorithmIdentifier get sha256 => .hmac(.sha256);

  /// HMAC using SHA-384
  SymmetricSigningAlgorithmIdentifier get sha384 => .hmac(.sha384);

  /// HMAC using SHA-512
  SymmetricSigningAlgorithmIdentifier get sha512 => .hmac(.sha512);

  /// HMAC using a caller-selected digest algorithm.
  SymmetricSigningAlgorithmIdentifier withHash(
    DigestAlgorithmIdentifier hash,
  ) => .hmac(hash);

  const HmacSigningAlgorithms._() : super('sig/HMAC');
}

/// Browsable catalog of RSA signing algorithms.
class RsaSigningAlgorithms extends Identifier {
  /// Contains the identifiers for supported RSASSA-PKCS1-v1_5 algorithms.
  final pkcs1 = const RsaPkcs1SigningAlgorithms._();

  /// Contains the identifiers for supported RSASSA-PSS signing algorithms
  final pss = const RsaPssSigningAlgorithms._();

  const RsaSigningAlgorithms._() : super('sig/RSA');
}

/// Browsable catalog of RSA PKCS#1 v1.5 signing algorithms.
class RsaPkcs1SigningAlgorithms extends Identifier {
  /// RSASSA-PKCS1-v1_5 using SHA-256
  RsaSigningAlgorithmIdentifier get sha256 => .pkcs1(.sha256);

  /// RSASSA-PKCS1-v1_5 using SHA-384
  RsaSigningAlgorithmIdentifier get sha384 => .pkcs1(.sha384);

  /// RSASSA-PKCS1-v1_5 using SHA-512
  RsaSigningAlgorithmIdentifier get sha512 => .pkcs1(.sha512);

  /// RSASSA-PKCS1-v1_5 using a caller-selected digest algorithm.
  RsaSigningAlgorithmIdentifier withHash(DigestAlgorithmIdentifier hash) =>
      .pkcs1(hash);

  const RsaPkcs1SigningAlgorithms._() : super('sig/RSA/PKCS1');
}

/// Browsable catalog of RSA-PSS signing algorithms.
class RsaPssSigningAlgorithms extends Identifier {
  const RsaPssSigningAlgorithms._() : super('sig/RSA/PSS');

  /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
  RsaSigningAlgorithmIdentifier get sha256 => .pss(.sha256);

  /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
  RsaSigningAlgorithmIdentifier get sha384 => .pss(.sha384);

  /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
  RsaSigningAlgorithmIdentifier get sha512 => .pss(.sha512);

  /// RSASSA-PSS with custom or defaulted parameters.
  ///
  /// Defaults:
  /// - `mgf1Hash`: same as `sigHash`
  /// - `saltLength`: digest output size of `sigHash` (in bytes)
  ///
  /// Example:
  /// ```dart
  /// final alg = algorithms.signing.rsa.pss.withParameters(sigHash: .sha256);
  /// ```
  RsaSigningAlgorithmIdentifier withParameters({
    required DigestAlgorithmIdentifier sigHash,
    DigestAlgorithmIdentifier? mgf1Hash,
    int? saltLength,
  }) => .pss(sigHash, mgf1Hash: mgf1Hash, saltLength: saltLength);
}

/// Browsable catalog of ECDSA signing algorithms.
class EcdsaSigningAlgorithms extends Identifier {
  /// ECDSA using P-256 and SHA-256
  EcSigningAlgorithmIdentifier get sha256 => .ecdsa(.sha256);

  /// ECDSA using P-384 and SHA-384
  EcSigningAlgorithmIdentifier get sha384 => .ecdsa(.sha384);

  /// ECDSA using P-521 and SHA-512
  EcSigningAlgorithmIdentifier get sha512 => .ecdsa(.sha512);

  /// ECDSA using a caller-selected digest algorithm.
  EcSigningAlgorithmIdentifier withHash(DigestAlgorithmIdentifier hash) =>
      .ecdsa(hash);

  const EcdsaSigningAlgorithms._() : super('sig/ECDSA');
}

/// Ed25519 signing (RFC 8032).
class Ed25519SigningAlgorithms extends Identifier {
  const Ed25519SigningAlgorithms._() : super('sig/Ed25519');

  /// Pure Ed25519 over the raw message bytes.
  Ed25519SigningAlgorithmIdentifier get pure => SigningAlgorithmIdentifier.ed25519;
}
