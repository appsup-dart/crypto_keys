part of '../catalog.dart';

/// Browsable catalog of signing algorithms.
class SigningAlgorithms {
  /// HMAC signing
  final hmac = const HmacSigningAlgorithms._();

  /// RSA signing
  final rsa = const RsaSigningAlgorithms._();

  /// ECDSA signing
  final ecdsa = const EcdsaSigningAlgorithms._();

  /// Ed25519 (RFC 8032)
  final ed25519 = const Ed25519SigningAlgorithms._();

  const SigningAlgorithms._();
}

/// Browsable catalog of HMAC signing algorithms.
class HmacSigningAlgorithms {
  /// HMAC using SHA-256
  final SymmetricSigningAlgorithm sha256 = const .hmac(.sha256);

  /// HMAC using SHA-384
  final SymmetricSigningAlgorithm sha384 = const .hmac(.sha384);

  /// HMAC using SHA-512
  final SymmetricSigningAlgorithm sha512 = const .hmac(.sha512);

  /// HMAC using a caller-selected digest algorithm.
  SymmetricSigningAlgorithm withHash(DigestAlgorithm hash) => .hmac(hash);

  const HmacSigningAlgorithms._();
}

/// Browsable catalog of RSA signing algorithms.
class RsaSigningAlgorithms {
  /// RSASSA-PKCS1-v1_5 algorithms
  final pkcs1 = const RsaPkcs1SigningAlgorithms._();

  /// RSASSA-PSS signing
  final pss = const RsaPssSigningAlgorithms._();

  const RsaSigningAlgorithms._();
}

/// Browsable catalog of RSA PKCS#1 v1.5 signing algorithms.
class RsaPkcs1SigningAlgorithms {
  /// RSASSA-PKCS1-v1_5 using SHA-256
  final RsaSigningAlgorithm sha256 = const .pkcs1(.sha256);

  /// RSASSA-PKCS1-v1_5 using SHA-384
  final RsaSigningAlgorithm sha384 = const .pkcs1(.sha384);

  /// RSASSA-PKCS1-v1_5 using SHA-512
  final RsaSigningAlgorithm sha512 = const .pkcs1(.sha512);

  /// RSASSA-PKCS1-v1_5 using a caller-selected digest algorithm.
  RsaSigningAlgorithm withHash(DigestAlgorithm hash) => .pkcs1(hash);

  const RsaPkcs1SigningAlgorithms._();
}

/// Browsable catalog of RSA-PSS signing algorithms.
class RsaPssSigningAlgorithms {
  const RsaPssSigningAlgorithms._();

  /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
  final RsaSigningAlgorithm sha256 = const .pss(
    sigHash: .sha256,
    mgf1Hash: .sha256,
    saltLength: 32,
  );

  /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
  final RsaSigningAlgorithm sha384 = const .pss(
    sigHash: .sha384,
    mgf1Hash: .sha384,
    saltLength: 48,
  );

  /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
  final RsaSigningAlgorithm sha512 = const .pss(
    sigHash: .sha512,
    mgf1Hash: .sha512,
    saltLength: 64,
  );

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
  RsaSigningAlgorithm withParameters({
    required DigestAlgorithm sigHash,
    DigestAlgorithm? mgf1Hash,
    int? saltLength,
  }) => SigningAlgorithm.rsaPss(
    sigHash: sigHash,
    mgf1Hash: mgf1Hash,
    saltLength: saltLength,
  );
}

/// Browsable catalog of ECDSA signing algorithms.
class EcdsaSigningAlgorithms {
  /// ECDSA using P-256 and SHA-256
  final EcSigningAlgorithm sha256 = const .ecdsa(.sha256);

  /// ECDSA using P-384 and SHA-384
  final EcSigningAlgorithm sha384 = const .ecdsa(.sha384);

  /// ECDSA using P-521 and SHA-512
  final EcSigningAlgorithm sha512 = const .ecdsa(.sha512);

  /// ECDSA using a caller-selected digest algorithm.
  EcSigningAlgorithm withHash(DigestAlgorithm hash) => .ecdsa(hash);

  const EcdsaSigningAlgorithms._();
}

/// Ed25519 signing (RFC 8032).
class Ed25519SigningAlgorithms {
  const Ed25519SigningAlgorithms._();

  /// Pure Ed25519 over the raw message bytes.
  final Ed25519SigningAlgorithm pure = SigningAlgorithm.ed25519;
}
