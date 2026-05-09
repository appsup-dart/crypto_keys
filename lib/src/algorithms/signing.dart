part of '../algorithms.dart';

/// Identifier for signing and signature-verification algorithms.
sealed class SigningAlgorithmIdentifier extends AlgorithmIdentifier {
  const SigningAlgorithmIdentifier._(super.name) : super._();

  /// HMAC with the given [hash].
  static SymmetricSigningAlgorithmIdentifier hmac(
    DigestAlgorithmIdentifier hash,
  ) => .hmac(hash);

  /// RSA PKCS#1 v1.5 with the given [hash].
  static RsaSigningAlgorithmIdentifier rsaPkcs1(
    DigestAlgorithmIdentifier hash,
  ) => .pkcs1(hash);

  /// RSA-PSS with caller-provided parameters.
  static RsaSigningAlgorithmIdentifier rsaPss({
    required DigestAlgorithmIdentifier sigHash,
    DigestAlgorithmIdentifier? mgf1Hash,
    int? saltLength,
  }) => .pss(sigHash, mgf1Hash: mgf1Hash, saltLength: saltLength);

  /// ECDSA with the given [hash].
  static EcSigningAlgorithmIdentifier ecdsa(DigestAlgorithmIdentifier hash) =>
      .ecdsa(hash);

  /// Ed25519 pure signatures (RFC 8032).
  static const Ed25519SigningAlgorithmIdentifier ed25519 =
      Ed25519SigningAlgorithmIdentifierImpl();
}

/// Symmetric signing algorithm identifiers (HMAC family).
sealed class SymmetricSigningAlgorithmIdentifier
    extends SigningAlgorithmIdentifier {
  const SymmetricSigningAlgorithmIdentifier._(super.name) : super._();

  /// HMAC with the given [hash].
  factory SymmetricSigningAlgorithmIdentifier.hmac(
    DigestAlgorithmIdentifier hash,
  ) = HmacSigningAlgorithmIdentifier;
}

/// Base class for asymmetric signing algorithm identifiers.
sealed class AsymmetricSigningAlgorithmIdentifier
    extends SigningAlgorithmIdentifier {
  const AsymmetricSigningAlgorithmIdentifier._(super.name) : super._();
}

/// RSA signing algorithm identifiers.
sealed class RsaSigningAlgorithmIdentifier
    extends AsymmetricSigningAlgorithmIdentifier {
  const RsaSigningAlgorithmIdentifier._(super.name) : super._();

  /// RSASSA-PKCS1-v1_5 with the given digest.
  factory RsaSigningAlgorithmIdentifier.pkcs1(DigestAlgorithmIdentifier hash) =
      RsaPkcs1SigningAlgorithmIdentifier;

  /// RSASSA-PSS with caller-provided or defaulted parameters.
  ///
  /// Defaults:
  /// - `mgf1Hash`: same as [sigHash]
  /// - `saltLength`: digest output size of [sigHash] (in bytes)
  factory RsaSigningAlgorithmIdentifier.pss(
    DigestAlgorithmIdentifier sigHash, {
    DigestAlgorithmIdentifier? mgf1Hash,
    int? saltLength,
  }) = RsaPssSigningAlgorithmIdentifier;
}

/// ECDSA signing algorithm identifiers.
sealed class EcSigningAlgorithmIdentifier
    extends AsymmetricSigningAlgorithmIdentifier {
  const EcSigningAlgorithmIdentifier._(super.name) : super._();

  factory EcSigningAlgorithmIdentifier.ecdsa(DigestAlgorithmIdentifier hash) =
      EcdsaSigningAlgorithmIdentifier;
}

/// Ed25519 signing (RFC 8032).
///
/// Signs and verifies the **raw** message bytes (no separate digest step).
sealed class Ed25519SigningAlgorithmIdentifier
    extends AsymmetricSigningAlgorithmIdentifier {
  const Ed25519SigningAlgorithmIdentifier._(super.name) : super._();
}
