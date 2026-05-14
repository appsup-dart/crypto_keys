part of '../algorithms.dart';

/// Identifies algorithms that produce and verify signatures over message bytes
/// (results as `Signature` in crypto_keys).
///
/// ```dart
/// pair.privateKey.createSigner(.hmac(.sha256)).sign(message);
/// pair.publicKey.createVerifier(.hmac(.sha256)).verify(message, sig);
/// ```

sealed class SigningAlgorithm extends Algorithm {
  const SigningAlgorithm();

  /// HMAC with the given [hash].
  static SymmetricSigningAlgorithm hmac(DigestAlgorithm hash) => .hmac(hash);

  /// RSA PKCS#1 v1.5 with the given [hash].
  static RsaSigningAlgorithm rsaPkcs1(DigestAlgorithm hash) => .pkcs1(hash);

  /// RSA-PSS with caller-provided parameters.
  static RsaSigningAlgorithm rsaPss({
    required DigestAlgorithm sigHash,
    DigestAlgorithm? mgf1Hash,
    int? saltLength,
  }) => .pss(
    sigHash: sigHash,
    mgf1Hash: mgf1Hash ?? sigHash,
    saltLength: saltLength ?? sigHash.algorithmImplementation.digestSize,
  );

  /// ECDSA with the given [hash].
  static EcSigningAlgorithm ecdsa(DigestAlgorithm hash) => .ecdsa(hash);

  /// RFC 8032 PureEdDSA on Ed25519 (raw message bytes).
  static const EddsaSigningAlgorithm eddsa = .eddsa();
}

/// Symmetric signing algorithm identifiers (HMAC family).
sealed class SymmetricSigningAlgorithm extends SigningAlgorithm {
  const SymmetricSigningAlgorithm();

  /// HMAC with the given [hash].
  const factory SymmetricSigningAlgorithm.hmac(DigestAlgorithm hash) =
      HmacSigningAlgorithm;
}

/// Base class for asymmetric signing algorithm identifiers.
sealed class AsymmetricSigningAlgorithm extends SigningAlgorithm {
  const AsymmetricSigningAlgorithm();
}

/// RSA signing algorithm identifiers.
sealed class RsaSigningAlgorithm extends AsymmetricSigningAlgorithm {
  const RsaSigningAlgorithm();

  /// RSASSA-PKCS1-v1_5 with the given digest.
  const factory RsaSigningAlgorithm.pkcs1(DigestAlgorithm hash) =
      RsaPkcs1SigningAlgorithm;

  /// RSASSA-PSS with caller-provided or defaulted parameters.
  ///
  /// Defaults:
  /// - `mgf1Hash`: same as [sigHash]
  /// - `saltLength`: digest output size of [sigHash] (in bytes)
  const factory RsaSigningAlgorithm.pss({
    required DigestAlgorithm sigHash,
    required DigestAlgorithm mgf1Hash,
    required int saltLength,
  }) = RsaPssSigningAlgorithm;
}

/// ECDSA signing algorithm identifiers.
sealed class EcSigningAlgorithm extends AsymmetricSigningAlgorithm {
  const EcSigningAlgorithm();

  const factory EcSigningAlgorithm.ecdsa(DigestAlgorithm hash) =
      EcdsaSigningAlgorithm;
}

/// RFC 8032 Edwards-curve Digital Signature Algorithm (EdDSA).
sealed class EddsaSigningAlgorithm extends AsymmetricSigningAlgorithm {
  const EddsaSigningAlgorithm();

  /// PureEdDSA (RFC 8032), e.g. Ed25519 in this package.
  const factory EddsaSigningAlgorithm.eddsa() = PureEddsaSigningAlgorithm;
}
