part of '../algorithms.dart';

/// Identifies algorithms that produce shared secrets from peer keys.
///
/// Example:
///
/// ```dart
/// alice.privateKey.deriveSharedSecret(
///   .ecdh(peerPublicKey: bob.publicKey),
/// );
/// ```
///
/// Next step is often HKDF / Concat-KDF on the `SecretBytes`. See `example/montgomerydh_hkdf_example.dart`,
/// `example/ecdh_concat_kdf_example.dart`.

sealed class KeyAgreementAlgorithm extends Algorithm {
  const KeyAgreementAlgorithm();

  /// ECDH on NIST Weierstrass curves ([EcPrivateKey] / [EcPublicKey], same curve).
  const factory KeyAgreementAlgorithm.ecdh() = EcdhKeyAgreementAlgorithm;

  /// RFC 7748 Montgomery-curve Diffie–Hellman ([MontgomeryPrivateKey] /
  /// [MontgomeryPublicKey]; [MontgomeryCurve] is on the keys).
  const factory KeyAgreementAlgorithm.montgomeryDh() =
      MontgomeryDhKeyAgreementAlgorithm;
}

/// Shared marker for elliptic-curve Diffie–Hellman raw shared-secret agreement.
///
/// Subtypes select Weierstrass ECDH vs Montgomery DH; keys must match the leaf.
sealed class DiffieHellmanKeyAgreementAlgorithm extends KeyAgreementAlgorithm {
  const DiffieHellmanKeyAgreementAlgorithm() : super();
}

/// Weierstrass ECDH (NIST curves).
final class EcdhKeyAgreementAlgorithm
    extends DiffieHellmanKeyAgreementAlgorithm {
  const EcdhKeyAgreementAlgorithm() : super();

  @override
  bool operator ==(Object other) => other is EcdhKeyAgreementAlgorithm;

  @override
  int get hashCode => (EcdhKeyAgreementAlgorithm).hashCode;
}

/// Montgomery-curve Diffie–Hellman (RFC 7748).
final class MontgomeryDhKeyAgreementAlgorithm
    extends DiffieHellmanKeyAgreementAlgorithm {
  const MontgomeryDhKeyAgreementAlgorithm() : super();

  @override
  bool operator ==(Object other) => other is MontgomeryDhKeyAgreementAlgorithm;

  @override
  int get hashCode => (MontgomeryDhKeyAgreementAlgorithm).hashCode;
}
