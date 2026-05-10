part of '../algorithms.dart';

/// Markers for [AgreementPrivateKey.deriveSharedSecret] (ECDH on NIST `Ec*`, X25519).
///
/// Example:
///
/// ```dart
/// alice.privateKey.deriveSharedSecret(.x25519(peerPublicKey: bob.publicKey));
/// ```
///
/// Next step is often HKDF / Concat-KDF on the `SecretBytes`. See `example/x25519_hkdf_example.dart`,
/// `example/ecdh_concat_kdf_example.dart`.

sealed class KeyAgreementAlgorithm extends Algorithm {
  const KeyAgreementAlgorithm();

  /// ECDH shared-secret agreement.
  const factory KeyAgreementAlgorithm.ecdh() = EcdhKeyAgreementAlgorithm;

  /// X25519 (Curve25519) shared-secret agreement.
  const factory KeyAgreementAlgorithm.x25519() = X25519KeyAgreementAlgorithm;
}
