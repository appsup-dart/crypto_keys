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

final class EcdhKeyAgreementAlgorithm extends KeyAgreementAlgorithm {
  const EcdhKeyAgreementAlgorithm() : super();

  @override
  bool operator ==(Object other) => other is EcdhKeyAgreementAlgorithm;

  @override
  int get hashCode => (EcdhKeyAgreementAlgorithm).hashCode;
}

final class X25519KeyAgreementAlgorithm extends KeyAgreementAlgorithm {
  const X25519KeyAgreementAlgorithm() : super();

  @override
  bool operator ==(Object other) => other is X25519KeyAgreementAlgorithm;

  @override
  int get hashCode => (X25519KeyAgreementAlgorithm).hashCode;
}
