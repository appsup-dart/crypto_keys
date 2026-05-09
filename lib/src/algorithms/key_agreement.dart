part of '../algorithms.dart';

/// Key agreement algorithms used with [AgreementPrivateKey.deriveSharedSecret].
sealed class KeyAgreementAlgorithm extends Algorithm {
  const KeyAgreementAlgorithm();

  /// ECDH shared-secret agreement.
  const factory KeyAgreementAlgorithm.ecdh() = EcdhKeyAgreementAlgorithm;

  /// X25519 (Curve25519) shared-secret agreement.
  const factory KeyAgreementAlgorithm.x25519() = X25519KeyAgreementAlgorithm;
}
