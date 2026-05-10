part of '../catalog.dart';

/// Key agreement algorithms ([AgreementPrivateKey.deriveSharedSecret]).
class KeyAgreementAlgorithms {
  final EcdhKeyAgreementAlgorithm ecdh = const EcdhKeyAgreementAlgorithm();

  final X25519KeyAgreementAlgorithm x25519 =
      const X25519KeyAgreementAlgorithm();

  const KeyAgreementAlgorithms._();
}
