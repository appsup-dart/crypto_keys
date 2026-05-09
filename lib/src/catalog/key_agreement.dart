part of '../catalog.dart';

/// Key agreement algorithms ([AgreementPrivateKey.deriveSharedSecret]).
class KeyAgreementAlgorithms {
  final KeyAgreementAlgorithm ecdh = const KeyAgreementAlgorithm.ecdh();

  final KeyAgreementAlgorithm x25519 = const KeyAgreementAlgorithm.x25519();

  const KeyAgreementAlgorithms._();
}
