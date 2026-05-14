part of '../catalog.dart';

/// Key agreement algorithms ([AgreementPrivateKey.deriveSharedSecret]).
class KeyAgreementAlgorithms {
  final EcdhKeyAgreementAlgorithm ecdh = const EcdhKeyAgreementAlgorithm();

  final MontgomeryDhKeyAgreementAlgorithm montgomeryDh =
      const MontgomeryDhKeyAgreementAlgorithm();

  const KeyAgreementAlgorithms._();
}
