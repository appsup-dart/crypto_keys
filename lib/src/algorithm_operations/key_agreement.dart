import 'package:crypto_keys/crypto_keys.dart';

/// Algorithm-first ECDH: [EcPrivateKey] with peer [EcPublicKey] (same curve).
extension EcdhKeyAgreementAlgorithmDerive on EcdhKeyAgreementAlgorithm {
  SecretBytes deriveSharedSecret(
    EcPrivateKey privateKey, {
    required EcPublicKey peerPublicKey,
  }) => privateKey.deriveSharedSecret(
    DiffieHellmanAgreementParams<EcPublicKey>(peerPublicKey: peerPublicKey),
  );
}

/// Algorithm-first Montgomery DH: [MontgomeryPrivateKey] with peer
/// [MontgomeryPublicKey] (same [MontgomeryCurve]).
extension MontgomeryKeyAgreementAlgorithmDerive
    on MontgomeryDhKeyAgreementAlgorithm {
  SecretBytes deriveSharedSecret(
    MontgomeryPrivateKey privateKey, {
    required MontgomeryPublicKey peerPublicKey,
  }) => privateKey.deriveSharedSecret(
    DiffieHellmanAgreementParams<MontgomeryPublicKey>(
      peerPublicKey: peerPublicKey,
    ),
  );
}
