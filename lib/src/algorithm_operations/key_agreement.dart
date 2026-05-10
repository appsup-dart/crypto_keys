import 'package:crypto_keys/crypto_keys.dart';

extension EcdhKeyAgreementAlgorithmDerive on EcdhKeyAgreementAlgorithm {
  /// ECDH shared secret (same semantics as [EcPrivateKey.deriveSharedSecret]).
  SecretBytes deriveSharedSecret(
    EcPrivateKey privateKey, {
    required EcPublicKey peerPublicKey,
  }) {
    return privateKey.deriveSharedSecret(
      EcdhKeyAgreementParams(peerPublicKey: peerPublicKey),
    );
  }
}

extension X25519KeyAgreementAlgorithmDerive on X25519KeyAgreementAlgorithm {
  /// X25519 shared secret (same semantics as [X25519PrivateKey.deriveSharedSecret]).
  SecretBytes deriveSharedSecret(
    X25519PrivateKey privateKey, {
    required X25519PublicKey peerPublicKey,
  }) {
    return privateKey.deriveSharedSecret(
      X25519KeyAgreementParams(peerPublicKey: peerPublicKey),
    );
  }
}
