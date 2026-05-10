import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart';

extension SymmetricSigningAlgorithmOps on SymmetricSigningAlgorithm {
  Signature sign(SymmetricKey key, List<int> data) =>
      key.createSigner(this).sign(data);

  bool verify(SymmetricKey key, Uint8List data, Signature signature) =>
      key.createVerifier(this).verify(data, signature);
}

extension RsaSigningAlgorithmOps on RsaSigningAlgorithm {
  Signature sign(RsaPrivateKey privateKey, List<int> data) =>
      privateKey.createSigner(this).sign(data);

  bool verify(RsaPublicKey publicKey, Uint8List data, Signature signature) =>
      publicKey.createVerifier(this).verify(data, signature);
}

extension EcSigningAlgorithmOps on EcSigningAlgorithm {
  Signature sign(EcPrivateKey privateKey, List<int> data) =>
      privateKey.createSigner(this).sign(data);

  bool verify(EcPublicKey publicKey, Uint8List data, Signature signature) =>
      publicKey.createVerifier(this).verify(data, signature);
}

extension Ed25519SigningAlgorithmOps on Ed25519SigningAlgorithm {
  Signature sign(Ed25519PrivateKey privateKey, List<int> data) =>
      privateKey.createSigner(this).sign(data);

  bool verify(
    Ed25519PublicKey publicKey,
    Uint8List data,
    Signature signature,
  ) => publicKey.createVerifier(this).verify(data, signature);
}
