import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart';

/// Symmetric encryption helpers (AEAD + legacy AES modes).
extension SymmetricEncryptionAlgorithmOps on SymmetricEncryptionAlgorithm {
  EncryptionResult encrypt(
    SymmetricKey key,
    Uint8List input, {
    Uint8List? initializationVector,
    Uint8List? additionalAuthenticatedData,
  }) => key
      .createEncrypter(this)
      .encrypt(
        input,
        initializationVector: initializationVector,
        additionalAuthenticatedData: additionalAuthenticatedData,
      );

  Uint8List decrypt(SymmetricKey key, EncryptionResult input) =>
      key.createDecrypter(this).decrypt(input);
}

/// RSA encryption helpers (short plaintexts / hybrid key transport).
extension RsaEncryptionAlgorithmOps on RsaEncryptionAlgorithm {
  EncryptionResult encrypt(
    RsaPublicKey publicKey,
    Uint8List input, {
    Uint8List? initializationVector,
    Uint8List? additionalAuthenticatedData,
  }) => publicKey
      .createEncrypter(this)
      .encrypt(
        input,
        initializationVector: initializationVector,
        additionalAuthenticatedData: additionalAuthenticatedData,
      );

  Uint8List decrypt(RsaPrivateKey privateKey, EncryptionResult input) =>
      privateKey.createDecrypter(this).decrypt(input);
}
