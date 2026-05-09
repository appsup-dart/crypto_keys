part of '../crypto_keys.dart';

/// A symmetric key
class SymmetricKey
    with Key, PublicKey, PrivateKey
    implements
        SigningPrivateKey,
        VerifyingPublicKey,
        EncryptingPublicKey,
        DecryptingPrivateKey {
  /// The value of the symmetric (or other single-valued) key
  final Uint8List keyValue;

  SymmetricKey({required Uint8List keyValue})
    : keyValue = Uint8List.fromList(keyValue);

  factory SymmetricKey.generate(int bitLength) {
    if (bitLength % 8 != 0) {
      throw ArgumentError(
        'Illegal bit length $bitLength, should be mutiple of 8.',
      );
    }
    var value = DefaultSecureRandom().nextBytes(bitLength ~/ 8);
    return SymmetricKey(keyValue: value);
  }

  @override
  Signer createSigner(covariant SymmetricSigningAlgorithmIdentifier algorithm) {
    return _SymmetricSignerAndVerifier(algorithm, this);
  }

  @override
  Verifier createVerifier(
    covariant SymmetricSigningAlgorithmIdentifier algorithm,
  ) {
    return _SymmetricSignerAndVerifier(algorithm, this);
  }

  @override
  Encrypter createEncrypter(
    covariant SymmetricEncryptionAlgorithmIdentifier algorithm,
  ) {
    return _SymmetricEncrypter(algorithm, this);
  }

  @override
  Decrypter createDecrypter(
    covariant SymmetricEncryptionAlgorithmIdentifier algorithm,
  ) {
    return _SymmetricEncrypter(algorithm, this);
  }

  @override
  int get hashCode => const ListEquality().hash(keyValue);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is SymmetricKey &&
          const ListEquality().equals(other.keyValue, keyValue));
}
