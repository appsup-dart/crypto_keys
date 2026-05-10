part of '../../crypto_keys.dart';

/// Single shared secret powering symmetric signatures (HMAC) and symmetric ciphers
/// (AES, ChaCha20-Poly1305, AES Key Wrap).
///
/// Create fresh material with [SymmetricKey.generate] or clone existing bytes via
/// the constructor (`SymmetricKey(keyValue: …)`); [SymmetricKeyPair] mirrors the same
/// key for ergonomic APIs.
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

  /// Returns this symmetric key as a key pair.
  SymmetricKeyPair asKeyPair() => SymmetricKeyPair.fromKey(this);

  @override
  Signer createSigner(covariant SymmetricSigningAlgorithm algorithm) {
    return SymmetricSignerAndVerifier(algorithm, this);
  }

  @override
  Verifier createVerifier(covariant SymmetricSigningAlgorithm algorithm) {
    return SymmetricSignerAndVerifier(algorithm, this);
  }

  @override
  Encrypter createEncrypter(covariant SymmetricEncryptionAlgorithm algorithm) {
    return SymmetricCipherOperator(algorithm, this);
  }

  @override
  Decrypter createDecrypter(covariant SymmetricEncryptionAlgorithm algorithm) {
    return SymmetricCipherOperator(algorithm, this);
  }

  @override
  int get hashCode => const ListEquality().hash(keyValue);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is SymmetricKey &&
          const ListEquality().equals(other.keyValue, keyValue));
}

class SymmetricKeyPair extends KeyPair<SymmetricKey, SymmetricKey> {
  SymmetricKeyPair({required Uint8List keyValue})
    : this.fromKey(SymmetricKey(keyValue: keyValue));

  SymmetricKeyPair.fromKey(SymmetricKey key)
    : super(publicKey: key, privateKey: key);

  factory SymmetricKeyPair.generate(int bitLength) {
    return SymmetricKeyPair.fromKey(SymmetricKey.generate(bitLength));
  }
}
