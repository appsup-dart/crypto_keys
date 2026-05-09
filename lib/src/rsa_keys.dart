part of '../crypto_keys.dart';

/// Base class for RSA keys
abstract class RsaKey extends Key {
  /// The modulus value for the RSA key
  BigInt get modulus;
}

/// A RSA public key
class RsaPublicKey
    with Key
    implements RsaKey, PublicKey, VerifyingPublicKey, EncryptingPublicKey {
  @override
  final BigInt modulus;

  /// The exponent value for the RSA public key
  final BigInt exponent;

  RsaPublicKey({required this.modulus, required this.exponent});

  @override
  Verifier createVerifier(covariant RsaSigningAlgorithm algorithm) {
    return RsaVerifier(algorithm, this);
  }

  @override
  Encrypter createEncrypter(
    covariant RsaEncryptionAlgorithm algorithm,
  ) {
    return RsaEncrypter(algorithm, this);
  }

  @override
  int get hashCode => Object.hash(exponent, modulus);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is RsaPublicKey &&
          other.exponent == exponent &&
          other.modulus == modulus);
}

/// A RSA private key
class RsaPrivateKey
    with Key
    implements RsaKey, PrivateKey, SigningPrivateKey, DecryptingPrivateKey {
  @override
  final BigInt modulus;

  /// The private exponent value for the RSA private key
  final BigInt privateExponent;

  /// The first prime factor
  final BigInt firstPrimeFactor;

  /// The second prime factor
  final BigInt secondPrimeFactor;

  RsaPrivateKey({
    required this.privateExponent,
    required this.firstPrimeFactor,
    required this.secondPrimeFactor,
    required this.modulus,
  });

  /// Returns the corresponding [RsaKeyPair] for the given public exponent.
  RsaKeyPair asKeyPair({required BigInt exponent}) =>
      RsaKeyPair.fromPrivateKey(this, exponent: exponent);

  @override
  Signer createSigner(covariant RsaSigningAlgorithm algorithm) {
    return RsaSigner(algorithm, this);
  }

  @override
  Decrypter createDecrypter(
    covariant RsaEncryptionAlgorithm algorithm,
  ) {
    return RsaDecrypter(algorithm, this);
  }

  @override
  int get hashCode => Object.hash(
    privateExponent,
    firstPrimeFactor,
    secondPrimeFactor,
    modulus,
  );

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is RsaPrivateKey &&
          other.privateExponent == privateExponent &&
          other.firstPrimeFactor == firstPrimeFactor &&
          other.secondPrimeFactor == secondPrimeFactor &&
          other.modulus == modulus);
}
