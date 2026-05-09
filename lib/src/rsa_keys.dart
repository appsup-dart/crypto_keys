part of '../crypto_keys.dart';

/// Base class for RSA keys
abstract class RsaKey extends Key {
  /// The modulus value for the RSA key
  BigInt get modulus;
}

/// A RSA public key
class RsaPublicKey with Key implements RsaKey, PublicKey, VerifyingPublicKey, EncryptingPublicKey {
  @override
  final BigInt modulus;

  /// The exponent value for the RSA public key
  final BigInt exponent;

  RsaPublicKey({required this.modulus, required this.exponent});

  @override
  Verifier createVerifier(covariant RsaSigningAlgorithmIdentifier algorithm) {
    return _AsymmetricVerifier(algorithm, this);
  }

  @override
  Encrypter createEncrypter(
    covariant RsaEncryptionAlgorithmIdentifier algorithm,
  ) {
    return _AsymmetricEncrypter(algorithm, this);
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

  @override
  Signer createSigner(covariant RsaSigningAlgorithmIdentifier algorithm) {
    return _AsymmetricSigner(algorithm, this);
  }

  @override
  Decrypter createDecrypter(
    covariant RsaEncryptionAlgorithmIdentifier algorithm,
  ) {
    return _AsymmetricDecrypter(algorithm, this);
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
