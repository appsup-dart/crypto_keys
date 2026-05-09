part of '../crypto_keys.dart';

/// Base class for elliptic curve (EC) keys
abstract class EcKey extends Key {
  /// The cryptographic curve used with the key
  Curve get curve;
}

/// An elliptic curve (EC) public key
class EcPublicKey
    with Key
    implements EcKey, PublicKey, VerifyingPublicKey, AgreementPublicKey {
  @override
  final Curve curve;

  /// The x coordinate for the Elliptic Curve point
  final BigInt xCoordinate;

  /// The y coordinate for the Elliptic Curve point
  final BigInt yCoordinate;

  EcPublicKey({
    required this.xCoordinate,
    required this.yCoordinate,
    required this.curve,
  });

  @override
  Verifier createVerifier(covariant EcSigningAlgorithm algorithm) {
    return EcVerifier(algorithm, this);
  }

  @override
  int get hashCode => Object.hash(xCoordinate, yCoordinate, curve);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is EcPublicKey &&
          other.xCoordinate == xCoordinate &&
          other.yCoordinate == yCoordinate &&
          other.curve == curve);
}

/// An elliptic curve (EC) private key
class EcPrivateKey
    with Key
    implements
        EcKey,
        PrivateKey,
        SigningPrivateKey,
        AgreementPrivateKey<EcKeyAgreementParams> {
  @override
  final Curve curve;

  /// The Elliptic Curve private key value
  final BigInt eccPrivateKey;

  EcPrivateKey({required this.eccPrivateKey, required this.curve});

  /// Derives and returns the corresponding [EcKeyPair].
  EcKeyPair asKeyPair() => EcKeyPair.fromPrivateKey(this);

  @override
  Signer createSigner(covariant EcSigningAlgorithm algorithm) {
    return EcSigner(algorithm, this);
  }

  @override
  SecretBytes deriveSharedSecret(EcKeyAgreementParams params) {
    return switch (params) {
      EcdhKeyAgreementParams() => EcdhKeyAgreement(
        this,
      ).deriveSharedSecret(params),
    };
  }

  @override
  int get hashCode => Object.hash(eccPrivateKey, curve);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is EcPrivateKey &&
          other.eccPrivateKey == eccPrivateKey &&
          other.curve == curve);
}
