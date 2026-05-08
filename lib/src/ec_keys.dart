part of '../crypto_keys.dart';

/// Base class for elliptic curve (EC) keys
abstract class EcKey extends Key {
  /// The cryptographic curve used with the key
  CurveIdentifier get curve;
}

/// An elliptic curve (EC) public key
class EcPublicKey with Key implements EcKey, PublicKey {
  @override
  final CurveIdentifier curve;

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
  Verifier createVerifier(covariant EcSigningAlgorithmIdentifier algorithm) {
    return _AsymmetricVerifier(algorithm, this);
  }

  @override
  Encrypter createEncrypter(
    covariant EcEncryptionAlgorithmIdentifier algorithm,
  ) {
    throw UnsupportedError(
      'EC public keys do not support encryption with ${algorithm.name}.',
    );
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
class EcPrivateKey with Key implements EcKey, PrivateKey {
  @override
  final CurveIdentifier curve;

  /// The Elliptic Curve private key value
  final BigInt eccPrivateKey;

  EcPrivateKey({required this.eccPrivateKey, required this.curve});

  @override
  Signer createSigner(covariant EcSigningAlgorithmIdentifier algorithm) {
    return _AsymmetricSigner(algorithm, this);
  }

  @override
  Decrypter createDecrypter(
    covariant EcEncryptionAlgorithmIdentifier algorithm,
  ) {
    throw UnsupportedError(
      'EC private keys do not support encryption with ${algorithm.name}.',
    );
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

extension EcPrivateKeyDerivation on EcPrivateKey {
  /// Derives an ECDH shared secret with a peer EC public key.
  SecretBytes deriveSharedSecret(EcKeyAgreementParams params) {
    return switch (params) {
      EcdhKeyDeriverParams() => _deriveEcdhSharedSecret(
        privateKey: this,
        params: params,
      ),
    };
  }
}
