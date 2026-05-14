part of '../../crypto_keys.dart';

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
      DiffieHellmanAgreementParams<EcPublicKey>() => EcdhKeyAgreement(
        this,
      ).deriveSharedSecret(params),
      _ => throw StateError(
        'Invalid key agreement parameters for ECDH: this path should be unreachable.',
      ),
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

class EcKeyPair extends KeyPair<EcPublicKey, EcPrivateKey> {
  EcKeyPair({
    required Curve curve,
    required BigInt xCoordinate,
    required BigInt yCoordinate,
    required BigInt eccPrivateKey,
  }) : super(
         publicKey: EcPublicKey(
           xCoordinate: xCoordinate,
           yCoordinate: yCoordinate,
           curve: curve,
         ),
         privateKey: EcPrivateKey(eccPrivateKey: eccPrivateKey, curve: curve),
       );

  EcKeyPair.fromPrivateKey(EcPrivateKey privateKey)
    : super(
        publicKey: (() {
          final domain = ecDomainParametersForCurve(privateKey.curve);
          final q = domain.G * privateKey.eccPrivateKey;
          return EcPublicKey(
            xCoordinate: q!.x!.toBigInteger()!,
            yCoordinate: q.y!.toBigInteger()!,
            curve: privateKey.curve,
          );
        })(),
        privateKey: privateKey,
      );

  factory EcKeyPair.generate(Curve curve) {
    final generator = pc.ECKeyGenerator()
      ..init(
        pc.ParametersWithRandom(
          pc.ECKeyGeneratorParameters(ecDomainParametersForCurve(curve)),
          DefaultSecureRandom(),
        ),
      );
    final pair = generator.generateKeyPair();
    return EcKeyPair(
      curve: curve,
      xCoordinate: pair.publicKey.Q!.x!.toBigInteger()!,
      yCoordinate: pair.publicKey.Q!.y!.toBigInteger()!,
      eccPrivateKey: pair.privateKey.d!,
    );
  }
}
