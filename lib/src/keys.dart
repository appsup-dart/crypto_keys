part of '../crypto_keys.dart';

/// Shared base type for secret material used by operators.
abstract mixin class KeyMaterial {}

/// A cryptographic key
abstract mixin class Key implements KeyMaterial {}

/// A password input for password-based key derivation.
class Password with KeyMaterial {
  final Uint8List value;

  Password(List<int> value) : value = Uint8List.fromList(value);

  factory Password.fromString(String value) =>
      Password(Uint8List.fromList(utf8.encode(value)));

  /// Derives bytes using password-based KDF parameters.
  Uint8List deriveBits(PasswordKeyDeriverParams params) {
    if (params case Pbkdf2KeyDeriverParams()) {
      return _derivePbkdf2Bits(password: this, params: params);
    }
    if (params case Argon2idKeyDeriverParams()) {
      return _deriveArgon2idBits(password: this, params: params);
    }
    throw UnsupportedError(
      'Unsupported password key derivation params: ${params.runtimeType}',
    );
  }
}

/// Generic secret bytes input for key derivation APIs such as HKDF.
class SecretBytes with KeyMaterial {
  final Uint8List value;

  SecretBytes(List<int> value) : value = Uint8List.fromList(value);

  /// Derives bytes from this secret using shared-secret KDF parameters.
  Uint8List deriveBits(SecretBytesKeyDeriverParams params) {
    return switch (params) {
      HkdfKeyDeriverParams() => _deriveHkdfBits(secret: this, params: params),
      ConcatKdfKeyDeriverParams() => _deriveConcatKdfBits(
        secret: this,
        params: params,
      ),
    };
  }
}

/// A cryptographic public key
abstract mixin class PublicKey implements Key {}

/// A cryptographic private key
abstract mixin class PrivateKey implements Key {}

/// Capability: create signatures with a private key.
abstract mixin class SigningPrivateKey implements PrivateKey {
  /// Creates a [Signer] using this key and the specified algorithm.
  Signer createSigner(covariant SigningAlgorithm algorithm);
}

/// Capability: verify signatures with a public key.
abstract mixin class VerifyingPublicKey implements PublicKey {
  /// Creates a signature [Verifier] using this key and the specified algorithm.
  Verifier createVerifier(covariant SigningAlgorithm algorithm);
}

/// Capability: encrypt with a public key.
abstract mixin class EncryptingPublicKey implements PublicKey {
  /// Creates an [Encrypter] using this key and the specified algorithm.
  Encrypter createEncrypter(covariant EncryptionAlgorithm algorithm);
}

/// Capability: decrypt with a private key.
abstract mixin class DecryptingPrivateKey implements PrivateKey {
  /// Creates a [Decrypter] using this key and the specified algorithm.
  Decrypter createDecrypter(covariant EncryptionAlgorithm algorithm);
}

/// Capability marker for key-agreement public keys.
abstract mixin class AgreementPublicKey implements PublicKey {}

/// Capability: derive a shared secret using key agreement.
abstract mixin class AgreementPrivateKey<Params extends PrivateKeyDeriverParams>
    implements PrivateKey {
  SecretBytes deriveSharedSecret(covariant Params params);
}

/// Holds a key pair (private and public key)
abstract class KeyPair<Pub extends PublicKey, Priv extends PrivateKey> {
  /// The public key
  final Pub publicKey;

  /// The private key
  final Priv privateKey;

  /// Creates a [KeyPair] from a public and private key
  KeyPair({required this.publicKey, required this.privateKey});
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

class RsaKeyPair extends KeyPair<RsaPublicKey, RsaPrivateKey> {
  RsaKeyPair({
    required BigInt modulus,
    required BigInt exponent,
    required BigInt privateExponent,
    required BigInt firstPrimeFactor,
    required BigInt secondPrimeFactor,
  }) : super(
         publicKey: RsaPublicKey(modulus: modulus, exponent: exponent),
         privateKey: RsaPrivateKey(
           modulus: modulus,
           privateExponent: privateExponent,
           firstPrimeFactor: firstPrimeFactor,
           secondPrimeFactor: secondPrimeFactor,
         ),
       );

  RsaKeyPair.fromPrivateKey(
    RsaPrivateKey privateKey, {
    required BigInt exponent,
  }) : super(
         publicKey: RsaPublicKey(
           modulus: privateKey.modulus,
           exponent: exponent,
         ),
         privateKey: privateKey,
       );

  factory RsaKeyPair.generate({BigInt? exponent, int bitStrength = 2048}) {
    exponent ??= BigInt.from(65537);
    final generator = pc.RSAKeyGenerator()
      ..init(
        pc.ParametersWithRandom(
          pc.RSAKeyGeneratorParameters(exponent, bitStrength, 5),
          DefaultSecureRandom(),
        ),
      );
    final pair = generator.generateKeyPair();
    return RsaKeyPair(
      modulus: pair.publicKey.n!,
      exponent: pair.publicKey.publicExponent!,
      privateExponent: pair.privateKey.privateExponent!,
      firstPrimeFactor: pair.privateKey.p!,
      secondPrimeFactor: pair.privateKey.q!,
    );
  }
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
