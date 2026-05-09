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
  Signer createSigner(covariant SigningAlgorithmIdentifier algorithm);
}

/// Capability: verify signatures with a public key.
abstract mixin class VerifyingPublicKey implements PublicKey {
  /// Creates a signature [Verifier] using this key and the specified algorithm.
  Verifier createVerifier(covariant SigningAlgorithmIdentifier algorithm);
}

/// Capability: encrypt with a public key.
abstract mixin class EncryptingPublicKey implements PublicKey {
  /// Creates an [Encrypter] using this key and the specified algorithm.
  Encrypter createEncrypter(covariant EncryptionAlgorithmIdentifier algorithm);
}

/// Capability: decrypt with a private key.
abstract mixin class DecryptingPrivateKey implements PrivateKey {
  /// Creates a [Decrypter] using this key and the specified algorithm.
  Decrypter createDecrypter(covariant EncryptionAlgorithmIdentifier algorithm);
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
  final Pub? publicKey;

  /// The private key
  final Priv? privateKey;

  /// Creates a [KeyPair] from a public and private key
  KeyPair({required this.publicKey, required this.privateKey})
    : assert(
        publicKey != null || privateKey != null,
        'Either public or private key must be provided',
      );

  /// Creates a [KeyPair] from a symmetric key.
  @factory
  static SymmetricKeyPair symmetric(SymmetricKey key) =>
      SymmetricKeyPair(publicKey: key, privateKey: key);

  /// Generates a random symmetric [KeyPair] with specified bit length.
  @factory
  static SymmetricKeyPair generateSymmetric(int bitLength) =>
      SymmetricKeyPair.generate(bitLength);

  /// Generates a random RSA [KeyPair] with specified exponent and bit strength.
  @factory
  static RsaKeyPair generateRsa({BigInt? exponent, int bitStrength = 2048}) =>
      RsaKeyPair.generate(exponent: exponent, bitStrength: bitStrength);

  /// Generates a random elliptic curve [KeyPair] with specified curve.
  @factory
  static EcKeyPair generateEc(CurveIdentifier curve) =>
      EcKeyPair.generate(curve);

  /// Create a key pair from a JsonWebKey
  static KeyPair<PublicKey, PrivateKey> fromJwk(Map<String, dynamic> jwk) {
    switch (jwk['kty']) {
      case 'oct':
        var key = SymmetricKey(keyValue: _base64ToBytes(jwk['k']) as Uint8List);
        return SymmetricKeyPair(publicKey: key, privateKey: key);
      case 'RSA':
        return RsaKeyPair(
          publicKey: jwk.containsKey('n') && jwk.containsKey('e')
              ? RsaPublicKey(
                  modulus: _base64ToInt(jwk['n']),
                  exponent: _base64ToInt(jwk['e']),
                )
              : null,
          privateKey:
              jwk.containsKey('n') &&
                  jwk.containsKey('d') &&
                  jwk.containsKey('p') &&
                  jwk.containsKey('q')
              ? RsaPrivateKey(
                  modulus: _base64ToInt(jwk['n']),
                  privateExponent: _base64ToInt(jwk['d']),
                  firstPrimeFactor: _base64ToInt(jwk['p']),
                  secondPrimeFactor: _base64ToInt(jwk['q']),
                )
              : null,
        );
      case 'EC':
        return EcKeyPair(
          privateKey: jwk.containsKey('d') && jwk.containsKey('crv')
              ? EcPrivateKey(
                  eccPrivateKey: _base64ToInt(jwk['d']),
                  curve: _parseCurve(jwk['crv']),
                )
              : null,
          publicKey:
              jwk.containsKey('x') &&
                  jwk.containsKey('y') &&
                  jwk.containsKey('crv')
              ? EcPublicKey(
                  xCoordinate: _base64ToInt(jwk['x']),
                  yCoordinate: _base64ToInt(jwk['y']),
                  curve: _parseCurve(jwk['crv']),
                )
              : null,
        );
    }
    throw ArgumentError('Unknown key type ${jwk['kty']}');
  }
}

class SymmetricKeyPair extends KeyPair<SymmetricKey, SymmetricKey> {
  SymmetricKeyPair({
    required SymmetricKey publicKey,
    required SymmetricKey privateKey,
  }) : super(publicKey: publicKey, privateKey: privateKey);

  factory SymmetricKeyPair.generate(int bitLength) {
    final key = SymmetricKey.generate(bitLength);
    return SymmetricKeyPair(publicKey: key, privateKey: key);
  }
}

class RsaKeyPair extends KeyPair<RsaPublicKey, RsaPrivateKey> {
  RsaKeyPair({required super.publicKey, required super.privateKey});

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
      publicKey: RsaPublicKey(
        exponent: pair.publicKey.publicExponent!,
        modulus: pair.publicKey.n!,
      ),
      privateKey: RsaPrivateKey(
        modulus: (pair.privateKey).n!,
        privateExponent: pair.privateKey.privateExponent!,
        firstPrimeFactor: pair.privateKey.p!,
        secondPrimeFactor: pair.privateKey.q!,
      ),
    );
  }
}

class EcKeyPair extends KeyPair<EcPublicKey, EcPrivateKey> {
  EcKeyPair({required super.publicKey, required super.privateKey});

  factory EcKeyPair.generate(CurveIdentifier curve) {
    final generator = pc.ECKeyGenerator()
      ..init(
        pc.ParametersWithRandom(
          pc.ECKeyGeneratorParameters(
            _AsymmetricOperator.createCurveParameters(curve),
          ),
          DefaultSecureRandom(),
        ),
      );
    final pair = generator.generateKeyPair();
    return EcKeyPair(
      publicKey: EcPublicKey(
        xCoordinate: pair.publicKey.Q!.x!.toBigInteger()!,
        yCoordinate: pair.publicKey.Q!.y!.toBigInteger()!,
        curve: curve,
      ),
      privateKey: EcPrivateKey(eccPrivateKey: pair.privateKey.d!, curve: curve),
    );
  }
}

List<int> _base64ToBytes(String encoded) {
  encoded += List.filled((4 - encoded.length % 4) % 4, '=').join();
  return base64Url.decode(encoded);
}

BigInt _base64ToInt(String encoded) {
  final b256 = BigInt.from(256);
  return _base64ToBytes(
    encoded,
  ).fold(BigInt.zero, (a, b) => a * b256 + BigInt.from(b));
}

CurveIdentifier _parseCurve(String name) {
  var v = {
    'P-256': CurveIdentifier.p256,
    'P-256K': CurveIdentifier.p256k,
    'P-384': CurveIdentifier.p384,
    'P-521': CurveIdentifier.p521,
  }[name];
  if (v == null) {
    throw UnsupportedError('Unknown curve $name');
  }
  return v;
}
