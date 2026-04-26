part of '../crypto_keys.dart';

/// Shared base type for secret material used by operators.
abstract mixin class KeyMaterial {}

/// Shared capability for types that can derive keys.
mixin CanDeriveKey on KeyMaterial {
  KeyDeriver createKeyDeriver(Identifier algorithm);
}

/// A cryptographic key
abstract mixin class Key implements KeyMaterial {
  /// Creates an [Encrypter] using this key and the specified algorithm
  Encrypter createEncrypter(Identifier algorithm) {
    if (this is SymmetricKey) {
      return _SymmetricEncrypter(algorithm, this as SymmetricKey);
    }

    return _AsymmetricEncrypter(algorithm, this);
  }
}

/// A password input for password-based key derivation.
class Password with KeyMaterial, CanDeriveKey {
  final Uint8List value;

  Password(List<int> value) : value = Uint8List.fromList(value);

  factory Password.fromString(String value) =>
      Password(Uint8List.fromList(utf8.encode(value)));

  /// Creates a [KeyDeriver] using this password and algorithm.
  @override
  KeyDeriver<Password, Pbkdf2KeyDeriverParams> createKeyDeriver(
          Identifier algorithm) =>
      _PasswordBasedKeyDeriver(algorithm, this);
}

/// Generic secret bytes input for key derivation APIs such as HKDF.
class SecretBytes with KeyMaterial, CanDeriveKey {
  final Uint8List value;

  SecretBytes(List<int> value) : value = Uint8List.fromList(value);

  /// Creates a [KeyDeriver] using these bytes and algorithm.
  @override
  KeyDeriver<SecretBytes, HkdfKeyDeriverParams> createKeyDeriver(
          Identifier algorithm) =>
      _SecretBytesKeyDeriver(algorithm, this);
}

/// A cryptographic public key
abstract mixin class PublicKey implements Key {
  /// Creates a signature [Verifier] using this key and the specified algorithm
  Verifier createVerifier(Identifier algorithm) {
    if (this is SymmetricKey) {
      return _SymmetricSignerAndVerifier(algorithm, this as SymmetricKey);
    }

    return _AsymmetricVerifier(algorithm, this);
  }
}

/// A cryptographic private key
abstract mixin class PrivateKey implements Key, CanDeriveKey {
  /// Creates a [Signer] using this key and the specified algorithm.
  Signer createSigner(Identifier algorithm) {
    if (this is SymmetricKey) {
      return _SymmetricSignerAndVerifier(algorithm, this as SymmetricKey);
    }

    return _AsymmetricSigner(algorithm, this);
  }

  /// Creates a [KeyDeriver] using this key and the specified algorithm.
  @override
  KeyDeriver<PrivateKey, EcdhKeyDeriverParams> createKeyDeriver(
      Identifier algorithm) {
    if (this is SymmetricKey) {
      throw UnsupportedError('Key derivation requires an asymmetric key pair');
    }
    return _AsymmetricKeyDeriver(algorithm, this);
  }
}

/// Holds a key pair (private and public key)
class KeyPair {
  /// The public key
  final PublicKey? publicKey;

  /// The private key
  final PrivateKey? privateKey;

  /// Creates a [KeyPair] from a public and private key
  KeyPair({required this.publicKey, required this.privateKey});

  /// Creates a [KeyPair] from a symmetric key
  KeyPair.symmetric(SymmetricKey key) : this(privateKey: key, publicKey: key);

  /// Generates a random symmetric [KeyPair] with specified bit length
  factory KeyPair.generateSymmetric(int bitLength) =>
      KeyPair.symmetric(SymmetricKey.generate(bitLength));

  factory KeyPair.generateRsa({BigInt? exponent, int bitStrength = 2048}) {
    exponent ??= BigInt.from(65537);

    var generator = pc.RSAKeyGenerator()
      ..init(pc.ParametersWithRandom(
          pc.RSAKeyGeneratorParameters(exponent, bitStrength, 5),
          DefaultSecureRandom()));

    var pair = generator.generateKeyPair();

    return KeyPair(
        publicKey: RsaPublicKey(
          exponent: pair.publicKey.publicExponent!,
          modulus: pair.publicKey.n!,
        ),
        privateKey: RsaPrivateKey(
          modulus: (pair.privateKey).n!,
          privateExponent: pair.privateKey.privateExponent!,
          firstPrimeFactor: pair.privateKey.p!,
          secondPrimeFactor: pair.privateKey.q!,
        ));
  }

  factory KeyPair.generateEc(Identifier curve) {
    var generator = pc.ECKeyGenerator()
      ..init(
        pc.ParametersWithRandom(
          pc.ECKeyGeneratorParameters(
            _AsymmetricOperator.createCurveParameters(curve),
          ),
          DefaultSecureRandom(),
        ),
      );

    var pair = generator.generateKeyPair();

    return KeyPair(
        publicKey: EcPublicKey(
            xCoordinate: pair.publicKey.Q!.x!.toBigInteger()!,
            yCoordinate: pair.publicKey.Q!.y!.toBigInteger()!,
            curve: curve),
        privateKey:
            EcPrivateKey(eccPrivateKey: pair.privateKey.d!, curve: curve));
  }

  /// Create a key pair from a JsonWebKey
  factory KeyPair.fromJwk(Map<String, dynamic> jwk) {
    switch (jwk['kty']) {
      case 'oct':
        var key = SymmetricKey(keyValue: _base64ToBytes(jwk['k']) as Uint8List);
        return KeyPair(publicKey: key, privateKey: key);
      case 'RSA':
        return KeyPair(
            publicKey: jwk.containsKey('n') && jwk.containsKey('e')
                ? RsaPublicKey(
                    modulus: _base64ToInt(jwk['n']),
                    exponent: _base64ToInt(jwk['e']),
                  )
                : null,
            privateKey: jwk.containsKey('n') &&
                    jwk.containsKey('d') &&
                    jwk.containsKey('p') &&
                    jwk.containsKey('q')
                ? RsaPrivateKey(
                    modulus: _base64ToInt(jwk['n']),
                    privateExponent: _base64ToInt(jwk['d']),
                    firstPrimeFactor: _base64ToInt(jwk['p']),
                    secondPrimeFactor: _base64ToInt(jwk['q']),
                  )
                : null);
      case 'EC':
        return KeyPair(
            privateKey: jwk.containsKey('d') && jwk.containsKey('crv')
                ? EcPrivateKey(
                    eccPrivateKey: _base64ToInt(jwk['d']),
                    curve: _parseCurve(jwk['crv']))
                : null,
            publicKey: jwk.containsKey('x') &&
                    jwk.containsKey('y') &&
                    jwk.containsKey('crv')
                ? EcPublicKey(
                    xCoordinate: _base64ToInt(jwk['x']),
                    yCoordinate: _base64ToInt(jwk['y']),
                    curve: _parseCurve(jwk['crv']))
                : null);
    }
    throw ArgumentError('Unknown key type ${jwk['kty']}');
  }

  /// Creates a [Signer] using the private key and the specified algorithm.
  Signer createSigner(Identifier algorithm) {
    if (privateKey == null) {
      throw StateError('Need a private key to create a signer.');
    }
    return privateKey!.createSigner(algorithm);
  }

  /// Creates a signature [Verifier] using the public key and the specified
  /// algorithm
  Verifier createVerifier(Identifier algorithm) {
    if (publicKey == null) {
      throw StateError('Need a public key to create a verifier.');
    }
    return publicKey!.createVerifier(algorithm);
  }

  /// Creates a [KeyDeriver] for this key pair.
  KeyDeriver<PrivateKey, EcdhKeyDeriverParams> createKeyDeriver(
      Identifier algorithm) {
    if (privateKey == null) {
      throw StateError('Need a private key to create a key deriver.');
    }
    return privateKey!.createKeyDeriver(algorithm);
  }
}

List<int> _base64ToBytes(String encoded) {
  encoded += List.filled((4 - encoded.length % 4) % 4, '=').join();
  return base64Url.decode(encoded);
}

BigInt _base64ToInt(String encoded) {
  final b256 = BigInt.from(256);
  return _base64ToBytes(encoded)
      .fold(BigInt.zero, (a, b) => a * b256 + BigInt.from(b));
}

Identifier _parseCurve(String name) {
  var v = {
    'P-256': curves.p256,
    'P-256K': curves.p256k,
    'P-384': curves.p384,
    'P-521': curves.p521,
  }[name];
  if (v == null) {
    throw UnsupportedError('Unknown curve $name');
  }
  return v;
}
