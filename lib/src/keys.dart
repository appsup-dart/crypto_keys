part of '../crypto_keys.dart';

/// A cryptographic key
abstract class Key {
  /// Creates an [Encrypter] using this key and the specified algorithm
  Encrypter createEncrypter(Identifier algorithm) {
    if (this is SymmetricKey) {
      return _SymmetricEncrypter(algorithm, this);
    }

    return _AsymmetricEncrypter(algorithm, this);
  }
}

/// A cryptographic public key
abstract class PublicKey implements Key {
  /// Creates a signature [Verifier] using this key and the specified algorithm
  Verifier createVerifier(Identifier algorithm) {
    if (this is SymmetricKey) {
      return _SymmetricSignerAndVerifier(algorithm, this);
    }

    return _AsymmetricVerifier(algorithm, this);
  }
}

/// A cryptographic private key
abstract class PrivateKey implements Key {
  /// Creates a [Signer] using this key and the specified algorithm.
  Signer createSigner(Identifier algorithm) {
    if (this is SymmetricKey) {
      return _SymmetricSignerAndVerifier(algorithm, this);
    }

    return _AsymmetricSigner(algorithm, this);
  }
}

/// Holds a key pair (private and public key)
class KeyPair {
  /// The public key
  final PublicKey publicKey;

  /// The private key
  final PrivateKey privateKey;

  /// Creates a [KeyPair] from a public and private key
  KeyPair({@required this.publicKey, @required this.privateKey});

  /// Creates a [KeyPair] from a symmetric key
  KeyPair.symmetric(SymmetricKey key) : this(privateKey: key, publicKey: key);

  /// Generates a random symmetric [KeyPair] with specified bit length
  factory KeyPair.generateSymmetric(int bitLength) =>
      KeyPair.symmetric(SymmetricKey.generate(bitLength));

  /// Create a key pair from a JsonWebKey
  factory KeyPair.fromJwk(Map<String, dynamic> jwk) {
    switch (jwk['kty']) {
      case 'oct':
        var key = SymmetricKey(keyValue: _base64ToBytes(jwk['k']));
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
  Signer createSigner(Identifier algorithm) =>
      privateKey.createSigner(algorithm);

  /// Creates a signature [Verifier] using the public key and the specified
  /// algorithm
  Verifier createVerifier(Identifier algorithm) =>
      publicKey.createVerifier(algorithm);
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
  return {
    'P-256': curves.p256,
    'P-384': curves.p384,
    'P-521': curves.p521,
  }[name];
}
