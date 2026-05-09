part of '../../crypto_keys.dart';

/// Ed25519 public key (32-byte encoding, RFC 8032).
class Ed25519PublicKey with Key implements PublicKey, VerifyingPublicKey {
  /// Raw public key bytes (32 octets).
  final Uint8List publicKeyBytes;

  Ed25519PublicKey({required Uint8List publicKeyBytes})
    : publicKeyBytes = Uint8List.fromList(publicKeyBytes) {
    if (this.publicKeyBytes.length != ed25519_impl.PublicKeySize) {
      throw ArgumentError.value(
        this.publicKeyBytes.length,
        'publicKeyBytes.length',
        'Ed25519 public key must be ${ed25519_impl.PublicKeySize} bytes',
      );
    }
  }

  @override
  Verifier createVerifier(covariant Ed25519SigningAlgorithm algorithm) {
    return Ed25519Verifier(algorithm, this);
  }

  @override
  int get hashCode => Object.hashAll(publicKeyBytes);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is Ed25519PublicKey &&
          const ListEquality<int>().equals(
            other.publicKeyBytes,
            publicKeyBytes,
          ));
}

/// Ed25519 private key as a 32-byte **seed** (RFC 8032 secret scalar seed).
class Ed25519PrivateKey with Key implements PrivateKey, SigningPrivateKey {
  /// RFC 8032 seed (32 octets); expanded key material is derived when signing.
  final Uint8List seed;

  Ed25519PrivateKey({required Uint8List seed})
    : seed = Uint8List.fromList(seed) {
    if (this.seed.length != ed25519_impl.SeedSize) {
      throw ArgumentError.value(
        this.seed.length,
        'seed.length',
        'Ed25519 seed must be ${ed25519_impl.SeedSize} bytes',
      );
    }
  }

  /// Derives and returns the corresponding [Ed25519KeyPair].
  Ed25519KeyPair asKeyPair() => Ed25519KeyPair.fromPrivateKey(this);

  @override
  Signer createSigner(covariant Ed25519SigningAlgorithm algorithm) {
    return Ed25519Signer(algorithm, this);
  }

  @override
  int get hashCode => Object.hashAll(seed);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is Ed25519PrivateKey &&
          const ListEquality<int>().equals(other.seed, seed));
}

/// Ed25519 key pair.
class Ed25519KeyPair extends KeyPair<Ed25519PublicKey, Ed25519PrivateKey> {
  Ed25519KeyPair({required Uint8List seed})
    : this.fromPrivateKey(Ed25519PrivateKey(seed: seed));

  Ed25519KeyPair.fromPrivateKey(Ed25519PrivateKey privateKey)
    : super(
        publicKey: (() {
          final priv = ed25519_impl.newKeyFromSeed(privateKey.seed);
          final pub = ed25519_impl.public(priv);
          return Ed25519PublicKey(
            publicKeyBytes: Uint8List.fromList(pub.bytes),
          );
        })(),
        privateKey: privateKey,
      );

  /// Generates a random Ed25519 key pair.
  factory Ed25519KeyPair.generate() {
    final pair = ed25519_impl.generateKey();
    return Ed25519KeyPair(seed: ed25519_impl.seed(pair.privateKey));
  }

  /// Builds a key pair from a 32-byte RFC 8032 seed.
  factory Ed25519KeyPair.fromSeed(Uint8List seed) {
    return Ed25519KeyPair(seed: seed);
  }
}
