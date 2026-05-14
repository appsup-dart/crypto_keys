part of '../../crypto_keys.dart';

/// RFC 8032 Edwards curves used for pure signatures (EdDSA-style).
///
/// Currently only [ed25519] is defined; more variants may be added later.
enum EdwardsCurve {
  /// Ed25519 (32-byte public key and seed encodings in this package).
  ed25519,
}

/// Base class for edwards-curve curve keys
abstract class EdwardsKey extends Key {
  /// The cryptographic curve used with the key
  EdwardsCurve get curve;
}

extension on EdwardsCurve {
  /// Byte length of a canonical encoded public key for this curve.
  int get publicKeyByteLength => ed25519_impl.PublicKeySize;

  /// Byte length of the RFC 8032 private **seed** for this curve.
  int get seedByteLength => ed25519_impl.SeedSize;
}

/// Edwards-curve public key for RFC 8032 pure signatures.
class EdwardsPublicKey with Key implements EdwardsKey, VerifyingPublicKey {
  @override
  final EdwardsCurve curve;

  final Uint8List publicKeyBytes;

  EdwardsPublicKey({required this.curve, required Uint8List publicKeyBytes})
    : publicKeyBytes = Uint8List.fromList(publicKeyBytes) {
    final n = curve.publicKeyByteLength;
    if (this.publicKeyBytes.length != n) {
      throw ArgumentError.value(
        this.publicKeyBytes.length,
        'publicKeyBytes.length',
        'Edwards public key for $curve must be $n bytes',
      );
    }
  }

  /// Shorthand for [EdwardsCurve.ed25519].
  factory EdwardsPublicKey.ed25519({required Uint8List publicKeyBytes}) =>
      EdwardsPublicKey(
        curve: EdwardsCurve.ed25519,
        publicKeyBytes: publicKeyBytes,
      );

  @override
  Verifier createVerifier(covariant EddsaSigningAlgorithm algorithm) {
    return switch (algorithm) {
      PureEddsaSigningAlgorithm() => EddsaVerifier(algorithm, this),
    };
  }

  @override
  int get hashCode => Object.hash(curve, Object.hashAll(publicKeyBytes));

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is EdwardsPublicKey &&
          other.curve == curve &&
          const ListEquality<int>().equals(
            other.publicKeyBytes,
            publicKeyBytes,
          ));
}

/// Edwards-curve private key (RFC 8032 seed octets).
class EdwardsPrivateKey with Key implements EdwardsKey, SigningPrivateKey {
  @override
  final EdwardsCurve curve;

  final Uint8List seed;

  EdwardsPrivateKey({required this.curve, required Uint8List seed})
    : seed = Uint8List.fromList(seed) {
    final n = curve.seedByteLength;
    if (this.seed.length != n) {
      throw ArgumentError.value(
        this.seed.length,
        'seed.length',
        'Edwards private key seed for $curve must be $n bytes',
      );
    }
  }

  /// Shorthand for [EdwardsCurve.ed25519].
  factory EdwardsPrivateKey.ed25519({required Uint8List seed}) =>
      EdwardsPrivateKey(curve: EdwardsCurve.ed25519, seed: seed);

  EdwardsKeyPair asKeyPair() => EdwardsKeyPair.fromPrivateKey(this);

  @override
  Signer createSigner(covariant EddsaSigningAlgorithm algorithm) {
    return switch (algorithm) {
      PureEddsaSigningAlgorithm() => EddsaSigner(algorithm, this),
    };
  }

  @override
  int get hashCode => Object.hash(curve, Object.hashAll(seed));

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is EdwardsPrivateKey &&
          other.curve == curve &&
          const ListEquality<int>().equals(other.seed, seed));
}

/// Edwards-curve key pair for RFC 8032 signatures.
class EdwardsKeyPair extends KeyPair<EdwardsPublicKey, EdwardsPrivateKey> {
  EdwardsKeyPair({required super.publicKey, required super.privateKey});

  EdwardsKeyPair._fromPrivate(EdwardsPrivateKey privateKey)
    : super(
        publicKey: (() {
          final priv = ed25519_impl.newKeyFromSeed(privateKey.seed);
          final pub = ed25519_impl.public(priv);
          return EdwardsPublicKey(
            curve: privateKey.curve,
            publicKeyBytes: Uint8List.fromList(pub.bytes),
          );
        })(),
        privateKey: privateKey,
      );

  /// Builds a pair from an existing private key (public half is derived).
  factory EdwardsKeyPair.fromPrivateKey(EdwardsPrivateKey privateKey) =>
      EdwardsKeyPair._fromPrivate(privateKey);

  /// Builds a pair from an RFC 8032 seed for [curve].
  factory EdwardsKeyPair.fromSeed(EdwardsCurve curve, Uint8List seed) =>
      EdwardsKeyPair.fromPrivateKey(
        EdwardsPrivateKey(curve: curve, seed: seed),
      );

  /// Random key pair for [curve].
  factory EdwardsKeyPair.generate(EdwardsCurve curve) {
    final pair = ed25519_impl.generateKey();
    return EdwardsKeyPair.fromPrivateKey(
      EdwardsPrivateKey(curve: curve, seed: ed25519_impl.seed(pair.privateKey)),
    );
  }
}
