part of '../../crypto_keys.dart';

/// RFC 7748 Montgomery curves used for raw Diffie–Hellman key agreement.
///
/// Currently only [x25519] is defined; more variants may be added later.
enum MontgomeryCurve {
  /// Curve25519 (128-bit classical security target, 32-byte encodings).
  x25519,
}

extension on MontgomeryCurve {
  /// Byte length of a Montgomery public `u`-coordinate for this curve.
  int get publicKeyByteLength => switch (this) {
    MontgomeryCurve.x25519 => x25519_impl.PointSize,
  };

  /// Byte length of a raw RFC 7748 private scalar for this curve.
  int get privateKeyByteLength => switch (this) {
    MontgomeryCurve.x25519 => x25519_impl.ScalarSize,
  };
}

/// Montgomery-curve public key for RFC 7748 key agreement (`u`-coordinate).
class MontgomeryPublicKey with Key implements AgreementPublicKey {
  final MontgomeryCurve curve;

  final Uint8List uCoordinate;

  MontgomeryPublicKey({required this.curve, required Uint8List uCoordinate})
    : uCoordinate = Uint8List.fromList(uCoordinate) {
    final n = curve.publicKeyByteLength;
    if (this.uCoordinate.length != n) {
      throw ArgumentError.value(
        this.uCoordinate.length,
        'uCoordinate.length',
        'Montgomery public key for $curve must be $n bytes',
      );
    }
  }

  /// Shorthand for [MontgomeryCurve.x25519].
  factory MontgomeryPublicKey.x25519({required Uint8List uCoordinate}) =>
      MontgomeryPublicKey(
        curve: MontgomeryCurve.x25519,
        uCoordinate: uCoordinate,
      );

  @override
  int get hashCode => Object.hash(curve, Object.hashAll(uCoordinate));

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is MontgomeryPublicKey &&
          other.curve == curve &&
          const ListEquality<int>().equals(other.uCoordinate, uCoordinate));
}

/// Montgomery-curve private key for RFC 7748 key agreement (raw scalar encoding).
class MontgomeryPrivateKey
    with Key
    implements PrivateKey, AgreementPrivateKey<MontgomeryKeyAgreementParams> {
  final MontgomeryCurve curve;

  final Uint8List scalarBytes;

  MontgomeryPrivateKey({required this.curve, required Uint8List scalarBytes})
    : scalarBytes = Uint8List.fromList(scalarBytes) {
    final n = curve.privateKeyByteLength;
    if (this.scalarBytes.length != n) {
      throw ArgumentError.value(
        this.scalarBytes.length,
        'scalarBytes.length',
        'Montgomery private key for $curve must be $n bytes',
      );
    }
  }

  /// Shorthand for [MontgomeryCurve.x25519].
  factory MontgomeryPrivateKey.x25519({required Uint8List scalarBytes}) =>
      MontgomeryPrivateKey(
        curve: MontgomeryCurve.x25519,
        scalarBytes: scalarBytes,
      );

  MontgomeryKeyPair asKeyPair() => MontgomeryKeyPair.fromPrivateKey(this);

  @override
  SecretBytes deriveSharedSecret(MontgomeryKeyAgreementParams params) =>
      MontgomeryKeyAgreement(this).deriveSharedSecret(params);

  @override
  int get hashCode => Object.hash(curve, Object.hashAll(scalarBytes));

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is MontgomeryPrivateKey &&
          other.curve == curve &&
          const ListEquality<int>().equals(other.scalarBytes, scalarBytes));
}

/// Montgomery Diffie–Hellman key pair (RFC 7748).
class MontgomeryKeyPair
    extends KeyPair<MontgomeryPublicKey, MontgomeryPrivateKey> {
  MontgomeryKeyPair({required super.publicKey, required super.privateKey});

  /// Random key pair for [curve] (clamped scalar, standard base point where applicable).
  factory MontgomeryKeyPair.generate(MontgomeryCurve curve) {
    final raw = x25519_impl.generateKeyPair();
    return MontgomeryKeyPair(
      publicKey: MontgomeryPublicKey(
        curve: curve,
        uCoordinate: Uint8List.fromList(raw.publicKey),
      ),
      privateKey: MontgomeryPrivateKey(
        curve: curve,
        scalarBytes: Uint8List.fromList(raw.privateKey),
      ),
    );
  }

  /// Builds a pair from a raw private scalar for [curve].
  factory MontgomeryKeyPair.fromPrivateKeyBytes(
    MontgomeryCurve curve,
    Uint8List privateScalar,
  ) {
    final scalar = Uint8List.fromList(privateScalar);
    final derived = x25519_impl.X25519(scalar, x25519_impl.basePoint);
    return MontgomeryKeyPair(
      publicKey: MontgomeryPublicKey(curve: curve, uCoordinate: derived),
      privateKey: MontgomeryPrivateKey(curve: curve, scalarBytes: scalar),
    );
  }

  factory MontgomeryKeyPair.fromPrivateKey(MontgomeryPrivateKey privateKey) =>
      MontgomeryKeyPair.fromPrivateKeyBytes(
        privateKey.curve,
        privateKey.scalarBytes,
      );
}
