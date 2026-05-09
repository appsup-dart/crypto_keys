part of '../../crypto_keys.dart';

/// X25519 public key: 32-byte u-coordinate (RFC 7748).
class X25519PublicKey with Key implements PublicKey, AgreementPublicKey {
  /// Montgomery u-coordinate of the peer or local public point.
  final Uint8List uCoordinate;

  X25519PublicKey({required Uint8List uCoordinate})
    : uCoordinate = Uint8List.fromList(uCoordinate) {
    if (this.uCoordinate.length != x25519_impl.PointSize) {
      throw ArgumentError.value(
        this.uCoordinate.length,
        'uCoordinate.length',
        'X25519 public key must be ${x25519_impl.PointSize} bytes',
      );
    }
  }

  @override
  int get hashCode => Object.hashAll(uCoordinate);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is X25519PublicKey &&
          const ListEquality<int>().equals(other.uCoordinate, uCoordinate));
}

/// X25519 private key: 32-byte scalar (RFC 7748 encoding).
///
/// Scalar clamping follows [x25519_impl.X25519] when deriving the shared secret.
class X25519PrivateKey
    with Key
    implements PrivateKey, AgreementPrivateKey<OkpKeyAgreementParams> {
  final Uint8List scalarBytes;

  X25519PrivateKey({required Uint8List scalarBytes})
    : scalarBytes = Uint8List.fromList(scalarBytes) {
    if (this.scalarBytes.length != x25519_impl.ScalarSize) {
      throw ArgumentError.value(
        this.scalarBytes.length,
        'scalarBytes.length',
        'X25519 private key must be ${x25519_impl.ScalarSize} bytes',
      );
    }
  }

  X25519KeyPair asKeyPair() => X25519KeyPair.fromPrivateKey(this);

  @override
  SecretBytes deriveSharedSecret(OkpKeyAgreementParams params) {
    return switch (params) {
      X25519KeyAgreementParams() => X25519KeyAgreement(
        this,
      ).deriveSharedSecret(params),
    };
  }

  @override
  int get hashCode => Object.hashAll(scalarBytes);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is X25519PrivateKey &&
          const ListEquality<int>().equals(other.scalarBytes, scalarBytes));
}

/// X25519 key agreement key pair (RFC 7748).
class X25519KeyPair extends KeyPair<X25519PublicKey, X25519PrivateKey> {
  X25519KeyPair({required super.publicKey, required super.privateKey});

  /// Random key pair (clamped scalar, standard base point).
  factory X25519KeyPair.generate() {
    final raw = x25519_impl.generateKeyPair();
    return X25519KeyPair(
      publicKey: X25519PublicKey(
        uCoordinate: Uint8List.fromList(raw.publicKey),
      ),
      privateKey: X25519PrivateKey(
        scalarBytes: Uint8List.fromList(raw.privateKey),
      ),
    );
  }

  /// Builds a pair from a 32-byte scalar
  factory X25519KeyPair.fromPrivateKeyBytes(Uint8List privateScalar) {
    final scalar = Uint8List.fromList(privateScalar);
    final derived = x25519_impl.X25519(scalar, x25519_impl.basePoint);
    return X25519KeyPair(
      publicKey: X25519PublicKey(uCoordinate: derived),
      privateKey: X25519PrivateKey(scalarBytes: scalar),
    );
  }

  factory X25519KeyPair.fromPrivateKey(X25519PrivateKey privateKey) =>
      X25519KeyPair.fromPrivateKeyBytes(privateKey.scalarBytes);
}
