part of '../algorithms.dart';

/// An identifier for uniquely identify algorithms and other objects
class Identifier {
  final String name;

  const Identifier(this.name);
  const Identifier._(this.name);

  @override
  int get hashCode => name.hashCode;

  @override
  bool operator ==(other) => other is Identifier && other.name == name;
}

/// Identifier for an elliptic-curve domain.
class CurveIdentifier extends Identifier {
  const CurveIdentifier._(super.name) : super._();

  /// NIST P-256 (`secp256r1`).
  static const CurveIdentifier p256 = ._('curve/P-256');

  /// NIST P-384 (`secp384r1`).
  static const CurveIdentifier p384 = ._('curve/P-384');

  /// NIST P-521 (`secp521r1`).
  static const CurveIdentifier p521 = ._('curve/P-521');

  /// SEC P-256K (`secp256k1`).
  static const CurveIdentifier p256k = ._('curve/P-256K');
}

/// Identifier for a concrete cryptographic algorithm instance.
///
/// This type is used across signing, encryption, digest, and derivation APIs
/// and provides the stable public identifier name for an algorithm.
class AlgorithmIdentifier extends Identifier {
  final pc.Algorithm Function() _factory;

  const AlgorithmIdentifier._(super.name, this._factory) : super._();
}

/// Internal helpers to instantiate algorithm implementations.
extension AlgorithmIdentifierInternal on AlgorithmIdentifier {
  pc.Algorithm createAlgorithm() => _factory();
}
