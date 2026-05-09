part of '../catalog.dart';

/// Top-level catalog grouping for all supported algorithm families.
class Algorithms {
  /// Signing algorithms
  final signing = const SigningAlgorithms._();

  /// Encryption algorithms
  final encryption = const EncryptionAlgorithms._();

  /// Digest / hash algorithms
  final digest = const DigestAlgorithms();

  /// Key derivation / agreement algorithms
  final derivation = const DerivationAlgorithms._();

  const Algorithms._();
}

/// Top-level algorithm catalog
const algorithms = Algorithms._();

/// Supported elliptic curves
const curves = Curves._();

/// Browsable catalog of supported elliptic curves.
class Curves {
  const Curves._();

  /// P-256
  final p256 = Curve.p256;

  /// P-384
  final p384 = Curve.p384;

  /// P-521
  final p521 = Curve.p521;

  /// P-256K
  final p256k = Curve.p256k;
}
