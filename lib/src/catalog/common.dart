part of '../catalog.dart';

/// Top-level catalog grouping for all supported algorithm families.
class Algorithms {
  /// Contains the identifiers for supported signing algorithms
  final signing = const SigningAlgorithms._();

  /// Contains the identifiers for supported encryption algorithms
  final encryption = const EncryptionAlgorithms._();

  /// Contains the identifiers for supported digest algorithms
  final digest = const DigestAlgorithms();

  /// Contains the identifiers for supported key derivation algorithms
  final derivation = const DerivationAlgorithms._();

  const Algorithms._();
}

/// Contains the identifiers for supported cryptographic algorithms
const algorithms = Algorithms._();

/// Contains the identifiers for supported cryptographic curves
const curves = Curves._();

/// Browsable catalog of supported elliptic curves.
class Curves {
  const Curves._();

  /// P-256
  final p256 = CurveIdentifier.p256;

  /// P-384
  final p384 = CurveIdentifier.p384;

  /// P-521
  final p521 = CurveIdentifier.p521;

  /// P-256K
  final p256k = CurveIdentifier.p256k;
}
