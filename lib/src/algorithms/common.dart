part of '../algorithms.dart';

/// Supported elliptic curves for EC keys (JWK `crv`, Web Crypto naming).
enum Curve {
  /// NIST P-256 (`secp256r1`).
  p256,

  /// NIST P-384 (`secp384r1`).
  p384,

  /// NIST P-521 (`secp521r1`).
  p521,

  /// SEC G `secp256k1` (`P-256K` / `SEC1`/`JWK`).
  p256k,
}

/// Marker for a concrete **cryptographic algorithm** plus its fixed parameters.
///
/// **Sealed** so subtrees (`SigningAlgorithm`, …) allow **exhaustive** `switch`es;
/// subclasses act as immutable value identifiers (`@immutable`).
@immutable
sealed class Algorithm {
  const Algorithm();
}
