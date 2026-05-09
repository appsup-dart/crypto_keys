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

/// Marker type for a concrete cryptographic algorithm instance.
///
/// Subtypes carry the algorithm family and parameters; identity is defined by
/// type and fields (`==` / `hashCode`), not a path string.
sealed class Algorithm {
  const Algorithm();
}
