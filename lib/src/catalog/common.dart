part of '../catalog.dart';

/// Nested grouping for every supported cryptographic primitive family.
///
/// Accessed via the top-level **`algorithms`** constant (typed [Algorithms]).
class Algorithms {
  /// Signing algorithms
  final signing = const SigningAlgorithms._();

  /// Encryption algorithms
  final encryption = const EncryptionAlgorithms._();

  /// Digest / hash algorithms
  final digest = const DigestAlgorithms();

  /// Key-derivation algorithms ([Password]/[SecretBytes].deriveBits).
  final kdf = const KdfAlgorithms._();

  /// Key agreement ([AgreementPrivateKey.deriveSharedSecret]).
  final keyAgreement = const KeyAgreementAlgorithms._();

  const Algorithms._();
}

/// Browsable **`algorithms.*`** entry points (`algorithms.signing.hmac.sha256`, …).
const algorithms = Algorithms._();
