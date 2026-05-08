part of '../algorithms.dart';

class DerivationAlgorithms extends Identifier {
  /// ECDH shared-secret derivation.
  // Internal note: PointyCastle's ECDH agreement is not a pc.Algorithm,
  // so this identifier uses a placeholder factory and is handled specially
  // by the ECDH deriver implementation.
  final ecdh = DerivationAlgorithmIdentifier._(
    'derive/ECDH',
    () => pc.SHA256Digest(),
  );

  /// Contains the identifiers for supported Concat KDF algorithms
  final concatKdf = _ConcatKdfAlgorithms();

  /// Contains the identifiers for supported PBKDF2 algorithms.
  final pbkdf2 = _Pbkdf2Algorithms();

  /// Contains the identifiers for supported HKDF algorithms.
  final hkdf = _HkdfAlgorithms();

  DerivationAlgorithms() : super._('derive');
}

class _ConcatKdfAlgorithms extends Identifier {
  /// Concat KDF using SHA-256
  final sha256 = DerivationAlgorithmIdentifier._(
    'derive/ConcatKDF/SHA-256',
    () => pc.SHA256Digest(),
  );

  /// Concat KDF using SHA-384
  final sha384 = DerivationAlgorithmIdentifier._(
    'derive/ConcatKDF/SHA-384',
    () => pc.SHA384Digest(),
  );

  /// Concat KDF using SHA-512
  final sha512 = DerivationAlgorithmIdentifier._(
    'derive/ConcatKDF/SHA-512',
    () => pc.SHA512Digest(),
  );

  _ConcatKdfAlgorithms() : super._('derive/ConcatKDF');
}

class _Pbkdf2Algorithms extends Identifier {
  /// PBKDF2 using HMAC-SHA-1
  final sha1 = DerivationAlgorithmIdentifier._(
    'derive/PBKDF2/SHA-1',
    () => pc.PBKDF2KeyDerivator(pc.HMac(pc.SHA1Digest(), 64)),
  );

  /// PBKDF2 using HMAC-SHA-256
  final sha256 = DerivationAlgorithmIdentifier._(
    'derive/PBKDF2/SHA-256',
    () => pc.PBKDF2KeyDerivator(pc.HMac(pc.SHA256Digest(), 64)),
  );

  /// PBKDF2 using HMAC-SHA-384
  final sha384 = DerivationAlgorithmIdentifier._(
    'derive/PBKDF2/SHA-384',
    () => pc.PBKDF2KeyDerivator(pc.HMac(pc.SHA384Digest(), 128)),
  );

  /// PBKDF2 using HMAC-SHA-512
  final sha512 = DerivationAlgorithmIdentifier._(
    'derive/PBKDF2/SHA-512',
    () => pc.PBKDF2KeyDerivator(pc.HMac(pc.SHA512Digest(), 128)),
  );

  _Pbkdf2Algorithms() : super._('derive/PBKDF2');
}

class _HkdfAlgorithms extends Identifier {
  /// HKDF using SHA-256
  final sha256 = DerivationAlgorithmIdentifier._(
    'derive/HKDF/SHA-256',
    () => pc.HKDFKeyDerivator(pc.SHA256Digest()),
  );

  /// HKDF using SHA-384
  final sha384 = DerivationAlgorithmIdentifier._(
    'derive/HKDF/SHA-384',
    () => pc.HKDFKeyDerivator(pc.SHA384Digest()),
  );

  /// HKDF using SHA-512
  final sha512 = DerivationAlgorithmIdentifier._(
    'derive/HKDF/SHA-512',
    () => pc.HKDFKeyDerivator(pc.SHA512Digest()),
  );

  _HkdfAlgorithms() : super._('derive/HKDF');
}

class DerivationAlgorithmIdentifier extends AlgorithmIdentifier {
  DerivationAlgorithmIdentifier._(super.name, super.factory) : super._();
}
