part of '../../algorithms.dart';

class _ConcatKdfDerivationAlgorithmIdentifier
    extends DerivationAlgorithmIdentifier {
  _ConcatKdfDerivationAlgorithmIdentifier(DigestAlgorithmIdentifier hash)
    : super._('derive/ConcatKDF/${hash.nameSuffix}');
}

class _Pbkdf2DerivationAlgorithmIdentifier extends DerivationAlgorithmIdentifier {
  _Pbkdf2DerivationAlgorithmIdentifier(DigestAlgorithmIdentifier hash)
    : super._('derive/PBKDF2/${hash.nameSuffix}');
}

class _HkdfDerivationAlgorithmIdentifier extends DerivationAlgorithmIdentifier {
  _HkdfDerivationAlgorithmIdentifier(DigestAlgorithmIdentifier hash)
    : super._('derive/HKDF/${hash.nameSuffix}');
}

class _EcdhDerivationAlgorithmIdentifier extends DerivationAlgorithmIdentifier {
  const _EcdhDerivationAlgorithmIdentifier() : super._('derive/ECDH');
}
