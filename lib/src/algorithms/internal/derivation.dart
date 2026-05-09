part of '../../algorithms.dart';

final class _ConcatKdfDerivationAlgorithm extends DerivationAlgorithm {
  final DigestAlgorithm hash;

  const _ConcatKdfDerivationAlgorithm(this.hash) : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is _ConcatKdfDerivationAlgorithm && hash == other.hash;

  @override
  int get hashCode => Object.hash(1, hash);
}

final class _Pbkdf2DerivationAlgorithm extends DerivationAlgorithm {
  final DigestAlgorithm hash;

  const _Pbkdf2DerivationAlgorithm(this.hash) : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is _Pbkdf2DerivationAlgorithm && hash == other.hash;

  @override
  int get hashCode => Object.hash(2, hash);
}

final class _HkdfDerivationAlgorithm extends DerivationAlgorithm {
  final DigestAlgorithm hash;

  const _HkdfDerivationAlgorithm(this.hash) : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is _HkdfDerivationAlgorithm && hash == other.hash;

  @override
  int get hashCode => Object.hash(3, hash);
}

final class _EcdhDerivationAlgorithm extends DerivationAlgorithm {
  const _EcdhDerivationAlgorithm() : super();

  @override
  bool operator ==(Object other) => other is _EcdhDerivationAlgorithm;

  @override
  int get hashCode => (_EcdhDerivationAlgorithm).hashCode;
}

final class _X25519DerivationAlgorithm extends DerivationAlgorithm {
  const _X25519DerivationAlgorithm() : super();

  @override
  bool operator ==(Object other) => other is _X25519DerivationAlgorithm;

  @override
  int get hashCode => (_X25519DerivationAlgorithm).hashCode;
}
