part of '../../algorithms.dart';

final class HmacSigningAlgorithm extends SymmetricSigningAlgorithm {
  final DigestAlgorithm hash;

  const HmacSigningAlgorithm(this.hash) : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is HmacSigningAlgorithm && hash == other.hash;

  @override
  int get hashCode => Object.hash(10, hash);
}

final class RsaPkcs1SigningAlgorithm extends RsaSigningAlgorithm {
  final DigestAlgorithm hash;

  const RsaPkcs1SigningAlgorithm(this.hash) : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is RsaPkcs1SigningAlgorithm && hash == other.hash;

  @override
  int get hashCode => Object.hash(11, hash);
}

final class RsaPssSigningAlgorithm extends RsaSigningAlgorithm {
  final DigestAlgorithm sigHash;
  final DigestAlgorithm mgf1Hash;
  final int saltLength;

  const RsaPssSigningAlgorithm({
    required this.sigHash,
    required this.mgf1Hash,
    required this.saltLength,
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is RsaPssSigningAlgorithm &&
          sigHash == other.sigHash &&
          mgf1Hash == other.mgf1Hash &&
          saltLength == other.saltLength;

  @override
  int get hashCode => Object.hash(sigHash, mgf1Hash, saltLength);
}

final class EcdsaSigningAlgorithm extends EcSigningAlgorithm {
  final DigestAlgorithm hash;

  const EcdsaSigningAlgorithm(this.hash) : super();

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is EcdsaSigningAlgorithm && hash == other.hash;

  @override
  int get hashCode => Object.hash(12, hash);
}

final class Ed25519SigningAlgorithmImpl extends Ed25519SigningAlgorithm {
  const Ed25519SigningAlgorithmImpl() : super();
}
