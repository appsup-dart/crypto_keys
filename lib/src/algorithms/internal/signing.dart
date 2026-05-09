part of '../../algorithms.dart';

class HmacSigningAlgorithmIdentifier extends SymmetricSigningAlgorithmIdentifier {
  final DigestAlgorithmIdentifier hash;

  HmacSigningAlgorithmIdentifier(this.hash) : super._('sig/HMAC/${hash.nameSuffix}');
}

class RsaPkcs1SigningAlgorithmIdentifier extends RsaSigningAlgorithmIdentifier {
  final DigestAlgorithmIdentifier hash;

  RsaPkcs1SigningAlgorithmIdentifier(this.hash)
    : super._('sig/RSA/${hash.nameSuffix}');
}

class RsaPssSigningAlgorithmIdentifier extends RsaSigningAlgorithmIdentifier {
  final DigestAlgorithmIdentifier sigHash;
  final DigestAlgorithmIdentifier mgf1Hash;
  final int saltLength;

  RsaPssSigningAlgorithmIdentifier(
    this.sigHash, {
    DigestAlgorithmIdentifier? mgf1Hash,
    int? saltLength,
  }) : mgf1Hash = _resolveMgf1(sigHash, mgf1Hash),
       saltLength = _resolveSaltLength(sigHash, saltLength),
       super._(_buildName(sigHash, mgf1Hash, saltLength));

  static DigestAlgorithmIdentifier _resolveMgf1(
    DigestAlgorithmIdentifier sigHash,
    DigestAlgorithmIdentifier? mgf1Hash,
  ) => mgf1Hash ?? sigHash;

  static int _resolveSaltLength(
    DigestAlgorithmIdentifier sigHash,
    int? saltLength,
  ) => saltLength ?? sigHash.algorithmImplementation.digestSize;

  static String _buildName(
    DigestAlgorithmIdentifier sigHash,
    DigestAlgorithmIdentifier? mgf1Hash,
    int? saltLength,
  ) {
    final resolvedMgf1 = _resolveMgf1(sigHash, mgf1Hash);
    final resolvedSaltLength = _resolveSaltLength(sigHash, saltLength);
    return 'sig/RSA/PSS/${sigHash.name}/mgf1${resolvedMgf1.name}/$resolvedSaltLength';
  }
}

class EcdsaSigningAlgorithmIdentifier extends EcSigningAlgorithmIdentifier {
  final DigestAlgorithmIdentifier hash;

  EcdsaSigningAlgorithmIdentifier(this.hash)
    : super._('sig/ECDSA/${hash.nameSuffix}');
}

class Ed25519SigningAlgorithmIdentifierImpl extends Ed25519SigningAlgorithmIdentifier {
  const Ed25519SigningAlgorithmIdentifierImpl() : super._('sig/Ed25519');
}
