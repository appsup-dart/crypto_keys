part of '../algorithms.dart';

class DigestAlgorithms extends Identifier {
  DigestAlgorithms() : super._('digest');

  /// SHA-1 digest
  DigestAlgorithmIdentifier get sha1 => .sha1;

  /// SHA-224 digest
  DigestAlgorithmIdentifier get sha224 => .sha224;

  /// SHA-256 digest
  DigestAlgorithmIdentifier get sha256 => .sha256;

  /// SHA-384 digest
  DigestAlgorithmIdentifier get sha384 => .sha384;

  /// SHA-512 digest
  DigestAlgorithmIdentifier get sha512 => .sha512;

  /// SHA-512/t digest
  DigestAlgorithmIdentifier sha512t(int digestSizeBytes) =>
      .sha512t(digestSizeBytes);

  /// MD2 digest
  DigestAlgorithmIdentifier get md2 => .md2;

  /// MD4 digest
  DigestAlgorithmIdentifier get md4 => .md4;

  /// MD5 digest
  DigestAlgorithmIdentifier get md5 => .md5;
}

class DigestAlgorithmIdentifier extends AlgorithmIdentifier<pc.Digest> {
  DigestAlgorithmIdentifier._(super.name, super.factory) : super._();

  static final DigestAlgorithmIdentifier sha1 = ._(
    'digest/SHA-1',
    () => pc.SHA1Digest(),
  );
  static final DigestAlgorithmIdentifier sha224 = ._(
    'digest/SHA-224',
    () => pc.SHA224Digest(),
  );
  static final DigestAlgorithmIdentifier sha256 = ._(
    'digest/SHA-256',
    () => pc.SHA256Digest(),
  );
  static final DigestAlgorithmIdentifier sha384 = ._(
    'digest/SHA-384',
    () => pc.SHA384Digest(),
  );
  static final DigestAlgorithmIdentifier sha512 = ._(
    'digest/SHA-512',
    () => pc.SHA512Digest(),
  );
  static final DigestAlgorithmIdentifier md2 = ._(
    'digest/MD2',
    () => pc.MD2Digest(),
  );
  static final DigestAlgorithmIdentifier md4 = ._(
    'digest/MD4',
    () => pc.MD4Digest(),
  );
  static final DigestAlgorithmIdentifier md5 = ._(
    'digest/MD5',
    () => pc.MD5Digest(),
  );

  static DigestAlgorithmIdentifier sha512t(int digestSizeBytes) =>
      DigestAlgorithmIdentifier._(
        'digest/SHA-512/${digestSizeBytes * 8}',
        () => pc.SHA512tDigest(digestSizeBytes),
      );
}
