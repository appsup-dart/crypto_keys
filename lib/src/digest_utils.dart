import 'package:pointycastle/export.dart' as pc;

import 'algorithms.dart';

extension DigestAlgorithmPointyCastle on DigestAlgorithm {
  /// PointyCastle digest implementation for this algorithm.
  pc.Digest get algorithmImplementation => switch (this) {
    DigestSha1() => pc.SHA1Digest(),
    DigestSha2(:final digestSizeBytes) when digestSizeBytes != null =>
      pc.SHA512tDigest(digestSizeBytes),
    DigestSha2(outputLength: Sha2OutputLength.bits224) => pc.SHA224Digest(),
    DigestSha2(outputLength: Sha2OutputLength.bits256) => pc.SHA256Digest(),
    DigestSha2(outputLength: Sha2OutputLength.bits384) => pc.SHA384Digest(),
    DigestSha2(outputLength: Sha2OutputLength.bits512) => pc.SHA512Digest(),
    DigestSha3(:final outputLength) => pc.SHA3Digest(outputLength.bits),
  };

  /// Digest block length (in bytes), as defined by the underlying PointyCastle
  /// [pc.Digest] ([pc.Digest.byteLength], used by RFC 2104 HMAC).
  int get blockLength => algorithmImplementation.byteLength;
}

extension DigestAlgorithmPkcs1 on DigestAlgorithm {
  /// DER-encoded digest algorithm OID (ASN.1 tag `0x06` only) for RSA PKCS#1
  /// v1.5 `DigestInfo`, in hex, as consumed by PointyCastle [pc.RSASigner].
  ///
  /// Includes SHA-2, SHA-3 (NIST hash OIDs under `2.16.840.1.101.3.4.2`), and
  /// NIST SHA-512/224 and SHA-512/256 (same arc, `.5` and `.6`). Other
  /// [DigestAlgorithm.sha512t] sizes have no widely registered PKCS#1
  /// OIDs here and throw.
  ///
  /// Encoding follows PointyCastle: a NULL `parameters` field is written after
  /// this OID in the `DigestInfo` sequence (see [pc.RSASigner]).
  String get rsaPkcs1DigestIdentifierHex => switch (this) {
    DigestSha1() => '06052b0e03021a',
    DigestSha2(outputLength: Sha2OutputLength.bits224) => '0609608648016503040204',
    DigestSha2(outputLength: Sha2OutputLength.bits256) => '0609608648016503040201',
    DigestSha2(outputLength: Sha2OutputLength.bits384) => '0609608648016503040202',
    DigestSha2(outputLength: Sha2OutputLength.bits512, digestSizeBytes: null) =>
      '0609608648016503040203',
    DigestSha2(digestSizeBytes: 28) => '0609608648016503040205',
    DigestSha2(digestSizeBytes: 32) => '0609608648016503040206',
    DigestSha3(outputLength: Sha3OutputLength.bits224) => '0609608648016503040207',
    DigestSha3(outputLength: Sha3OutputLength.bits256) => '0609608648016503040208',
    DigestSha3(outputLength: Sha3OutputLength.bits384) => '0609608648016503040209',
    DigestSha3(outputLength: Sha3OutputLength.bits512) => '060960864801650304020a',
    final d => throw UnsupportedError(
      'RSA PKCS#1 v1.5 has no registered DigestInfo OID mapping for ${d.name}',
    ),
  };
}
