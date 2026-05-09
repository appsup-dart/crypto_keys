import 'algorithms.dart';
import 'package:pointycastle/export.dart' as pc;

extension DigestAlgorithmIdentifierPointyCastle on DigestAlgorithmIdentifier {
  /// PointyCastle digest implementation for this identifier.
  pc.Digest get algorithmImplementation => switch (this) {
    _ when this == .sha1 => pc.SHA1Digest(),
    _ when this == .sha224 => pc.SHA224Digest(),
    _ when this == .sha256 => pc.SHA256Digest(),
    _ when this == .sha384 => pc.SHA384Digest(),
    _ when this == .sha512 => pc.SHA512Digest(),
    _ when this == .sha3_224 => pc.SHA3Digest(224),
    _ when this == .sha3_256 => pc.SHA3Digest(256),
    _ when this == .sha3_384 => pc.SHA3Digest(384),
    _ when this == .sha3_512 => pc.SHA3Digest(512),
    _ when name.startsWith('digest/SHA-512/') => pc.SHA512tDigest(
      int.parse(name.split('/').last) ~/ 8,
    ),
    _ => throw UnsupportedError('Unsupported digest identifier: $name'),
  };

  /// Digest block length (in bytes), as defined by the underlying PointyCastle
  /// [pc.Digest] ([pc.Digest.byteLength], used by RFC 2104 HMAC).
  int get blockLength => algorithmImplementation.byteLength;
}

extension DigestAlgorithmIdentifierPkcs1 on DigestAlgorithmIdentifier {
  /// DER-encoded `AlgorithmIdentifier` (tag `0x06` OID only) for RSA PKCS#1
  /// v1.5 `DigestInfo`, in hex, as consumed by PointyCastle [pc.RSASigner].
  ///
  /// Includes SHA-2, SHA-3 (NIST hash OIDs under `2.16.840.1.101.3.4.2`), and
  /// NIST SHA-512/224 and SHA-512/256 (same arc, `.5` and `.6`). Other
  /// [DigestAlgorithmIdentifier.sha512t] sizes have no widely registered PKCS#1
  /// OIDs here and throw.
  ///
  /// Encoding follows PointyCastle: a NULL `parameters` field is written after
  /// this OID in the `DigestInfo` sequence (see [pc.RSASigner]).
  String get rsaPkcs1DigestIdentifierHex => switch (this) {
    _ when this == .sha1 => '06052b0e03021a',
    _ when this == .sha224 => '0609608648016503040204',
    _ when this == .sha256 => '0609608648016503040201',
    _ when this == .sha384 => '0609608648016503040202',
    _ when this == .sha512 => '0609608648016503040203',
    _ when this == .sha3_224 => '0609608648016503040207',
    _ when this == .sha3_256 => '0609608648016503040208',
    _ when this == .sha3_384 => '0609608648016503040209',
    _ when this == .sha3_512 => '060960864801650304020a',
    _ when name == 'digest/SHA-512/224' => '0609608648016503040205',
    _ when name == 'digest/SHA-512/256' => '0609608648016503040206',
    _ => throw UnsupportedError(
      'RSA PKCS#1 v1.5 has no registered DigestInfo OID mapping for $name',
    ),
  };
}
