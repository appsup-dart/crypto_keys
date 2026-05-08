import 'algorithms.dart';
import 'package:pointycastle/export.dart' as pc;

extension DigestAlgorithmIdentifierHmac on DigestAlgorithmIdentifier {
  /// Digest block length (in bytes), as defined by the underlying PointyCastle
  /// [pc.Digest] ([pc.Digest.byteLength], used by RFC 2104 HMAC).
  int get blockLength {
    final digest = createAlgorithm() as pc.Digest;
    return digest.byteLength;
  }

  String get nameSuffix => name.replaceFirst('digest/', '');

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
