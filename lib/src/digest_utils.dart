import 'algorithms.dart';

extension DigestAlgorithmIdentifierHmac on DigestAlgorithmIdentifier {
  /// Digest block length (in bytes).
  int get blockLength => switch (this) {
    _ when this == .sha1 => 64,
    _ when this == .sha224 => 64,
    _ when this == .sha256 => 64,
    _ when this == .sha384 => 128,
    _ when this == .sha512 => 128,
    // SHA-512/t variants use SHA-512's internal compression block size.
    _ when name.startsWith('digest/SHA-512/') => 128,
    _ => throw UnsupportedError('HMAC does not support digest $name'),
  };

  String get nameSuffix => name.replaceFirst('digest/', '');

  /// DER-encoded AlgorithmIdentifier OID hex for RSA PKCS#1 v1.5 signatures.
  String get rsaPkcs1DigestIdentifierHex => switch (this) {
    _ when this == .sha1 => '06052b0e03021a',
    _ when this == .sha224 => '0609608648016503040204',
    _ when this == .sha256 => '0609608648016503040201',
    _ when this == .sha384 => '0609608648016503040202',
    _ when this == .sha512 => '0609608648016503040203',
    _ => throw UnsupportedError(
      'RSA PKCS#1 does not support digest $name in this library',
    ),
  };
}
