import 'dart:typed_data';

import 'package:crypto_keys/src/algorithms.dart';
import 'package:crypto_keys/src/utils/digest.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';

pc.Digest _digest(DigestAlgorithm id) => id.algorithmImplementation;

void main() {
  group('DigestAlgorithm', () {
    test('blockLength matches PointyCastle byteLength', () {
      expect(DigestAlgorithm.sha256.blockLength, 64);
      expect(DigestAlgorithm.sha512.blockLength, 128);
      expect(DigestAlgorithm.sha512t(32).blockLength, 128);
      expect(
        DigestAlgorithm.sha3_256.blockLength,
        _digest(DigestAlgorithm.sha3_256).byteLength,
      );
    });

    test('rsaPkcs1DigestIdentifierHex OID encodings', () {
      expect(
        DigestAlgorithm.sha256.rsaPkcs1DigestIdentifierHex,
        '0609608648016503040201',
      );
      expect(
        DigestAlgorithm.sha3_256.rsaPkcs1DigestIdentifierHex,
        '0609608648016503040208',
      );
      expect(
        DigestAlgorithm.sha512t(28).rsaPkcs1DigestIdentifierHex,
        '0609608648016503040205',
      );
      expect(
        DigestAlgorithm.sha512t(32).rsaPkcs1DigestIdentifierHex,
        '0609608648016503040206',
      );
    });

    test('rsaPkcs1DigestIdentifierHex rejects unsupported SHA-512/t sizes', () {
      expect(
        () => DigestAlgorithm.sha512t(48).rsaPkcs1DigestIdentifierHex,
        throwsUnsupportedError,
      );
    });

    test('SHA-256 empty message', () {
      final out = Uint8List(32);
      _digest(DigestAlgorithm.sha256).doFinal(out, 0);
      expect(out, [
        0xe3,
        0xb0,
        0xc4,
        0x42,
        0x98,
        0xfc,
        0x1c,
        0x14,
        0x9a,
        0xfb,
        0xf4,
        0xc8,
        0x99,
        0x6f,
        0xb9,
        0x24,
        0x27,
        0xae,
        0x41,
        0xe4,
        0x64,
        0x9b,
        0x93,
        0x4c,
        0xa4,
        0x95,
        0x99,
        0x1b,
        0x78,
        0x52,
        0xb8,
        0x55,
      ]);
    });
  });
}
