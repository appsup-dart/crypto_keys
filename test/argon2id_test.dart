import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart';
import 'package:crypto_keys/src/catalog.dart';
import 'package:test/test.dart';

Uint8List _h(String hex) => .fromList(
  .generate(
    hex.length ~/ 2,
    (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16),
  ),
);

void main() {
  group('Argon2id', () {
    test(
      'RFC 9106-style vector (PointyCastle Argon2id v1.3, t=2, m=256 KiB)',
      () {
        // Same parameters as PointyCastle Argon2 VM test #8, but Argon2id instead
        // of Argon2i; expected output verified against PointyCastle locally.
        final expected = _h(
          '9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe',
        );
        final pwd = Password.fromString('password');
        final out = pwd.deriveBits(
          .argon2id(
            salt: .fromList(utf8.encode('somesalt')),
            iterations: 2,
            keyBitLength: 256,
            memoryKiB: 256,
            lanes: 1,
          ),
        );
        expect(out, expected);
      },
    );

    test('algorithm-first deriveBits matches Password.deriveBits', () {
      final pwd = Password.fromString('password');
      final salt = Uint8List.fromList(utf8.encode('somesalt'));
      final viaPassword = pwd.deriveBits(
        .argon2id(
          salt: salt,
          iterations: 2,
          keyBitLength: 256,
          memoryKiB: 256,
          lanes: 1,
        ),
      );
      final viaAlgorithm = algorithms.kdf.password.argon2id.deriveBits(
        pwd,
        salt: salt,
        iterations: 2,
        keyBitLength: 256,
        memoryKiB: 256,
        lanes: 1,
      );
      expect(viaAlgorithm, viaPassword);
    });
  });
}
