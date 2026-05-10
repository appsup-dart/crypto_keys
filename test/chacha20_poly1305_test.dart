import 'dart:typed_data';

import 'package:crypto_keys/catalog.dart';
import 'package:crypto_keys/crypto_keys.dart';
import 'package:test/test.dart';

/// RFC 8439 / RFC 7539 AEAD test vector (same as PointyCastle upstream test).
/// See https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8.2
Uint8List _h(String hex) => Uint8List.fromList(
  List.generate(
    hex.length ~/ 2,
    (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16),
  ),
);

void main() {
  group('ChaCha20-Poly1305', () {
    test('RFC 8439 §2.8.2 vector encrypt then decrypt', () {
      final key = _h(
        '808182838485868788898a8b8c8d8e8f'
        '909192939495969798999a9b9c9d9e9f',
      );
      final nonce = _h('070000004041424344454647');
      final aad = _h('50515253c0c1c2c3c4c5c6c7');
      final plaintext = _h(
        '4c616469657320616e642047656e746c656d656e206f66207468652063'
        '6c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6'
        'c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20'
        '776f756c642062652069742e',
      );
      final expectedCt = _h(
        'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a73'
        '6ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692'
        'ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4'
        'b7a9de576d26586cec64b6116',
      );
      final expectedTag = _h('1ae10b594f09e26a7e902ecbd0600691');

      final sk = SymmetricKey(keyValue: key);
      final alg = algorithms.encryption.chacha20.poly1305;
      final enc = sk.createEncrypter(alg);
      final dec = sk.createDecrypter(alg);

      final out = enc.encrypt(
        plaintext,
        initializationVector: nonce,
        additionalAuthenticatedData: aad,
      );
      expect(out.initializationVector, nonce);
      expect(out.data, expectedCt);
      expect(out.authenticationTag, expectedTag);

      final round = dec.decrypt(
        EncryptionResult(
          out.data,
          initializationVector: nonce,
          additionalAuthenticatedData: aad,
          authenticationTag: out.authenticationTag,
        ),
      );
      expect(round, plaintext);
    });
  });
}
