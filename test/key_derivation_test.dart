import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart';
import 'package:test/test.dart';

void main() {
  group('KeyDeriver operator', () {
    test('both parties derive identical key material', () {
      final a = KeyPair.generateEc(curves.p256);
      final b = KeyPair.generateEc(curves.p256);
      final ecdhAlg = algorithms.derivation.ecdh;
      final kdfAlg = algorithms.derivation.concatKdf.sha256;

      final aDeriver = a.createKeyDeriver(ecdhAlg);
      final bDeriver = b.createKeyDeriver(ecdhAlg);
      final otherInfo = _buildOtherInfo(
        algorithmId: Uint8List.fromList('key-agreement'.codeUnits),
        partyUInfo: Uint8List.fromList([1, 2, 3]),
        partyVInfo: Uint8List.fromList([4, 5, 6]),
        keyBitLength: 256,
      );

      final aZ = aDeriver
          .deriveKey(KeyDeriverParams.ecdh(peerPublicKey: b.publicKey!));
      final bZ = bDeriver
          .deriveKey(KeyDeriverParams.ecdh(peerPublicKey: a.publicKey!));

      final aKey = SecretBytes(aZ).createKeyDeriver(kdfAlg).deriveKey(
          KeyDeriverParams.concatKdf(keyBitLength: 256, otherInfo: otherInfo));
      final bKey = SecretBytes(bZ).createKeyDeriver(kdfAlg).deriveKey(
          KeyDeriverParams.concatKdf(keyBitLength: 256, otherInfo: otherInfo));

      expect(aKey, bKey);
    });

    test('curve mismatch throws', () {
      final a = KeyPair.generateEc(curves.p256);
      final b = KeyPair.generateEc(curves.p384);
      final deriver = a.createKeyDeriver(algorithms.derivation.ecdh);

      expect(
        () => deriver
            .deriveKey(KeyDeriverParams.ecdh(peerPublicKey: b.publicKey!)),
        throwsArgumentError,
      );
    });

    test('derivation is deterministic and parameter-sensitive', () {
      final a = KeyPair.generateEc(curves.p384);
      final b = KeyPair.generateEc(curves.p384);
      final deriver = a.createKeyDeriver(algorithms.derivation.ecdh);
      final kdfAlg = algorithms.derivation.concatKdf.sha256;

      final baseInfo = _buildOtherInfo(
        algorithmId: Uint8List.fromList('kdf-a'.codeUnits),
        partyUInfo: Uint8List.fromList([1]),
        partyVInfo: Uint8List.fromList([2]),
        keyBitLength: 256,
      );
      final z =
          deriver.deriveKey(KeyDeriverParams.ecdh(peerPublicKey: b.publicKey!));
      final kdfDeriver = SecretBytes(z).createKeyDeriver(kdfAlg);
      final key1 = kdfDeriver.deriveKey(
          KeyDeriverParams.concatKdf(keyBitLength: 256, otherInfo: baseInfo));
      final key2 = kdfDeriver.deriveKey(
          KeyDeriverParams.concatKdf(keyBitLength: 256, otherInfo: baseInfo));
      expect(key1, key2);

      final differentAlg = kdfDeriver.deriveKey(KeyDeriverParams.concatKdf(
          keyBitLength: 256,
          otherInfo: _buildOtherInfo(
              algorithmId: Uint8List.fromList('kdf-b'.codeUnits),
              partyUInfo: Uint8List.fromList([1]),
              partyVInfo: Uint8List.fromList([2]),
              keyBitLength: 256)));
      final differentU = kdfDeriver.deriveKey(KeyDeriverParams.concatKdf(
          keyBitLength: 256,
          otherInfo: _buildOtherInfo(
              algorithmId: Uint8List.fromList('kdf-a'.codeUnits),
              partyUInfo: Uint8List.fromList([9]),
              partyVInfo: Uint8List.fromList([2]),
              keyBitLength: 256)));
      final differentV = kdfDeriver.deriveKey(KeyDeriverParams.concatKdf(
          keyBitLength: 256,
          otherInfo: _buildOtherInfo(
              algorithmId: Uint8List.fromList('kdf-a'.codeUnits),
              partyUInfo: Uint8List.fromList([1]),
              partyVInfo: Uint8List.fromList([9]),
              keyBitLength: 256)));

      expect(differentAlg, isNot(key1));
      expect(differentU, isNot(key1));
      expect(differentV, isNot(key1));
    });

    test('derived key length equals requested bit length', () {
      final a = KeyPair.generateEc(curves.p521);
      final b = KeyPair.generateEc(curves.p521);
      final deriver = a.createKeyDeriver(algorithms.derivation.ecdh);
      final kdfAlg = algorithms.derivation.concatKdf.sha512;

      final z =
          deriver.deriveKey(KeyDeriverParams.ecdh(peerPublicKey: b.publicKey!));
      final key = SecretBytes(z)
          .createKeyDeriver(kdfAlg)
          .deriveKey(KeyDeriverParams.concatKdf(keyBitLength: 384));
      expect(key.length, 48);
    });
  });

  group('PasswordKeyDeriver operator', () {
    test('matches RFC 6070 PBKDF2-HMAC-SHA1 vectors', () {
      // RFC 6070, section 2:
      // https://www.rfc-editor.org/rfc/rfc6070#section-2
      final deriver = Password.fromString('password')
          .createKeyDeriver(algorithms.derivation.pbkdf2.sha1);

      final dk1 = deriver.deriveKey(KeyDeriverParams.pbkdf2(
          salt: Uint8List.fromList('salt'.codeUnits),
          iterations: 1,
          keyBitLength: 20 * 8));
      expect(dk1, _hexToBytes('0c60c80f961f0e71f3a9b524af6012062fe037a6'));

      final dk2 = deriver.deriveKey(KeyDeriverParams.pbkdf2(
          salt: Uint8List.fromList('salt'.codeUnits),
          iterations: 2,
          keyBitLength: 20 * 8));
      expect(dk2, _hexToBytes('ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'));

      final dk3 = deriver.deriveKey(KeyDeriverParams.pbkdf2(
          salt: Uint8List.fromList('salt'.codeUnits),
          iterations: 4096,
          keyBitLength: 20 * 8));
      expect(dk3, _hexToBytes('4b007901b765489abead49d926f721d065a429c1'));
    });

    test('matches known PBKDF2-HMAC-SHA256 test vector', () {
      final deriver = Password.fromString('password').createKeyDeriver(
        algorithms.derivation.pbkdf2.sha256,
      );

      final key = deriver.deriveKey(KeyDeriverParams.pbkdf2(
        salt: Uint8List.fromList('salt'.codeUnits),
        iterations: 1,
        keyBitLength: 256,
      ));

      expect(
          key,
          _hexToBytes(
              '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b'));
    });

    test('derivation is deterministic and parameter-sensitive', () {
      final deriver = Password.fromString('correct horse battery staple')
          .createKeyDeriver(algorithms.derivation.pbkdf2.sha512);
      final salt = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);

      final key1 = deriver.deriveKey(KeyDeriverParams.pbkdf2(
          salt: salt, iterations: 1000, keyBitLength: 256));
      final key2 = deriver.deriveKey(KeyDeriverParams.pbkdf2(
          salt: salt, iterations: 1000, keyBitLength: 256));
      final differentSalt = deriver.deriveKey(KeyDeriverParams.pbkdf2(
          salt: Uint8List.fromList([9, 2, 3, 4, 5, 6, 7, 8]),
          iterations: 1000,
          keyBitLength: 256));
      final differentIterations = deriver.deriveKey(KeyDeriverParams.pbkdf2(
          salt: salt, iterations: 2000, keyBitLength: 256));

      expect(key1, key2);
      expect(differentSalt, isNot(key1));
      expect(differentIterations, isNot(key1));
    });

    test('invalid parameters throw', () {
      final deriver = Password.fromString('pw')
          .createKeyDeriver(algorithms.derivation.pbkdf2.sha256);

      expect(
          () => deriver.deriveKey(KeyDeriverParams.pbkdf2(
              salt: Uint8List(0), iterations: 1000, keyBitLength: 128)),
          throwsArgumentError);
      expect(
          () => deriver.deriveKey(KeyDeriverParams.pbkdf2(
              salt: Uint8List.fromList([1]), iterations: 0, keyBitLength: 128)),
          throwsArgumentError);
      expect(
          () => deriver.deriveKey(KeyDeriverParams.pbkdf2(
              salt: Uint8List.fromList([1]),
              iterations: 1000,
              keyBitLength: 0)),
          throwsArgumentError);
    });
  });

  group('SecretBytes HKDF operator', () {
    test('matches RFC 5869 HKDF-SHA256 test vector case 1', () {
      // RFC 5869, appendix A.1:
      // https://www.rfc-editor.org/rfc/rfc5869#appendix-A.1
      final ikm = Uint8List.fromList(List.filled(22, 0x0b));
      final deriver =
          SecretBytes(ikm).createKeyDeriver(algorithms.derivation.hkdf.sha256);

      final okm = deriver.deriveKey(KeyDeriverParams.hkdf(
        salt: _hexToBytes('000102030405060708090a0b0c'),
        info: _hexToBytes('f0f1f2f3f4f5f6f7f8f9'),
        keyBitLength: 42 * 8,
      ));

      expect(
        okm,
        _hexToBytes(
            '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'),
      );
    });

    test('derivation is deterministic and parameter-sensitive', () {
      final deriver =
          SecretBytes(_hexToBytes('00112233445566778899aabbccddeeff'))
              .createKeyDeriver(algorithms.derivation.hkdf.sha512);

      final key1 = deriver.deriveKey(KeyDeriverParams.hkdf(
          salt: Uint8List.fromList([1, 2, 3]),
          info: Uint8List.fromList([9, 8, 7]),
          keyBitLength: 256));
      final key2 = deriver.deriveKey(KeyDeriverParams.hkdf(
          salt: Uint8List.fromList([1, 2, 3]),
          info: Uint8List.fromList([9, 8, 7]),
          keyBitLength: 256));
      final differentInfo = deriver.deriveKey(KeyDeriverParams.hkdf(
          salt: Uint8List.fromList([1, 2, 3]),
          info: Uint8List.fromList([9, 8, 6]),
          keyBitLength: 256));
      final differentSalt = deriver.deriveKey(KeyDeriverParams.hkdf(
          salt: Uint8List.fromList([3, 2, 1]),
          info: Uint8List.fromList([9, 8, 7]),
          keyBitLength: 256));

      expect(key1, key2);
      expect(differentInfo, isNot(key1));
      expect(differentSalt, isNot(key1));
    });

    test('invalid parameters throw', () {
      final deriver = SecretBytes([1, 2, 3])
          .createKeyDeriver(algorithms.derivation.hkdf.sha256);
      expect(
          () => deriver.deriveKey(
              KeyDeriverParams.hkdf(salt: Uint8List(0), keyBitLength: 0)),
          throwsArgumentError);

      final emptySecretDeriver =
          SecretBytes([]).createKeyDeriver(algorithms.derivation.hkdf.sha256);
      expect(
          () => emptySecretDeriver.deriveKey(
              KeyDeriverParams.hkdf(salt: Uint8List(0), keyBitLength: 128)),
          throwsArgumentError);
    });
  });
}

Uint8List _buildOtherInfo(
    {required Uint8List algorithmId,
    Uint8List? partyUInfo,
    Uint8List? partyVInfo,
    required int keyBitLength,
    Uint8List? suppPrivInfo}) {
  partyUInfo ??= Uint8List(0);
  partyVInfo ??= Uint8List(0);
  suppPrivInfo ??= Uint8List(0);
  final bytes = <int>[
    ..._len(algorithmId),
    ..._len(partyUInfo),
    ..._len(partyVInfo),
    ..._u32be(keyBitLength),
    ..._len(suppPrivInfo)
  ];
  return Uint8List.fromList(bytes);
}

Uint8List _len(Uint8List v) => Uint8List.fromList([..._u32be(v.length), ...v]);

Uint8List _u32be(int value) {
  final b = Uint8List(4);
  b.buffer.asByteData().setUint32(0, value);
  return b;
}

Uint8List _hexToBytes(String hex) {
  if (hex.length.isOdd) {
    throw ArgumentError.value(hex, 'hex', 'Length must be even');
  }
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
