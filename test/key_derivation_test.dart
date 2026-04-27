import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart';
import 'package:test/test.dart';

void main() {
  group('Key derivation', () {
    test('both parties derive identical key material', () {
      final a = KeyPair.generateEc(curves.p256);
      final b = KeyPair.generateEc(curves.p256);
      final otherInfo = _buildOtherInfo(
        algorithmId: Uint8List.fromList('key-agreement'.codeUnits),
        partyUInfo: Uint8List.fromList([1, 2, 3]),
        partyVInfo: Uint8List.fromList([4, 5, 6]),
        keyBitLength: 256,
      );

      final aZ = (a.privateKey! as EcPrivateKey)
          .deriveSharedSecret(.ecdh(peerPublicKey: b.publicKey! as EcPublicKey))
          .value;
      final bZ = (b.privateKey! as EcPrivateKey)
          .deriveSharedSecret(.ecdh(peerPublicKey: a.publicKey! as EcPublicKey))
          .value;

      final aKey = SecretBytes(aZ).deriveBits(
        .concatKdf(hash: .sha256, keyBitLength: 256, otherInfo: otherInfo),
      );
      final bKey = SecretBytes(bZ).deriveBits(
        .concatKdf(hash: .sha256, keyBitLength: 256, otherInfo: otherInfo),
      );

      expect(aKey, bKey);
    });

    test('curve mismatch throws', () {
      final a = KeyPair.generateEc(curves.p256);
      final b = KeyPair.generateEc(curves.p384);
      expect(
        () => (a.privateKey! as EcPrivateKey).deriveSharedSecret(
          .ecdh(peerPublicKey: b.publicKey! as EcPublicKey),
        ),
        throwsArgumentError,
      );
    });

    test('derived key length equals requested bit length', () {
      final a = KeyPair.generateEc(curves.p521);
      final b = KeyPair.generateEc(curves.p521);
      final z = (a.privateKey! as EcPrivateKey)
          .deriveSharedSecret(.ecdh(peerPublicKey: b.publicKey! as EcPublicKey))
          .value;
      final key = SecretBytes(
        z,
      ).deriveBits(.concatKdf(hash: .sha512, keyBitLength: 384));
      expect(key.length, 48);
    });
  });

  group('Password deriveBits', () {
    test('matches RFC 6070 PBKDF2-HMAC-SHA1 vectors', () {
      // RFC 6070, section 2:
      // https://www.rfc-editor.org/rfc/rfc6070#section-2
      final password = Password.fromString('password');

      final dk1 = password.deriveBits(
        .pbkdf2(
          hash: .sha1,
          salt: Uint8List.fromList('salt'.codeUnits),
          iterations: 1,
          keyBitLength: 20 * 8,
        ),
      );
      expect(dk1, _hexToBytes('0c60c80f961f0e71f3a9b524af6012062fe037a6'));

      final dk2 = password.deriveBits(
        .pbkdf2(
          hash: .sha1,
          salt: Uint8List.fromList('salt'.codeUnits),
          iterations: 2,
          keyBitLength: 20 * 8,
        ),
      );
      expect(dk2, _hexToBytes('ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'));
    });

    test('matches known PBKDF2-HMAC-SHA256 test vector', () {
      final password = Password.fromString('password');

      final key = password.deriveBits(
        .pbkdf2(
          hash: .sha256,
          salt: Uint8List.fromList('salt'.codeUnits),
          iterations: 1,
          keyBitLength: 256,
        ),
      );

      expect(
        key,
        _hexToBytes(
          '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b',
        ),
      );
    });
  });

  group('SecretBytes deriveBits', () {
    test('matches RFC 5869 HKDF-SHA256 test vector case 1', () {
      // RFC 5869, appendix A.1:
      // https://www.rfc-editor.org/rfc/rfc5869#appendix-A.1
      final ikm = Uint8List.fromList(List.filled(22, 0x0b));
      final secret = SecretBytes(ikm);

      final okm = secret.deriveBits(
        .hkdf(
          hash: .sha256,
          salt: _hexToBytes('000102030405060708090a0b0c'),
          info: _hexToBytes('f0f1f2f3f4f5f6f7f8f9'),
          keyBitLength: 42 * 8,
        ),
      );

      expect(
        okm,
        _hexToBytes(
          '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
        ),
      );
    });
  });
}

Uint8List _buildOtherInfo({
  required Uint8List algorithmId,
  Uint8List? partyUInfo,
  Uint8List? partyVInfo,
  required int keyBitLength,
  Uint8List? suppPrivInfo,
}) {
  partyUInfo ??= Uint8List(0);
  partyVInfo ??= Uint8List(0);
  suppPrivInfo ??= Uint8List(0);
  final bytes = <int>[
    ..._len(algorithmId),
    ..._len(partyUInfo),
    ..._len(partyVInfo),
    ..._u32be(keyBitLength),
    ..._len(suppPrivInfo),
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
