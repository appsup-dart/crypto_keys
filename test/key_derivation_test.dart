import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart';
import 'package:test/test.dart';

void main() {
  group('KeyDeriver operator', () {
    test('both parties derive identical key material', () {
      final a = KeyPair.generateEc(curves.p256);
      final b = KeyPair.generateEc(curves.p256);
      final alg = algorithms.derivation.concatKdf.sha256;

      final aDeriver = a.createKeyDeriver(alg);
      final bDeriver = b.createKeyDeriver(alg);
      final otherInfo = _buildOtherInfo(
        algorithmId: Uint8List.fromList('key-agreement'.codeUnits),
        partyUInfo: Uint8List.fromList([1, 2, 3]),
        partyVInfo: Uint8List.fromList([4, 5, 6]),
        keyBitLength: 256,
      );

      final aKey = aDeriver.deriveKey(
          peerPublicKey: b.publicKey!, keyBitLength: 256, otherInfo: otherInfo);
      final bKey = bDeriver.deriveKey(
          peerPublicKey: a.publicKey!, keyBitLength: 256, otherInfo: otherInfo);

      expect(aKey, bKey);
    });

    test('curve mismatch throws', () {
      final a = KeyPair.generateEc(curves.p256);
      final b = KeyPair.generateEc(curves.p384);
      final deriver =
          a.createKeyDeriver(algorithms.derivation.concatKdf.sha256);

      expect(
        () => deriver.deriveKey(peerPublicKey: b.publicKey!, keyBitLength: 256),
        throwsArgumentError,
      );
    });

    test('derivation is deterministic and parameter-sensitive', () {
      final a = KeyPair.generateEc(curves.p384);
      final b = KeyPair.generateEc(curves.p384);
      final deriver =
          a.createKeyDeriver(algorithms.derivation.concatKdf.sha256);

      final baseInfo = _buildOtherInfo(
        algorithmId: Uint8List.fromList('kdf-a'.codeUnits),
        partyUInfo: Uint8List.fromList([1]),
        partyVInfo: Uint8List.fromList([2]),
        keyBitLength: 256,
      );
      final key1 = deriver.deriveKey(
          peerPublicKey: b.publicKey!, keyBitLength: 256, otherInfo: baseInfo);
      final key2 = deriver.deriveKey(
          peerPublicKey: b.publicKey!, keyBitLength: 256, otherInfo: baseInfo);
      expect(key1, key2);

      final differentAlg = deriver.deriveKey(
          peerPublicKey: b.publicKey!,
          keyBitLength: 256,
          otherInfo: _buildOtherInfo(
              algorithmId: Uint8List.fromList('kdf-b'.codeUnits),
              partyUInfo: Uint8List.fromList([1]),
              partyVInfo: Uint8List.fromList([2]),
              keyBitLength: 256));
      final differentU = deriver.deriveKey(
          peerPublicKey: b.publicKey!,
          keyBitLength: 256,
          otherInfo: _buildOtherInfo(
              algorithmId: Uint8List.fromList('kdf-a'.codeUnits),
              partyUInfo: Uint8List.fromList([9]),
              partyVInfo: Uint8List.fromList([2]),
              keyBitLength: 256));
      final differentV = deriver.deriveKey(
          peerPublicKey: b.publicKey!,
          keyBitLength: 256,
          otherInfo: _buildOtherInfo(
              algorithmId: Uint8List.fromList('kdf-a'.codeUnits),
              partyUInfo: Uint8List.fromList([1]),
              partyVInfo: Uint8List.fromList([9]),
              keyBitLength: 256));

      expect(differentAlg, isNot(key1));
      expect(differentU, isNot(key1));
      expect(differentV, isNot(key1));
    });

    test('derived key length equals requested bit length', () {
      final a = KeyPair.generateEc(curves.p521);
      final b = KeyPair.generateEc(curves.p521);
      final deriver =
          a.createKeyDeriver(algorithms.derivation.concatKdf.sha512);

      final key =
          deriver.deriveKey(peerPublicKey: b.publicKey!, keyBitLength: 384);
      expect(key.length, 48);
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
