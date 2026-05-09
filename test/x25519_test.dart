import 'dart:typed_data';

import 'package:crypto_keys/catalog.dart';
import 'package:crypto_keys/crypto_keys.dart';
import 'package:test/test.dart';

Uint8List _hex(String s) {
  final h = s.replaceAll(RegExp(r'\s'), '');
  return Uint8List.fromList(
    List.generate(
      h.length ~/ 2,
      (i) => int.parse(h.substring(2 * i, 2 * i + 2), radix: 16),
    ),
  );
}

void main() {
  group('X25519 (RFC 7748 §6.1)', () {
    test('fixed test vector: public keys and shared secret', () {
      final aliceScalar = _hex(
        '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
      );
      final alicePub = _hex(
        '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
      );
      final bobScalar = _hex(
        '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
      );
      final bobPub = _hex(
        'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
      );
      final expectedShared = _hex(
        '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
      );

      final alice = X25519KeyPair.fromPrivateKeyBytes(aliceScalar);
      expect(alice.publicKey.uCoordinate, alicePub);
      final bob = X25519KeyPair.fromPrivateKeyBytes(bobScalar);
      expect(bob.publicKey.uCoordinate, bobPub);
      final kAlice = alice.privateKey.deriveSharedSecret(
        OkpKeyAgreementParams.x25519(peerPublicKey: bob.publicKey),
      );
      final kBob = bob.privateKey.deriveSharedSecret(
        OkpKeyAgreementParams.x25519(peerPublicKey: alice.publicKey),
      );

      expect(kAlice.value, expectedShared);
      expect(kBob.value, expectedShared);

      expect(algorithms.keyAgreement.x25519, KeyAgreementAlgorithm.x25519());
    });

    test('random pair agrees', () {
      final a = X25519KeyPair.generate();
      final b = X25519KeyPair.generate();
      final z1 = a.privateKey.deriveSharedSecret(
        OkpKeyAgreementParams.x25519(peerPublicKey: b.publicKey),
      );
      final z2 = b.privateKey.deriveSharedSecret(
        OkpKeyAgreementParams.x25519(peerPublicKey: a.publicKey),
      );
      expect(z1.value, z2.value);
    });
  });
}
