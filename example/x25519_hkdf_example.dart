// X25519 shared secret then HKDF-SHA256 to a 256-bit application key (both sides).
//
// Run from repo root: dart run example/x25519_hkdf_example.dart
import 'package:crypto_keys/crypto_keys.dart';
import 'dart:convert';
import 'dart:typed_data';

void main() {
  final alice = X25519KeyPair.generate();
  final bob = X25519KeyPair.generate();

  final aliceSecret = alice.privateKey.deriveSharedSecret(
    .x25519(peerPublicKey: bob.publicKey),
  );
  final bobSecret = bob.privateKey.deriveSharedSecret(
    .x25519(peerPublicKey: alice.publicKey),
  );

  final info = utf8.encode('app-context');
  Uint8List derive256(SecretBytes secret) => secret.deriveBits(
        .hkdf(
          hash: .sha256,
          salt: utf8.encode(''),
          keyBitLength: 256,
          info: info,
        ),
      );

  final aliceKey = derive256(aliceSecret);
  final bobKey = derive256(bobSecret);

  print(aliceKey.length == 32 && _bytesEq(aliceKey, bobKey)); // true
}

bool _bytesEq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
