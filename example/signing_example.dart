// HMAC-SHA256 sign and verify with a symmetric key (catalog-backed algorithm).
//
// Run from repo root: dart run example/signing_example.dart
import 'package:crypto_keys/catalog.dart';
import 'package:crypto_keys/crypto_keys.dart';
import 'dart:convert';

void main() {
  final keyPair = SymmetricKeyPair.generate(256);
  final plaintext = utf8.encode("It's me, really me");

  final signature = keyPair.privateKey
      .createSigner(algorithms.signing.hmac.sha256)
      .sign(plaintext);

  final ok = keyPair.publicKey
      .createVerifier(algorithms.signing.hmac.sha256)
      .verify(plaintext, signature);

  print(ok ? 'Verification succeeded' : 'Verification failed');
}
