// Ed25519 sign and verify (raw message bytes).
//
// Run from repo root: dart run example/ed25519_signing_example.dart
import 'package:crypto_keys/crypto_keys.dart';
import 'dart:convert';

void main() {
  final pair = Ed25519KeyPair.generate();
  final msg = utf8.encode('hello');
  final sig = pair.privateKey.createSigner(SigningAlgorithm.ed25519).sign(msg);
  final ok = pair.publicKey.createVerifier(SigningAlgorithm.ed25519).verify(
        msg,
        sig,
      );
  print(ok); // true
}
