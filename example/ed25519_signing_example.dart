// Ed25519 sign and verify (raw message bytes).
//
// Run from repo root: dart run example/ed25519_signing_example.dart
import 'package:crypto_keys/crypto_keys.dart';
import 'dart:convert';

void main() {
  final pair = EdwardsKeyPair.generate(.ed25519);
  final msg = utf8.encode('hello');
  final sig = pair.privateKey.createSigner(.eddsa()).sign(msg);
  final ok = pair.publicKey.createVerifier(.eddsa()).verify(msg, sig);
  print(ok); // true
}
