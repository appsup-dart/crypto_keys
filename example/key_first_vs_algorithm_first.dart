// Compare key-first vs algorithm-first signing (equivalent results).
//
// Run from repo root: dart run example/key_first_vs_algorithm_first.dart
import 'package:crypto_keys/catalog.dart';
import 'package:crypto_keys/crypto_keys.dart';
import 'dart:convert';

void main() {
  final kp = SymmetricKeyPair.generate(256);
  final bytes = utf8.encode('authenticated message');

  final keyFirstSig =
      kp.privateKey.createSigner(algorithms.signing.hmac.sha256).sign(bytes);

  final algoFirstSig =
      algorithms.signing.hmac.sha256.sign(kp.privateKey, bytes);

  assert(algoFirstSig == keyFirstSig);
  assert(
    kp.publicKey.createVerifier(algorithms.signing.hmac.sha256).verify(
          bytes,
          keyFirstSig,
        ),
  );
  print('key-first and algorithm-first signatures match');
}
