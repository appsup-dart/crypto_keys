import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed25519_impl;

class Ed25519Signer extends Signer<Ed25519PrivateKey> {
  Ed25519Signer(Ed25519SigningAlgorithm super.algorithm, super.key);

  @override
  Signature sign(List<int> data) {
    final message = data is Uint8List ? data : Uint8List.fromList(data);
    final priv = ed25519_impl.newKeyFromSeed(key.seed);
    final sig = ed25519_impl.sign(priv, message);
    return Signature(sig);
  }
}

class Ed25519Verifier extends Verifier<Ed25519PublicKey> {
  Ed25519Verifier(Ed25519SigningAlgorithm super.algorithm, super.key);

  @override
  bool verify(Uint8List data, Signature signature) {
    final pk = ed25519_impl.PublicKey(key.publicKeyBytes.toList());
    return ed25519_impl.verify(pk, data, signature.data);
  }
}
