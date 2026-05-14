import 'dart:typed_data';

import 'package:crypto_keys/crypto_keys.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed25519_impl;

class EddsaSigner extends Signer<EdwardsPrivateKey> {
  EddsaSigner(EddsaSigningAlgorithm super.algorithm, super.key);

  @override
  Signature sign(List<int> data) {
    final message = data is Uint8List ? data : Uint8List.fromList(data);
    final priv = ed25519_impl.newKeyFromSeed(keyMaterial.seed);
    final sig = ed25519_impl.sign(priv, message);
    return Signature(sig);
  }
}

class EddsaVerifier extends Verifier<EdwardsPublicKey> {
  EddsaVerifier(EddsaSigningAlgorithm super.algorithm, super.key);

  @override
  bool verify(List<int> data, Signature signature) {
    data = data is Uint8List ? data : Uint8List.fromList(data);
    final pk = ed25519_impl.PublicKey(keyMaterial.publicKeyBytes.toList());
    return ed25519_impl.verify(pk, data, signature.data);
  }
}
