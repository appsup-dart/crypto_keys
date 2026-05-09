part of '../crypto_keys.dart';

class _Ed25519Signer extends Signer<Ed25519PrivateKey> {
  _Ed25519Signer(Ed25519SigningAlgorithmIdentifier super.algorithm, super.key)
    : super._();

  @override
  Signature sign(List<int> data) {
    final message = data is Uint8List ? data : Uint8List.fromList(data);
    final priv = ed25519_impl.newKeyFromSeed(key.seed);
    final sig = ed25519_impl.sign(priv, message);
    return Signature(sig);
  }
}

class _Ed25519Verifier extends Verifier<Ed25519PublicKey> {
  _Ed25519Verifier(Ed25519SigningAlgorithmIdentifier super.algorithm, super.key)
    : super._();

  @override
  bool verify(Uint8List data, Signature signature) {
    final pk = ed25519_impl.PublicKey(key.publicKeyBytes.toList());
    return ed25519_impl.verify(pk, data, signature.data);
  }
}
